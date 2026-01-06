// hexabiz-ai-layer.js
import fetch from "node-fetch";
import express from "express";

// ----------------------------
// Configuration
// ----------------------------
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";
const PORT = process.env.PORT || 3000;
const HEALTH_ENDPOINT = "/v1/models";
const RETRIES = 60;
const DELAY_MS = 3000;

// Dynamic OrdeXa-AI runners (comma-separated URLs)
let RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",")
  .map(url => ({ url, busy: false }));

const requestQueue = [];
const MAX_QUEUE_SIZE = parseInt(process.env.MAX_QUEUE_SIZE || "50");

// ----------------------------
// Utility: Sleep
// ----------------------------
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ----------------------------
// Wait for OrdeXa-AI runner readiness
// ----------------------------
async function waitForRunner(runner) {
  console.log(`⏳ Checking if OrdeXa-AI at ${runner.url} has model "${MODEL_NAME}"...`);
  for (let i = 0; i < RETRIES; i++) {
    try {
      const res = await fetch(`${runner.url}${HEALTH_ENDPOINT}`);
      if (!res.ok) throw new Error("OrdeXa-AI endpoint not reachable");
      const result = await res.json();
      if (result.data && result.data.some(m => m.id === MODEL_NAME)) {
        console.log(`✅ OrdeXa-AI at ${runner.url} is ready`);
        return true;
      }
    } catch {
      console.log(`⏳ Retry ${i + 1}/${RETRIES} for ${runner.url}...`);
      await sleep(DELAY_MS);
    }
  }
  console.error(`❌ Model "${MODEL_NAME}" not found on ${runner.url}. Exiting.`);
  process.exit(1);
}

// ----------------------------
// Queue + Runner logic
// ----------------------------
async function processRequest(ollamaRequest, endpointType) {
  const freeRunner = RUNNERS.find(r => !r.busy);
  if (freeRunner) return sendToRunner(freeRunner, ollamaRequest, endpointType);

  if (requestQueue.length >= MAX_QUEUE_SIZE) {
    throw new Error("Server busy. Hexabiz-AI request queue full.");
  }

  return new Promise((resolve, reject) => {
    requestQueue.push({ ollamaRequest, endpointType, resolve, reject });
  });
}

async function sendToRunner(runner, ollamaRequest, endpointType) {
  runner.busy = true;
  const orDexaEndpoint = endpointType === "json" ? "/v1/completion" : "/v1/chat";

  try {
    const response = await fetch(`${runner.url}${orDexaEndpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ollamaRequest),
    });

    if (!response.ok) {
      const text = await response.text();
      console.error(`❌ OrdeXa-AI Error [${runner.url}${orDexaEndpoint}]:`, text);
      throw new Error(`OrdeXa-AI runner returned ${response.status}`);
    }

    const data = await response.json();
    return { source: "OrdeXa-AI", data };
  } catch (err) {
    console.error(`⚠️ Hexabiz-AI runner failed:`, err.message);
    throw err;
  } finally {
    runner.busy = false;
    if (requestQueue.length > 0) {
      const next = requestQueue.shift();
      sendToRunner(next.runner ?? runner, next.ollamaRequest, next.endpointType)
        .then(next.resolve)
        .catch(next.reject);
    }
  }
}

// ----------------------------
// Main server
// ----------------------------
async function startServer() {
  for (const runner of RUNNERS) await waitForRunner(runner);

  const app = express();
  app.use(express.json());

  // ----------------------------
  // Health endpoint
  // ----------------------------
  app.get("/health", async (req, res) => {
    const now = new Date().toISOString();
    try {
      let healthy = false;
      for (const runner of RUNNERS) {
        try {
          const result = await fetch(`${runner.url}${HEALTH_ENDPOINT}`);
          const data = await result.json();
          if (data.data && data.data.some(m => m.id === MODEL_NAME)) {
            healthy = true;
            break;
          }
        } catch {}
      }

      if (healthy) {
        return res.json({
          Status: 200,
          Status_text: "Success",
          model_name: "OrdeXa_AI",
          model_desc: "AI model for order processing",
          Company: "Hexagon Bizolution",
          timestamp: now,
        });
      } else {
        return res.status(503).json({
          Status: 503,
          Status_text: "Service Unavailable",
          model_name: "OrdeXa_AI",
          model_desc: "AI model for order processing",
          Company: "Hexagon Bizolution",
          timestamp: now,
        });
      }
    } catch (err) {
      console.error("[HealthCheck API] Error:", err);
      return res.status(503).json({
        Status: 503,
        Status_text: "Service Unavailable",
        model_name: "OrdeXa_AI",
        model_desc: "AI model for order processing",
        Company: "Hexagon Bizolution",
        timestamp: now,
      });
    }
  });

  // ----------------------------
  // Chat endpoint (default)
  // ----------------------------
  app.post("/ask", async (req, res) => {
    const clientAuth = req.headers.authorization?.split(" ")[1];
    if (!clientAuth || clientAuth !== process.env.OSCILLATION_LAYER_API_KEY) {
      return res.status(401).json({ error: "Unauthorized. Hexabiz-AI blocked this request." });
    }

    const body = req.body;
    if (!body.messages || !body.messages.length) {
      return res.status(400).json({ error: "messages array is required" });
    }

    const ollamaRequest = {
      model: body.model || MODEL_NAME,
      messages: body.messages,
      temperature: body.temperature ?? 0.25,
      json: body.response_format?.type === "json_object" ? true : false,
    };

    try {
      const data = await processRequest(ollamaRequest, "chat");
      res.json(data);
    } catch (err) {
      res.status(503).json({ error: err.message });
    }
  });

  // ----------------------------
  // JSON completion endpoint
  // ----------------------------
  app.post("/ask/json", async (req, res) => {
    const clientAuth = req.headers.authorization?.split(" ")[1];
    if (!clientAuth || clientAuth !== process.env.OSCILLATION_LAYER_API_KEY) {
      return res.status(401).json({ error: "Unauthorized. Hexabiz-AI blocked this request." });
    }

    const body = req.body;
    const prompt = body.prompt ?? body.messages?.[0]?.content;
    if (!prompt) return res.status(400).json({ error: "prompt or messages[0] is required" });

    const ollamaRequest = {
      model: body.model || MODEL_NAME,
      prompt,
      format: "json",
      stream: false,
      temperature: body.temperature ?? 0.25,
    };

    try {
      const data = await processRequest(ollamaRequest, "json");
      res.json(data);
    } catch (err) {
      res.status(503).json({ error: err.message });
    }
  });

  app.listen(PORT, () => console.log(`🌐 Hexabiz-AI server running on port ${PORT}`));
}

// Start the server
startServer();

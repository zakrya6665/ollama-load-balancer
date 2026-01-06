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

// Queue and maximum queue size to avoid overload
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
      const models = result.data;
      if (models.some(m => m.id === MODEL_NAME)) {
        console.log(`✅ OrdeXa-AI at ${runner.url} is ready with model "${MODEL_NAME}"`);
        return true;
      }
    } catch (err) {
      console.log(`⏳ Retry ${i + 1}/${RETRIES} - waiting for OrdeXa-AI at ${runner.url}...`);
      await sleep(DELAY_MS);
    }
  }
  console.error(`❌ Model "${MODEL_NAME}" not found on ${runner.url}. Exiting.`);
  process.exit(1);
}

// ----------------------------
// Queue + Runner logic
// ----------------------------
async function processRequest(ollamaRequest) {
  const freeRunner = RUNNERS.find(r => !r.busy);
  if (freeRunner) {
    return sendToRunner(freeRunner, ollamaRequest);
  } else {
    if (requestQueue.length >= MAX_QUEUE_SIZE) {
      throw new Error("Server busy. Hexabiz-AI request queue full.");
    }
    return new Promise((resolve, reject) => {
      requestQueue.push({ ollamaRequest, resolve, reject });
    });
  }
}

async function sendToRunner(runner, ollamaRequest) {
  runner.busy = true;
  try {
    const response = await fetch(`${runner.url}/v1/completion`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ollamaRequest)
    });
    const data = await response.json();
    return { source: "OrdeXa-AI", data };
  } finally {
    runner.busy = false;
    if (requestQueue.length > 0) {
      const next = requestQueue.shift();
      sendToRunner(runner, next.ollamaRequest)
        .then(next.resolve)
        .catch(next.reject);
    }
  }
}

// ----------------------------
// Main server
// ----------------------------
async function startServer() {
  // Wait for all runners to be ready
  for (const runner of RUNNERS) {
    await waitForRunner(runner);
  }

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
        } catch {
          // ignore runner errors
        }
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
      console.error("[HealthCheck API] Error checking runners:", err);
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
  // Endpoint for app requests
  // ----------------------------
  app.post("/ask", async (req, res) => {
    const clientAuth = req.headers.authorization?.split(" ")[1];
    if (!clientAuth || clientAuth !== process.env.OSCILLATION_LAYER_API_KEY) {
      console.log("⛔ Unauthorized request blocked by Hexabiz-AI");
      return res.status(401).json({ error: "Unauthorized. Hexabiz-AI blocked this request." });
    }

    const body = req.body;
    if ((!body.messages || !body.messages.length) && !body.prompt) {
      return res.status(400).json({ error: "messages array or prompt is required" });
    }

    // ----------------------------
    // Translate request for OrdeXa-AI
    // ----------------------------
    let ollamaRequest;
    if (body.response_format?.type === "json_object") {
      const content = body.prompt ?? body.messages[0].content;
      ollamaRequest = {
        model: body.model || MODEL_NAME,
        prompt: content,
        format: "json",
        stream: false
      };
    } else {
      ollamaRequest = {
        model: body.model || MODEL_NAME,
        messages: body.messages ?? [{ role: "user", content: body.prompt }],
        temperature: body.temperature ?? 0.1,
        max_tokens: body.max_tokens ?? 500,
        private: body.private ?? true,
        response_format: body.response_format ?? { type: "json_object" }
      };
    }

    // ----------------------------
    // Send to runner / queue
    // ----------------------------
    try {
      const data = await processRequest(ollamaRequest);
      res.json(data);
    } catch (err) {
      console.error("⚠️ Hexabiz-AI: request failed:", err.message);
      res.status(503).json({ error: err.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`🌐 Hexabiz-AI server running on port ${PORT}`);
  });
}

// Start Hexabiz-AI
startServer();

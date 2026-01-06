// oscillation-layer.js
import fetch from "node-fetch";
import express from "express";

// ----------------------------
// Configuration
// ----------------------------
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";
const HEALTH_ENDPOINT = "/v1/models";
const PORT = process.env.PORT || 3000;
const RETRIES = 60;       // retries for Ollama readiness
const DELAY_MS = 3000;    // 3 seconds between retries

// Runner URLs (dynamic from env, comma-separated)
let RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",")
  .map(url => ({ url, busy: false }));

const requestQueue = [];

// ----------------------------
// Utility: Sleep
// ----------------------------
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ----------------------------
// Wait for Ollama to be ready and model loaded
// ----------------------------
async function waitForOllama(url) {
  console.log(`⏳ Checking if Ollama at ${url} has model "${MODEL_NAME}"...`);
  for (let i = 0; i < RETRIES; i++) {
    try {
      const res = await fetch(`${url}${HEALTH_ENDPOINT}`);
      if (!res.ok) throw new Error("Ollama endpoint not reachable");
      const result = await res.json();
      const models = result.data;
      if (models.some(m => m.id === MODEL_NAME)) {
        console.log(`✅ Ollama at ${url} is ready with model "${MODEL_NAME}"`);
        return true;
      }
    } catch (err) {
      console.log(`⏳ Retry ${i + 1}/${RETRIES} - waiting for Ollama at ${url}...`);
      await sleep(DELAY_MS);
    }
  }
  console.error(`❌ Model "${MODEL_NAME}" not found on ${url}. Exiting.`);
  process.exit(1);
}

// ----------------------------
// Queue + Runner logic
// ----------------------------
async function processRequest(ollamaRequest) {
  // Find a free runner dynamically
  const freeRunner = RUNNERS.find(r => !r.busy);
  if (freeRunner) {
    return sendToRunner(freeRunner, ollamaRequest);
  } else {
    // All busy → enqueue
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
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${process.env.HEXAGON_AI_API_KEY || ""}`
      },
      body: JSON.stringify(ollamaRequest)
    });
    const data = await response.json();
    return data;
  } finally {
    runner.busy = false;
    // Process queued requests if any
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
    await waitForOllama(runner.url);
  }

  const app = express();
  app.use(express.json());

  // Health endpoint
  app.get("/health", (req, res) => res.send("OK"));

  // Endpoint to interact with Ollama
  app.post("/ask", async (req, res) => {
    const clientAuth = req.headers.authorization?.split(" ")[1];
    if (!clientAuth || clientAuth !== process.env.OSCILLATION_LAYER_API_KEY) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const body = req.body;
    if (!body.messages || !body.messages.length) {
      return res.status(400).json({ error: "messages array is required" });
    }

    // Prepare request for Ollama
    let ollamaRequest;
    if (body.response_format?.type === "json_object") {
      // JSON-format request
      ollamaRequest = {
        model: body.model || MODEL_NAME,
        prompt: body.messages[0].content,
        format: "json",
        stream: false
      };
    } else {
      // Normal request
      ollamaRequest = {
        model: body.model || MODEL_NAME,
        messages: body.messages,
        temperature: body.temperature ?? 0.1,
        max_tokens: body.max_tokens ?? 500,
        private: body.private ?? true,
        response_format: body.response_format ?? { type: "json_object" }
      };
    }

    try {
      const data = await processRequest(ollamaRequest);
      res.json(data);
    } catch (err) {
      console.error("Error sending request to Ollama:", err.message);
      res.status(500).json({ error: err.message });
    }
  });

  app.listen(PORT, () => {
    console.log(`🌐 Oscillation-layer server running on port ${PORT}`);
  });
}

// Start the app
startServer();

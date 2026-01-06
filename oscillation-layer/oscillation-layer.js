// oscillation-layer.js
import fetch from "node-fetch";
import express from "express";

// ----------------------------
// Configuration
// ----------------------------
const OLLAMA_HOST = process.env.OLLAMA_HOST || "http://ollama:11434";
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";
const HEALTH_ENDPOINT = "/v1/models";
const RETRIES = 40;          // Number of attempts
const DELAY_MS = 3000;       // 3s between retries
const PORT = process.env.PORT || 3000;

// ----------------------------
// Utility: Sleep
// ----------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ----------------------------
// Wait for Ollama to be ready and model loaded
// ----------------------------
async function waitForOllama() {
  console.log(`⏳ Waiting for Ollama at ${OLLAMA_HOST} and model ${MODEL_NAME} to load...`);
  for (let i = 0; i < RETRIES; i++) {
    try {
      const res = await fetch(`${OLLAMA_HOST}${HEALTH_ENDPOINT}`);
      if (res.ok) {
        const models = await res.json();
        const modelLoaded = models.some(
          (m) => m.name === MODEL_NAME && m.status === "ready"
        );
        if (modelLoaded) {
          console.log(`✅ Ollama is ready and model ${MODEL_NAME} is loaded!`);
          return true;
        } else {
          console.log(`⏳ Model ${MODEL_NAME} not ready yet (${i + 1}/${RETRIES})`);
        }
      }
    } catch (err) {
      console.log(`⏳ Waiting for Ollama... (${i + 1}/${RETRIES})`);
    }
    await sleep(DELAY_MS);
  }
  console.error(`❌ Ollama or model ${MODEL_NAME} did not become ready in time. Exiting.`);
  process.exit(1);
}

// ----------------------------
// Main server
// ----------------------------
async function startServer() {
  await waitForOllama();

  const app = express();
  app.use(express.json());

  // Health endpoint
  app.get("/health", (req, res) => res.send("OK"));

  // Endpoint to interact with Ollama
  app.post("/ask", async (req, res) => {
    const { prompt } = req.body;
    if (!prompt) return res.status(400).json({ error: "Prompt is required" });

    try {
      const response = await fetch(`${OLLAMA_HOST}/v1/completion`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model: MODEL_NAME, prompt }),
      });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      console.error("Error calling Ollama:", err.message);
      res.status(500).json({ error: err.message });
    }
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`🌐 Oscillation-layer server running on port ${PORT}`);
  });
}

// Start
startServer();

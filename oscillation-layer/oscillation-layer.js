// oscillation-layer.js
import fetch from "node-fetch";
import express from "express";

// ----------------------------
// Configuration
// ----------------------------
const OLLAMA_HOST = process.env.OLLAMA_HOST || "http://ollama:11434";
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";
const HEALTH_ENDPOINT = "/v1/models";
const RETRIES = 60;          // More retries for slow loading
const DELAY_MS = 3000;       // 3 seconds between retries
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
  console.log(`⏳ Checking if Ollama at ${OLLAMA_HOST} has model "${MODEL_NAME}"...`);

  try {
    const res = await fetch(`${OLLAMA_HOST}${HEALTH_ENDPOINT}`);
    if (!res.ok) throw new Error("Ollama endpoint not reachable");

    const result = await res.json();

    // The array is inside result.data
    const models = result.data;

    models.forEach((m) => console.log(`   - ${m.id}`));

    const modelLoaded = models.some((m) => m.id === MODEL_NAME);
    if (modelLoaded) {
      console.log(`✅ Ollama is ready and model "${MODEL_NAME}" exists!`);
      return true;
    } else {
      console.error(`❌ Model "${MODEL_NAME}" not found! Exiting.`);
      process.exit(1);
    }
  } catch (err) {
    console.error("❌ Error reaching Ollama:", err.message);
    process.exit(1);
  }
}



// ----------------------------
// Main server
// ----------------------------
async function startServer() {
  await waitForOllama();

  const app = express();
  app.use(express.json());

  // Health endpoint for Docker healthcheck
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

// Start the app
startServer();

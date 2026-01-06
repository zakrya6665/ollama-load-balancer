// oscillation-layer.js
import fetch from "node-fetch";
import express from "express";

// ----------------------------
// Configuration
// ----------------------------
const OLLAMA_HOST = process.env.OLLAMA_HOST || "http://ollama:11434"; // Docker service name
const HEALTH_ENDPOINT = "/v1/models"; // Ollama health endpoint
const RETRIES = 20; // Number of attempts to check Ollama
const DELAY_MS = 5000; // 3 seconds delay between retries
const PORT = process.env.PORT || 3000;

// ----------------------------
// Utility: Sleep
// ----------------------------
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ----------------------------
// Wait for Ollama to be ready
// ----------------------------
async function waitForOllama() {
  for (let i = 0; i < RETRIES; i++) {
    try {
      const res = await fetch(`${OLLAMA_HOST}${HEALTH_ENDPOINT}`);
      if (res.ok) {
        console.log("✅ Ollama is ready!");
        return true;
      }
    } catch (err) {
      console.log(`Waiting for Ollama... (${i + 1}/${RETRIES})`);
    }
    await sleep(DELAY_MS);
  }
  console.error("❌ Ollama did not become ready in time. Exiting.");
  process.exit(1);
}

// ----------------------------
// Main server
// ----------------------------
async function startServer() {
  // Wait until Ollama is ready
  await waitForOllama();

  const app = express();
  app.use(express.json());

  // Health endpoint for Docker healthcheck
  app.get("/health", (req, res) => res.send("OK"));

  // Example endpoint to interact with Ollama
  app.post("/ask", async (req, res) => {
    const { prompt } = req.body;

    if (!prompt) {
      return res.status(400).json({ error: "Prompt is required" });
    }

    try {
      const response = await fetch(`${OLLAMA_HOST}/v1/completion`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt }),
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
    console.log(`Oscillation-layer server running on port ${PORT}`);
  });
}

// Start the app
startServer();

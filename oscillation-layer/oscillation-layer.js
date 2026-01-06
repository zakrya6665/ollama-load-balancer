import express from "express";
import fetch from "node-fetch";
import PQueue from "p-queue";
import { execSync } from "child_process";

const app = express();
app.use(express.json());

// ======= CONFIG =======
const API_KEY = process.env.OLLAMA_API_KEY || "my-secret-key";

// --- Detect all active Ollama runners dynamically ---
function getActiveRunners() {
  const output = execSync("ps aux | grep '[o]llama runner'").toString();
  const runners = [];

  output.split("\n").forEach(line => {
    if (!line.trim()) return;
    const match = line.match(/--port (\d+)/);
    if (match) {
      runners.push({ url: `http://localhost:${match[1]}/v1/completion`, busy: false });
    }
  });

  return runners;
}

// Initial runner list
let RUNNERS = getActiveRunners();
console.log(`Oscillation Layer detected ${RUNNERS.length} runner(s)`);

// Queue to limit concurrency across runners
const queue = new PQueue({ concurrency: RUNNERS.length });

// ======= API Endpoint =======
app.post("/api/ollama", async (req, res) => {
  const authHeader = req.headers["authorization"];
  if (!authHeader || authHeader !== `Bearer ${API_KEY}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  queue.add(async () => {
    const runner = RUNNERS.find(r => !r.busy);
    if (!runner) {
      return res.status(503).json({ error: "All runners busy, try again" });
    }

    runner.busy = true;
    try {
      const response = await fetch(runner.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req.body),
      });
      const data = await response.json();
      res.json(data);
    } catch (err) {
      res.status(500).json({ error: "Runner request failed", details: err.message });
    } finally {
      runner.busy = false;
    }
  });
});

// ======= Start Server =======
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Oscillation Layer running on http://localhost:${PORT}`);
});

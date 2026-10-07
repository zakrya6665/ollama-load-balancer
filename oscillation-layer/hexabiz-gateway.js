import express from "express";
import fetch from "node-fetch";
import crypto from "crypto";

// ----------------------------
// Configuration & Env Variables
// ----------------------------
const PORT = process.env.PORT || 3000;
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";
const HEALTH_ENDPOINT = "/v1/models";
const RETRIES = 60;
const DELAY_MS = 3000;

// --- EVOLUTION API CONFIG ---
const EVOLUTION_SERVER_URL = process.env.EVOLUTION_SERVER_URL || "http://evolution-api:8080";
const EVOLUTION_GLOBAL_KEY = process.env.EVOLUTION_GLOBAL_KEY; // Top-level Master Server Key

// --- FALLBACK / ROUTER CONFIG ---
const AI_PROVIDER = (process.env.AI_PROVIDER || "ollama").lower();  // "ollama" or "pollinations"
const FALLBACK_MODEL = process.env.FALLBACK_MODEL || "llama-3-70b-instruct";
const POLLINATIONS_BASE_URL = process.env.POLLINATIONS_BASE_URL || "https://gen.pollinations.ai";
const FALLBACK_MODEL = process.env.FALLBACK_MODEL || "openai/gpt-5.4-nano";
const POLLINATIONS_API_KEY = process.env.POLLINATIONS_API_KEY || "YOUR_API_KEY"; 


// --- OLLAMA RUNNERS LAYER ---
let RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",")
  .map(url => ({ url, busy: false }));

const requestQueue = [];
const MAX_QUEUE_SIZE = parseInt(process.env.MAX_QUEUE_SIZE || "50");

// --- RATE LIMITING ---
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || "60000"); // 1 minute
const MAX_REQUESTS_PER_WINDOW = parseInt(process.env.MAX_REQUESTS_PER_WINDOW || "5");
const rateLimits = {}; // Memory store: { deviceId: { count, windowStart } }

// ----------------------------
// Helper Utilities
// ----------------------------
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function checkRateLimit(deviceId) {
  const now = Date.now();
  const key = deviceId || "anonymous";
  
  if (!rateLimits[key]) {
    rateLimits[key] = { count: 1, windowStart: now };
    return true;
  }

  const rl = rateLimits[key];
  if (now - rl.windowStart > RATE_LIMIT_WINDOW_MS) {
    rl.count = 1;
    rl.windowStart = now;
    return true;
  }

  if (rl.count >= MAX_REQUESTS_PER_WINDOW) return false;
  rl.count++;
  return true;
}

/**
 * Derives a secure, static, reproducible unique token for an individual device.
 * Ensures the Android client cannot guess it without its physical deviceId.
 */
function deriveDeviceSecret(deviceId) {
  return crypto
    .createHmac("sha256", EVOLUTION_GLOBAL_KEY)
    .update(deviceId)
    .digest("hex");
}

// ----------------------------
// Security Middleware (HMAC)
// ----------------------------
/**
 * Dynamic HMAC validation to authorize AI and generic operations.
 * Prevents tampering, structural reverse-engineering, and replay attacks.
 */
function verifyDynamicHmac(req, res, next) {
  const deviceId = req.headers["x-device-id"];
  const sentSignature = req.headers["x-signature"];
  const timestamp = req.headers["x-timestamp"];

  if (!deviceId || !sentSignature || !timestamp) {
    return res.status(401).json({ error: "Unauthorized: Missing core validation headers" });
  }

  // 1. Prevent Replay Attacks: Restrict execution windows to 60 seconds
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - parseInt(timestamp)) > 60) {
    return res.status(401).json({ error: "Unauthorized: Signature window expired" });
  }

  // 2. Fetch the target validation secret key for this specific device
  const deviceSpecificSecret = deriveDeviceSecret(deviceId);

  // 3. Reconstruct payload structure to sign
  const stringifiedBody = JSON.stringify(req.body);
  const dataToSign = `${timestamp}.${stringifiedBody}`;

  const expectedSignature = crypto
    .createHmac("sha256", deviceSpecificSecret)
    .update(dataToSign)
    .digest("hex");

  // 4. Constant-time comparison checking to eliminate execution timing side-channels
  const isSignatureValid = crypto.timingSafeEqual(
    Buffer.from(sentSignature, "utf-8"),
    Buffer.from(expectedSignature, "utf-8")
  );

  if (!isSignatureValid) {
    return res.status(401).json({ error: "Unauthorized: Invalid application signature" });
  }

  // Assign details onto request context for subsequent processing access
  req.deviceId = deviceId;
  req.deviceToken = deviceSpecificSecret;
  next();
}

// ----------------------------
// Fallback Pool (Pollinations)
// ----------------------------
// ----------------------------
// Fallback Provider Logic (Decoupled Path Structure)
// ----------------------------
async function callPollinationsFallback(prompt) {
  console.log(`⚠️ Routing payload to Pollinations Fallback Node using model: "${FALLBACK_MODEL}"`);
  try {
    const encodedPrompt = encodeURIComponent(prompt);
    
    // Dynamically append the specific text processing path (/text) to the base domain
    const url = `${POLLINATIONS_BASE_URL}/text/${encodedPrompt}?model=${encodeURIComponent(FALLBACK_MODEL)}&key=${POLLINATIONS_API_KEY}`;
    
    const response = await fetch(url, { method: "GET" });
    if (!response.ok) {
      throw new Error(`Pollinations API gateway returned network status: ${response.status}`);
    }
    
    const text = await response.text();
    
    return {
      source: "Pollinations-Fallback",
      data: { 
        message: { 
          role: "assistant", 
          content: text.trim() 
        } 
      }
    };
  } catch (err) {
    console.error("❌ Fallback Router Critical Exception:", err.message);
    throw new Error(`Execution path error across both processing nodes: ${err.message}`);
  }
}


// ----------------------------
// Runner Engine Infrastructure
// ----------------------------
async function waitForRunner(runner) {
  console.log(`⏳ Monitoring execution path ${runner.url} for target model "${MODEL_NAME}"...`);
  for (let i = 0; i < RETRIES; i++) {
    try {
      const res = await fetch(`${runner.url}${HEALTH_ENDPOINT}`);
      if (!res.ok) throw new Error("Unreachable endpoint context");
      const result = await res.json();
      if (result.data?.some(m => m.id === MODEL_NAME)) {
        console.log(`✅ Runner platform verified: ${runner.url}`);
        return true;
      }
    } catch {
      console.log(`⏳ Retrying verification loop ${i + 1}/${RETRIES}...`);
      await sleep(DELAY_MS);
    }
  }
  console.error(`❌ Dependency failure: "${MODEL_NAME}" was not localized on ${runner.url}.`);
  process.exit(1);
}

async function processRequest(ollamaRequest, endpointType, promptForFallback) {
  if (AI_PROVIDER === "pollinations") {
    return await callPollinationsFallback(promptForFallback);
  }

  const freeRunner = RUNNERS.find(r => !r.busy);
  if (freeRunner) return sendToRunner(freeRunner, ollamaRequest, endpointType);

  if (requestQueue.length >= MAX_QUEUE_SIZE) {
    console.log("⚠️ Queue boundary breached. Routing current traffic to fallback node.");
    return await callPollinationsFallback(promptForFallback);
  }

  return new Promise((resolve, reject) => {
    requestQueue.push({ ollamaRequest, endpointType, resolve, reject });
  });
}

async function sendToRunner(runner, ollamaRequest, endpointType) {
  runner.busy = true;
  const targetEndpoint = endpointType === "json" ? "/api/generate" : "/api/chat";

  try {
    const response = await fetch(`${runner.url}${targetEndpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(ollamaRequest),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Runner connection error context: ${response.status} - ${text}`);
    }

    const data = await response.json();
    return { source: "OrdeXa-AI", data };
  } catch (err) {
    console.error(`⚠️ Runner path exception encountered:`, err.message);
    throw err;
  } finally {
    runner.busy = false;
    if (requestQueue.length > 0) {
      const next = requestQueue.shift();
      sendToRunner(next.runner || runner, next.ollamaRequest, next.endpointType)
        .then(next.resolve)
        .catch(next.reject);
    }
  }
}

// ----------------------------
// Core Express Server Initialization
// ----------------------------
async function startServer() {
  if (!EVOLUTION_GLOBAL_KEY) {
    console.error("❌ Critical Failure: EVOLUTION_GLOBAL_KEY environmental variable missing.");
    process.exit(1);
  }

  if (AI_PROVIDER !== "pollinations") {
    for (const runner of RUNNERS) await waitForRunner(runner);
  }

  const app = express();
  app.use(express.json());

  // System Diagnostics Route
  app.get("/health", (req, res) => {
    res.json({ status: 200, system: "Hexabiz-Orchestration-Service", live: true });
  });

  // -------------------------------------------------------------
  // SECURE EVOLUTION API INSTANCE ROUTE (Zero-Login Architecture)
  // -------------------------------------------------------------
  app.post("/instance/auto-connect", async (req, res) => {
    const { deviceId } = req.body;
    if (!deviceId) return res.status(400).json({ error: "Device hardware signature required" });

    // Derive a unique token dedicated specifically to this device
    const specificDeviceToken = deriveDeviceSecret(deviceId);
    const instanceName = `device_${deviceId}`;

    try {
      const response = await fetch(`${EVOLUTION_SERVER_URL}/instance/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": EVOLUTION_GLOBAL_KEY // Isolated safely on server side
        },
        body: JSON.stringify({
          instanceName: instanceName,
          token: specificDeviceToken,
          qrcode: true
        })
      });

      const data = await response.json();

      if (!response.ok) {
        return res.status(response.status).json({ error: "Evolution platform registration error", details: data });
      }

      // Return configuration metadata straight back to the client device
      return res.json({
        success: true,
        instanceName: instanceName,
        instanceToken: specificDeviceToken, // Client securely writes this locally for messaging
        qrcode: data.qrcode?.code || null,
        pairingCode: data.qrcode?.pairingCode || null
      });

    } catch (err) {
      console.error("❌ Instance registration pipeline error:", err.message);
      return res.status(503).json({ error: "Evolution engine access failure" });
    }
  });

  // -------------------------------------------------------------
// AI ROUTING LAYER ENDPOINTS (Protected via Dynamic HMAC)
// -------------------------------------------------------------
app.post("/ask", verifyDynamicHmac, async (req, res) => {
const body = req.body;
const fallbackPrompt = body.messages?.[body.messages.length - 1]?.content || "Hello";
if (!checkRateLimit(req.deviceId)) {
console.log(⚠️ Rate monitoring threshold breached for ${req.deviceId}. Forcing offload channel.);
try {
const fallbackData = await callPollinationsFallback(fallbackPrompt);
return res.json(fallbackData);
} catch (err) {
return res.status(429).json({ error: "Rate thresholds surpassed, backup pipeline failed." });
}
}
if (!body.messages || !body.messages.length) {
return res.status(400).json({ error: "Structured message configuration array is required" });
}
const ollamaRequest = {
model: body.model || MODEL_NAME,
messages: body.messages,
temperature: body.temperature ?? 0.25,
...(body.response_format?.type === "json_object" ? { format: "json" } : {}),
};
try {
const data = await processRequest(ollamaRequest, "chat", fallbackPrompt);
res.json(data);
} catch (err) {
try {
const fallbackData = await callPollinationsFallback(fallbackPrompt);
res.json(fallbackData);
} catch (fallbackErr) {
res.status(503).json({ error: err.message });
}
}
});
app.post("/ask/json", verifyDynamicHmac, async (req, res) => {
const body = req.body;
const fallbackPrompt = body.prompt || body.messages?.[0]?.content;
if (!checkRateLimit(req.deviceId)) {
console.log(⚠️ Rate monitoring threshold breached for ${req.deviceId}. Forcing offload channel.);
try {
const fallbackData = await callPollinationsFallback(fallbackPrompt);
return res.json(fallbackData);
} catch (err) {
return res.status(429).json({ error: "Rate thresholds surpassed, backup pipeline failed." });
}
}
if (!fallbackPrompt) return res.status(400).json({ error: "Explicit prompt text or array required" });
const ollamaRequest = {
model: body.model || MODEL_NAME,
prompt: fallbackPrompt,
format: "json",
stream: false,
temperature: body.temperature ?? 0.25,
...(body.response_format ? { response_format: body.response_format } : {}),
};
try {
const data = await processRequest(ollamaRequest, "json", fallbackPrompt);
res.json(data);
} catch (err) {
try {
const fallbackData = await callPollinationsFallback(fallbackPrompt);
res.json(fallbackData);
} catch (fallbackErr) {
res.status(503).json({ error: err.message });
}
}
});
app.listen(PORT, () => console.log(🌐 Secure Hexabiz-AI Service running on port ${PORT}));
}
startServer();

import express from "express";
import helmet from "helmet";
import fetch from "node-fetch";
import crypto from "crypto";

// ============================================================
// Configuration
// ============================================================

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";

const EVOLUTION_SERVER_URL = process.env.EVOLUTION_SERVER_URL || "http://evolution-api:8080";
const EVOLUTION_GLOBAL_KEY = process.env.EVOLUTION_GLOBAL_KEY;
const APP_ENROLLMENT_KEY = process.env.APP_ENROLLMENT_KEY;

const AI_PROVIDER = (process.env.AI_PROVIDER || "ollama").toLowerCase();
const FALLBACK_MODEL = process.env.FALLBACK_MODEL || "openai/gpt-5.4-nano";
const POLLINATIONS_BASE_URL = process.env.POLLINATIONS_BASE_URL || "https://text.pollinations.ai"; // Fixed URL
const POLLINATIONS_API_KEY = process.env.POLLINATIONS_API_KEY;

const MAX_QUEUE_SIZE = positiveInt(process.env.MAX_QUEUE_SIZE, 50);
const RATE_LIMIT_WINDOW_MS = positiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60_000);
const MAX_REQUESTS_PER_WINDOW = positiveInt(process.env.MAX_REQUESTS_PER_WINDOW, 20);
const HMAC_MAX_SKEW_SECONDS = positiveInt(process.env.HMAC_MAX_SKEW_SECONDS, 60);
const OUTBOUND_TIMEOUT_MS = positiveInt(process.env.OUTBOUND_TIMEOUT_MS, 120_000);
const MAX_PROMPT_LENGTH = positiveInt(process.env.MAX_PROMPT_LENGTH, 12_000);

const RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",")
  .map((value) => value.trim().replace(/\/+$/, ""))
  .filter(Boolean)
  .map((url) => ({ url, busy: false }));

const rateLimits = new Map();
const usedNonces = new Map();
const instanceCreationLimits = new Map(); // STRICT IP LIMITER

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a), "utf8");
  const right = Buffer.from(String(b), "utf8");
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function isValidDeviceId(deviceId) {
  return typeof deviceId === "string" && /^[A-Za-z0-9._:-]{8,128}$/.test(deviceId);
}

function isValidIP(ip) {
  const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6 = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
  return ipv4.test(ip) || ipv6.test(ip);
}

function deriveDeviceSecret(deviceId) {
  return crypto.createHmac("sha256", EVOLUTION_GLOBAL_KEY).update(`device:${deviceId}`, "utf8").digest("hex");
}

function deriveInstanceName(deviceId) {
  const digest = crypto.createHash("sha256").update(deviceId, "utf8").digest("hex").slice(0, 32);
  return `device_${digest}`;
}

function checkRateLimit(deviceId) {
  const now = Date.now();
  const existing = rateLimits.get(deviceId);

  if (!existing || now - existing.windowStart >= RATE_LIMIT_WINDOW_MS) {
    rateLimits.set(deviceId, { count: 1, windowStart: now });
    return true;
  }

  if (existing.count >= MAX_REQUESTS_PER_WINDOW) return false;
  existing.count += 1;
  return true;
}

function cleanupNonces(now) {
  for (const [nonce, expiresAt] of usedNonces) {
    if (expiresAt <= now) usedNonces.delete(nonce);
  }
}

function consumeNonce(nonce, now) {
  cleanupNonces(now);
  if (usedNonces.has(nonce)) return false;
  if (usedNonces.size > 10000) usedNonces.clear(); // Prevent memory leak
  usedNonces.set(nonce, now + HMAC_MAX_SKEW_SECONDS * 1000);
  return true;
}

function extractPrompt(value) {
  if (typeof value === "string") return value.slice(0, MAX_PROMPT_LENGTH);
  if (Array.isArray(value)) {
    const last = value[value.length - 1];
    if (last && typeof last.content === "string") return last.content.slice(0, MAX_PROMPT_LENGTH);
  }
  return "";
}

async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), OUTBOUND_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

// ============================================================
// Security Middleware
// ============================================================

function verifyEnrollmentKey(req, res, next) {
  const supplied = req.get("x-enrollment-key");
  if (!supplied || !safeEqualText(supplied, APP_ENROLLMENT_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// STRICT IP RATE LIMITER FOR INSTANCE CREATION
function strictIpRateLimit(req, res, next) {
  // Extract real IP, accounting for Coolify/Nginx reverse proxy
  const ip = req.headers['x-forwarded-for'] 
    ? req.headers['x-forwarded-for'].split(',')[0].trim() 
    : (req.ip || req.connection.remoteAddress);

  if (!isValidIP(ip)) {
    console.warn(`[SECURITY] Invalid IP format attempted instance creation: ${ip}`);
    return res.status(400).json({ error: "Invalid network request." });
  }

  const now = Date.now();
  const existing = instanceCreationLimits.get(ip);
  const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

  if (!existing || (now - existing.windowStart) > TWENTY_FOUR_HOURS_MS) {
    instanceCreationLimits.set(ip, { count: 1, windowStart: now });
    return next();
  }

  if (existing.count >= 3) {
    console.warn(`[SECURITY] IP ${ip} exceeded strict instance creation limit (3/24h).`);
    return res.status(429).json({ 
      error: "Strict limit reached: Maximum 3 device linkings allowed per 24 hours from this network." 
    });
  }

  existing.count += 1;
  next();
}

function verifyDynamicHmac(req, res, next) {
  const deviceId = req.get("x-device-id");
  const signature = req.get("x-signature");
  const timestampHeader = req.get("x-timestamp");
  const nonce = req.get("x-nonce");

  if (!isValidDeviceId(deviceId) || !signature || !timestampHeader || !nonce || !/^[A-Za-z0-9._~-]{16,128}$/.test(nonce)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const timestamp = Number.parseInt(timestampHeader, 10);
  if (!Number.isSafeInteger(timestamp)) return res.status(401).json({ error: "Unauthorized" });

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > HMAC_MAX_SKEW_SECONDS) {
    return res.status(401).json({ error: "Signature expired" });
  }

  const deviceSecret = deriveDeviceSecret(deviceId);
  const bodyText = JSON.stringify(req.body ?? {});
  const dataToSign = `${timestamp}.${nonce}.${bodyText}`;

  const expectedSignature = crypto.createHmac("sha256", deviceSecret).update(dataToSign, "utf8").digest("hex");

  if (!safeEqualText(signature, expectedSignature)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (!consumeNonce(`${deviceId}:${nonce}`, Date.now())) {
    return res.status(401).json({ error: "Replay detected" });
  }

  if (!checkRateLimit(deviceId)) {
    return res.status(429).json({ error: "Too many requests. Calm down." });
  }

  req.deviceId = deviceId;
  req.deviceToken = deviceSecret;
  next();
}

function verifyPlayIntegrityToken(req, res, next) {
  const integrityToken = req.get("x-play-integrity-token");
  if (!integrityToken) return next(); // Allow bypass for local testing
  // TODO: Validate integrityToken via Google Play Developer APIs here for production
  next();
}

// ============================================================
// AI & Fallback Logic
// ============================================================

async function callPollinationsFallback(prompt) {
  if (!POLLINATIONS_API_KEY) throw new Error("Pollinations fallback is not configured");
  const cleanPrompt = extractPrompt(prompt);
  if (!cleanPrompt) throw new Error("Fallback prompt is empty");

  // Fixed URL construction to prevent double "/text/"
  const url = new URL(encodeURIComponent(cleanPrompt), POLLINATIONS_BASE_URL);
  url.searchParams.set("model", FALLBACK_MODEL);
  url.searchParams.set("key", POLLINATIONS_API_KEY);

  const response = await fetchWithTimeout(url.toString(), { method: "GET", headers: { Accept: "text/plain" } });
  if (!response.ok) throw new Error(`Fallback provider returned HTTP ${response.status}`);

  const text = (await response.text()).trim();
  return { source: "Pollinations-Fallback", data: { message: { role: "assistant", content: text } } };
}

async function waitForRunner(runner) {
  const deadline = Date.now() + 180_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetchWithTimeout(`${runner.url}/api/tags`, { method: "GET", headers: { Accept: "application/json" } });
      if (response.ok) {
        const result = await response.json();
        const models = Array.isArray(result.models) ? result.models : [];
        if (models.some((model) => model.name === MODEL_NAME || model.model === MODEL_NAME)) return;
      }
    } catch { /* Retry */ }
    await sleep(3000);
  }
  throw new Error(`Ollama runner ${runner.url} did not expose model ${MODEL_NAME}`);
}

async function sendToRunner(runner, ollamaRequest, endpointType) {
  runner.busy = true;
  const targetEndpoint = endpointType === "chat" ? "/api/chat" : "/api/generate";

  try {
    const response = await fetchWithTimeout(`${runner.url}${targetEndpoint}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...ollamaRequest, model: MODEL_NAME, stream: false }),
    });

    if (!response.ok) throw new Error(`Ollama runner returned HTTP ${response.status}`);
    const data = await response.json();
    return { source: "Ollama", data };
  } finally {
    runner.busy = false;
  }
}

async function getAvailableRunner() {
  return RUNNERS.find((r) => !r.busy);
}

// ============================================================
// Express App Initialization & Routes
// ============================================================

const app = express();
app.use(helmet());
app.use(express.json({ limit: "2mb" }));

// --- TIER 1: HIGH VALUE ADMIN OPERATIONS ---
// --- TIER 1: HIGH VALUE ADMIN OPERATIONS ---
app.post(
  "/api/instance/create",
  strictIpRateLimit,          // 1. Strict IP check (Max 3 per 24h)
  verifyEnrollmentKey,        // 2. App enrollment key check
  verifyPlayIntegrityToken,   // 3. Optional Google Play Integrity check
  async (req, res) => {
    const { deviceId } = req.body;

    if (!isValidDeviceId(deviceId)) {
      return res.status(400).json({ error: "Invalid device ID assignment" });
    }

    const instanceName = deriveInstanceName(deviceId);
    
    // ⚠️ CRITICAL: Derive the secret on the server using the hidden GLOBAL_KEY
    const deviceSecret = deriveDeviceSecret(deviceId);

    try {
      const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": EVOLUTION_GLOBAL_KEY, // Safe: Only the server knows this
        },
        body: JSON.stringify({
          instanceName: instanceName,
          token: deviceSecret, // Sent to Evolution API
          qrcode: true,
        }),
      });

      const data = await evoResponse.json();
      
      // ⚠️ CRITICAL FIX: Return the deviceSecret to the Android app 
      // so it can store it and use it to sign future /api/chat requests!
      return res.status(evoResponse.status).json({
        ...data,
        deviceSecret: deviceSecret, 
      });
    } catch (err) {
      return res.status(500).json({ error: "Evolution API context error", details: err.message });
    }
  }
);

// --- TIER 2: ROUTINE OPERATIONS ---
app.post("/api/chat", verifyDynamicHmac, async (req, res) => {
  const { messages, prompt } = req.body;
  const ollamaPayload = messages ? { messages } : { prompt: extractPrompt(prompt) };
  const endpointType = messages ? "chat" : "generate";

  if (AI_PROVIDER === "ollama") {
    const runner = await getAvailableRunner();
    if (runner) {
      try {
        const result = await sendToRunner(runner, ollamaPayload, endpointType);
        return res.json(result);
      } catch (err) {
        console.error("Primary Ollama runner failed, executing fallback...", err.message);
      }
    }
  }

  try {
    const fallbackResult = await callPollinationsFallback(messages || prompt);
    return res.json(fallbackResult);
  } catch (fallbackErr) {
    return res.status(500).json({ error: "All AI layers failed execution", details: fallbackErr.message });
  }
});

app.get("/api/instance/status", verifyDynamicHmac, async (req, res) => {
  const instanceName = deriveInstanceName(req.deviceId);
  try {
    // FIXED: Added backticks for template literal
    const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${instanceName}`, {
      method: "GET",
      headers: { "apikey": req.deviceToken },
    });
    const data = await evoResponse.json();
    return res.status(evoResponse.status).json(data);
  } catch (err) {
    return res.status(500).json({ error: "Failed to pull state connection", details: err.message });
  }
});

// --- INITIALIZATION ---
const server = app.listen(PORT, async () => {
  // FIXED: Added backticks for template literals
  console.log(`Proxy system active and listening on port ${PORT}`);
  
  if (AI_PROVIDER === "ollama") {
    console.log(`Verifying target model allocations: [${MODEL_NAME}] across runners...`);
    for (const runner of RUNNERS) {
      try {
        await waitForRunner(runner);
        console.log(`Runner ready: ${runner.url}`);
      } catch (err) {
        console.error(`Runner diagnostic alert: ${err.message}`);
      }
    }
  }
});

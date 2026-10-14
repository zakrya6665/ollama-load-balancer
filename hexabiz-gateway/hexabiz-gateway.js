import express from "express";
import helmet from "helmet";
import fetch from "node-fetch";
import crypto from "crypto";
import { initializeApp, cert } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";

// ============================================================
// Configuration
// ============================================================

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "gemma:2b";

const EVOLUTION_SERVER_URL = (process.env.EVOLUTION_SERVER_URL || "http://whatsapp_api:8080").replace(/\/+$/, "");
const EVOLUTION_GLOBAL_KEY = process.env.EVOLUTION_GLOBAL_KEY;
const APP_ENROLLMENT_KEY = process.env.APP_ENROLLMENT_KEY;

// Public URL of THIS gateway as Evolution can reach it (used for the per-instance webhook).
const GATEWAY_PUBLIC_URL = (process.env.GATEWAY_PUBLIC_URL || "https://gateway.hexabizsolutions.cloud").replace(/\/+$/, "");

const AI_PROVIDER = (process.env.AI_PROVIDER || "ollama").toLowerCase();
const FALLBACK_MODEL = process.env.FALLBACK_MODEL || "openai/gpt-4o-mini";
const POLLINATIONS_BASE_URL = process.env.POLLINATIONS_BASE_URL || "https://text.pollinations.ai/openai";
const POLLINATIONS_API_KEY = process.env.POLLINATIONS_API_KEY;

const MAX_QUEUE_SIZE = positiveInt(process.env.MAX_QUEUE_SIZE, 50);
const RATE_LIMIT_WINDOW_MS = positiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60_000);
const MAX_REQUESTS_PER_WINDOW = positiveInt(process.env.MAX_REQUESTS_PER_WINDOW, 20);
const HMAC_MAX_SKEW_SECONDS = positiveInt(process.env.HMAC_MAX_SKEW_SECONDS, 60);
const OUTBOUND_TIMEOUT_MS = positiveInt(process.env.OUTBOUND_TIMEOUT_MS, 120_000);
const MAX_PROMPT_LENGTH = positiveInt(process.env.MAX_PROMPT_LENGTH, 12_000);

// Successful instance creations allowed per IP per 24h. Raise it while testing, set back to 3 for release.
const INSTANCE_CREATE_LIMIT = positiveInt(process.env.INSTANCE_CREATE_LIMIT, 3);

const RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",")
  .map((value) => value.trim().replace(/\/+$/, ""))
  .filter(Boolean)
  .map((url) => ({ url, busy: false }));

// Fail fast: these two keys protect everything. Without them the gateway is unsafe.
if (!EVOLUTION_GLOBAL_KEY || !APP_ENROLLMENT_KEY) {
  console.error("[CONFIG] EVOLUTION_GLOBAL_KEY and APP_ENROLLMENT_KEY must both be set. Exiting.");
  process.exit(1);
}

console.log("[CONFIG] Evolution Server URL:", safeUrl(EVOLUTION_SERVER_URL));
console.log("[CONFIG] Gateway Public URL:", GATEWAY_PUBLIC_URL);
console.log("[CONFIG] AI Provider:", AI_PROVIDER);

const rateLimits = new Map();
const usedNonces = new Map();
const instanceCreationLimits = new Map();
const instanceToDeviceMap = new Map(); // instanceName -> deviceId
const deviceToInstanceMap = new Map(); // deviceId -> instanceName
const deviceFcmTokens = new Map();     // deviceId -> FCM token

// Secret Evolution must present when calling /webhook/evolution. Derived, so no new env var is needed.
const WEBHOOK_SECRET = crypto
  .createHmac("sha256", EVOLUTION_GLOBAL_KEY)
  .update("webhook:evolution", "utf8")
  .digest("hex");

const WEBHOOK_EVENTS = [
  "MESSAGES_UPSERT",
  "MESSAGES_UPDATE",
  "MESSAGES_DELETE",
  "PRESENCE_UPDATE",
  "CONNECTION_UPDATE",
];

const MAX_FCM_TEXT = 1500; // FCM data payloads are capped at 4 KB total

// Global state for health checks
let isFirebaseReady = false;

// ============================================================
// Small helpers
// ============================================================

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Strips any user:password from a URL before it is logged. */
function safeUrl(value) {
  try {
    const u = new URL(value);
    u.username = "";
    u.password = "";
    return u.toString().replace(/\/$/, "");
  } catch {
    return "[invalid url]";
  }
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

// ------------------------------------------------------------
// Instance naming: dev_<number>   e.g. dev_923001234567
// ------------------------------------------------------------

/** Digits only, 8 to 15 long (country code + number). Returns null if invalid. */
function normalizePhone(value) {
  const digits = String(value ?? "").replace(/\D/g, "");
  return /^\d{8,15}$/.test(digits) ? digits : null;
}

function deriveInstanceName(phoneDigits) {
  return `dev_${phoneDigits}`;
}

/** Old naming (device_<hash>). Kept only so existing instances can still be unlinked. */
function deriveLegacyInstanceName(deviceId) {
  const digest = crypto.createHash("sha256").update(deviceId, "utf8").digest("hex").slice(0, 32);
  return `device_${digest}`;
}

/** Whitelist check. Also stops path tricks like "../" when the name is placed in a URL. */
function isValidInstanceName(name) {
  return typeof name === "string" && /^(?:dev_\d{8,15}|device_[a-f0-9]{32})$/.test(name);
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
  if (usedNonces.size > 10000) usedNonces.clear();
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

function registerInstance(instanceName, deviceId) {
  instanceToDeviceMap.set(instanceName, deviceId);
  deviceToInstanceMap.set(deviceId, instanceName);
  console.log(`[INSTANCE] Registered mapping: ${instanceName} <-> ${deviceId}`);
}

function unregisterInstance(instanceName, deviceId) {
  instanceToDeviceMap.delete(instanceName);
  deviceToInstanceMap.delete(deviceId);
  deviceFcmTokens.delete(deviceId);
  console.log(`[INSTANCE] Unregistered: ${instanceName}`);
}

// ============================================================
// Evolution helpers
// ============================================================

// NOTE: Updated for Evolution API v2.x schema compatibility
function buildWebhookConfig() {
  return {
    enabled: true,
    url: `${GATEWAY_PUBLIC_URL}/webhook/evolution?s=${WEBHOOK_SECRET}`,
    events: WEBHOOK_EVENTS,
    webhook_by_events: false, // Evolution v2 exact schema
    webhook_base64: false,    // Evolution v2 exact schema
    headers: { "x-webhook-secret": WEBHOOK_SECRET },
  };
}

/** true = exists, false = does not exist, null = could not tell. Uses the global key. */
async function instanceExists(instanceName) {
  try {
    const r = await fetchWithTimeout(
      `${EVOLUTION_SERVER_URL}/instance/fetchInstances?instanceName=${encodeURIComponent(instanceName)}`,
      { method: "GET", headers: { apikey: EVOLUTION_GLOBAL_KEY } }
    );
    if (r.status === 404) return false;
    if (!r.ok) return null;
    const body = await r.json().catch(() => null);
    const list = Array.isArray(body) ? body : body ? [body] : [];
    return list.length > 0;
  } catch (err) {
    console.error(`[EVOLUTION] Error checking instance existence: ${err.message}`);
    return null;
  }
}

/**
 * Proves whether this device owns the instance. The instance token in Evolution was set to the
 * device's secret at creation, so Evolution itself accepts or rejects it. No local state needed.
 * Returns "owned" | "foreign" | "missing" | "error".
 */
async function instanceAccess(instanceName, deviceSecret) {
  try {
    const r = await fetchWithTimeout(
      `${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(instanceName)}`,
      { method: "GET", headers: { apikey: deviceSecret } }
    );
    if (r.ok) return "owned";
    const exists = await instanceExists(instanceName);
    if (exists === false) return "missing";
    if (exists === true) return "foreign";
    return "error";
  } catch (err) {
    console.error(`[EVOLUTION] Error checking instance access: ${err.message}`);
    return "error";
  }
}

/** "open" | "connecting" | "close" | null (unknown). Uses the instance's own key. */
async function getInstanceState(instanceName, deviceSecret) {
  try {
    const r = await fetchWithTimeout(
      `${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(instanceName)}`,
      { method: "GET", headers: { apikey: deviceSecret } }
    );
    if (!r.ok) return null;
    const d = await r.json().catch(() => null);
    return d?.instance?.state ?? d?.state ?? null;
  } catch {
    return null;
  }
}

/**
 * Asks Evolution for a pairing code: GET /instance/connect/{name}?number=...
 */
async function fetchPairingCode(instanceName, deviceSecret, phone) {
  const url = `${EVOLUTION_SERVER_URL}/instance/connect/${encodeURIComponent(instanceName)}?number=${phone}`;
  for (let attempt = 1; attempt <= 3; attempt++) {
    await sleep(attempt === 1 ? 1500 : 3000);
    try {
      const r = await fetchWithTimeout(url, { method: "GET", headers: { apikey: deviceSecret } });
      const d = await r.json().catch(() => ({}));
      const code = d?.pairingCode ?? d?.qrcode?.pairingCode ?? null;
      console.log(`[PAIRING] ${instanceName} attempt ${attempt}: http=${r.status} code=${code ? "present" : "absent"}`);
      if (code) return code;
    } catch (err) {
      console.warn(`[PAIRING] ${instanceName} attempt ${attempt} failed: ${err.message}`);
    }
    if (attempt === 1) {
      try {
        await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/logout/${encodeURIComponent(instanceName)}`, {
          method: "DELETE",
          headers: { apikey: EVOLUTION_GLOBAL_KEY },
        });
      } catch { /* best effort */ }
    }
  }
  return null;
}

/** Best effort: (re)attach the webhook to an existing instance. Needs Evolution v2 /webhook/set. */
async function configureWebhook(instanceName) {
  try {
    // Evolution v2 sometimes needs a brief moment after creation to accept webhook configs
    await sleep(1500); 
    
    const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/webhook/set/${encodeURIComponent(instanceName)}`, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "apikey": EVOLUTION_GLOBAL_KEY 
      },
      body: JSON.stringify({ webhook: buildWebhookConfig() }),
    });
    
    if (!r.ok) {
      const errText = await r.text().catch(() => "Unknown error");
      console.warn(`[WEBHOOK] webhook/set for ${instanceName} returned HTTP ${r.status}: ${errText}`);
    } else {
      console.log(`[WEBHOOK] ✅ Webhook successfully configured for ${instanceName}`);
    }
  } catch (err) {
    console.error(`[WEBHOOK] webhook/set for ${instanceName} failed: ${err.message}`);
  }
}

/** Instance name for a signed request. Header first, then known mapping, then the old hash name. */
function resolveInstanceName(req) {
  const header = req.get("x-instance-name");
  if (header) return isValidInstanceName(header) ? header : null;
  return deviceToInstanceMap.get(req.deviceId) || deriveLegacyInstanceName(req.deviceId);
}

// ============================================================
// Security Middleware
// ============================================================

function verifyEnrollmentKey(req, res, next) {
  const supplied = req.get("x-enrollment-key");
  if (!supplied || !safeEqualText(supplied, APP_ENROLLMENT_KEY)) {
    console.warn(
      `[SECURITY] Enrollment key rejected from ${req.ip} (supplied length=${supplied ? supplied.length : 0}, expected length=${APP_ENROLLMENT_KEY.length})`
    );
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function strictIpRateLimit(req, res, next) {
  const ip = (req.ip || req.socket.remoteAddress || "").replace(/^::ffff:/, "");
  if (!isValidIP(ip)) {
    console.warn(`[SECURITY] Invalid IP format attempted instance creation: ${ip}`);
    return res.status(400).json({ error: "Invalid network request." });
  }
  const now = Date.now();
  const WINDOW_MS = 24 * 60 * 60 * 1000;
  let entry = instanceCreationLimits.get(ip);
  if (!entry || now - entry.windowStart > WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    instanceCreationLimits.set(ip, entry);
  }
  if (entry.count >= INSTANCE_CREATE_LIMIT) {
    console.warn(`[SECURITY] IP ${ip} exceeded instance creation limit (${INSTANCE_CREATE_LIMIT}/24h).`);
    return res.status(429).json({
      error: `Strict limit reached: Maximum ${INSTANCE_CREATE_LIMIT} device linkings allowed per 24 hours.`,
    });
  }
  entry.count += 1;
  res.on("finish", () => {
    if (res.statusCode >= 400 && entry.count > 0) entry.count -= 1;
  });
  next();
}

function verifyDynamicHmac(req, res, next) {
  const deviceId = req.get("x-device-id");
  const signature = req.get("x-signature");
  const timestampHeader = req.get("x-timestamp");
  const nonce = req.get("x-nonce");

  if (!isValidDeviceId(deviceId) || !signature || !timestampHeader || !nonce || !/^[A-Za-z0-9._~-]{16,128}$/.test(nonce)) {
    console.warn(`[SECURITY] Invalid HMAC parameters from IP: ${req.ip}`);
    return res.status(401).json({ error: "Unauthorized" });
  }

  const timestamp = Number.parseInt(timestampHeader, 10);
  if (!Number.isSafeInteger(timestamp)) return res.status(401).json({ error: "Unauthorized" });

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > HMAC_MAX_SKEW_SECONDS) {
    console.warn(`[SECURITY] Signature expired: timestamp=${timestamp}, now=${now}`);
    return res.status(401).json({ error: "Signature expired" });
  }

  const deviceSecret = deriveDeviceSecret(deviceId);
  const bodyText = req.rawBody ? req.rawBody.toString("utf8") : ""; // Exact raw bytes
  const dataToSign = `${timestamp}.${nonce}.${bodyText}`;

  const expectedSignature = crypto.createHmac("sha256", deviceSecret).update(dataToSign, "utf8").digest("hex");

  if (!safeEqualText(signature, expectedSignature)) {
    console.warn(`[SECURITY] Invalid signature for device: ${deviceId}`);
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (!consumeNonce(`${deviceId}:${nonce}`, Date.now())) {
    console.warn(`[SECURITY] Replay detected for device: ${deviceId}`);
    return res.status(401).json({ error: "Replay detected" });
  }

  if (!checkRateLimit(deviceId)) {
    console.warn(`[SECURITY] Rate limit exceeded for device: ${deviceId}`);
    return res.status(429).json({ error: "Too many requests. Calm down." });
  }

  req.deviceId = deviceId;
  req.deviceToken = deviceSecret;
  next();
}

function verifyPlayIntegrityToken(req, res, next) {
  const integrityToken = req.get("x-play-integrity-token");
  if (!integrityToken) return next();
  next();
}

/** Only Evolution (which knows the secret) may post to /webhook/evolution. */
function verifyWebhookSecret(req, res, next) {
  const supplied = req.get("x-webhook-secret") || req.query?.s;
  if (!supplied || !safeEqualText(supplied, WEBHOOK_SECRET)) {
    console.warn(`[WEBHOOK] Invalid webhook secret from IP: ${req.ip}`);
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ============================================================
// AI & Fallback Logic
// ============================================================

async function callPollinationsFallback(prompt) {
  if (!POLLINATIONS_API_KEY) throw new Error("Pollinations fallback is not configured");
  const cleanPrompt = extractPrompt(prompt);
  if (!cleanPrompt) throw new Error("Fallback prompt is empty");

  const response = await fetchWithTimeout(POLLINATIONS_BASE_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${POLLINATIONS_API_KEY}`
    },
    body: JSON.stringify({
      model: FALLBACK_MODEL,
      messages: [{ role: "user", content: cleanPrompt }]
    })
  });

  if (!response.ok) throw new Error(`Fallback provider returned HTTP ${response.status}`);
  const data = await response.json();
  const text = data.choices?.[0]?.message?.content?.trim() || "";
  if (!text) throw new Error("Fallback provider returned empty response");

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
  throw new Error(`Ollama runner ${safeUrl(runner.url)} did not expose model ${MODEL_NAME}`);
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
// FCM Helper
// ============================================================
async function sendFcmData(instanceName, dataPayload) {
  const deviceId = instanceToDeviceMap.get(instanceName);
  const fcmToken = deviceId ? deviceFcmTokens.get(deviceId) : null;

  if (!fcmToken) {
    console.log(`[FCM] No FCM token found for instance ${instanceName} (deviceId: ${deviceId}).`);
    return;
  }

  // FCM "data" values MUST be strings. A boolean here makes send() throw.
  const data = Object.fromEntries(Object.entries(dataPayload).map(([k, v]) => [k, String(v ?? "")]));

  try {
    await getMessaging().send({
      token: fcmToken,
      data,
      android: { priority: "high" },
    });
    console.log(`[FCM] ✅ Pushed ${data.type || "data"} to device ${deviceId}`);
  } catch (fcmError) {
    console.error(`[FCM] ❌ Failed to send to ${deviceId}:`, fcmError.message);
    if (fcmError.code === "messaging/invalid-registration-token" || fcmError.code === "messaging/registration-token-not-registered") {
      console.log(`[FCM] Removing invalid token for device ${deviceId}`);
      deviceFcmTokens.delete(deviceId); // Clean up invalid token
    }
  }
}

// ============================================================
// Express App Initialization & Routes
// ============================================================

const app = express();
app.set("trust proxy", 1);
app.use(helmet());

// Capture raw body for HMAC verification BEFORE parsing JSON
app.use(express.json({
  limit: "2mb",
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// ============================================================
// PUBLIC FACING: Health Check & API Introduction
// ============================================================

// 1. Luxurious Root Introduction (GET /)
app.get("/", (req, res) => {
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>HexaSynq Gateway | HexaBiz Solutions</title>
      <style>
        :root { --bg: #0a0a0f; --card: #13131f; --accent: #00f0ff; --text: #e0e0e0; --muted: #888899; }
        body { margin: 0; font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); display: flex; flex-direction: column; align-items: center; justify-content: center; min-height: 100vh; }
        .container { text-align: center; max-width: 600px; padding: 2rem; background: var(--card); border: 1px solid rgba(0, 240, 255, 0.1); border-radius: 16px; box-shadow: 0 0 40px rgba(0, 240, 255, 0.05); }
        .logo { font-size: 2.5rem; font-weight: 800; letter-spacing: -1px; margin-bottom: 0.5rem; background: linear-gradient(90deg, #fff, var(--accent)); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .subtitle { color: var(--muted); font-size: 1rem; margin-bottom: 2rem; }
        .badge { display: inline-block; padding: 4px 12px; background: rgba(0, 240, 255, 0.1); color: var(--accent); border-radius: 20px; font-size: 0.8rem; font-weight: 600; margin: 4px; border: 1px solid rgba(0, 240, 255, 0.2); }
        .footer { margin-top: 2rem; font-size: 0.8rem; color: var(--muted); border-top: 1px solid rgba(255,255,255,0.05); padding-top: 1rem; }
        .status-dot { display: inline-block; width: 8px; height: 8px; background: #00ff88; border-radius: 50%; margin-right: 6px; box-shadow: 0 0 8px #00ff88; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="logo">HexaSynq Gateway</div>
        <div class="subtitle">Secure AI & WhatsApp Orchestration Layer by <strong>HexaBiz Solutions</strong></div>
        
        <div>
          <span class="badge">v2.3.7</span>
          <span class="badge">Node.js / Express</span>
          <span class="badge">Evolution API v2</span>
          <span class="badge">Ollama / FCM</span>
        </div>

        <div style="margin-top: 2rem; text-align: left; background: rgba(0,0,0,0.3); padding: 1rem; border-radius: 8px; font-family: monospace; font-size: 0.85rem;">
          <div><span class="status-dot"></span> API Gateway: <span style="color:#00ff88">Operational</span></div>
          <div style="margin-top:8px; color: var(--muted);">Endpoint: <span style="color:var(--accent)">${GATEWAY_PUBLIC_URL}</span></div>
          <div style="margin-top:8px; color: var(--muted);">For programmatic access, please refer to the internal API documentation or contact the system administrator.</div>
        </div>

        <div class="footer">
          &copy; ${new Date().getFullYear()} HexaBiz Solutions. All systems secured via HMAC-256 & End-to-End Encryption.
        </div>
      </div>
    </body>
    </html>
  `;
  res.setHeader('Content-Type', 'text/html');
  res.status(200).send(html);
});

// 2. Deep Health Check for Coolify (GET /health)
app.get("/health", async (req, res) => {
  const health = {
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: {
      evolution_api: "unknown",
      ollama: "unknown",
      firebase: isFirebaseReady ? "ok" : "degraded",
    }
  };

  // Check Evolution API
  try {
    const evoRes = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/`, { method: "GET" });
    // 404 is fine, it just means the root path isn't a specific endpoint, but the server is responding
    health.checks.evolution_api = evoRes.ok || evoRes.status === 404 ? "ok" : "degraded";
  } catch {
    health.checks.evolution_api = "down";
  }

  // Check Ollama (Primary Runner)
  if (AI_PROVIDER === "ollama" && RUNNERS.length > 0) {
    try {
      const ollamaRes = await fetchWithTimeout(`${RUNNERS[0].url}/api/tags`, { method: "GET" });
      health.checks.ollama = ollamaRes.ok ? "ok" : "degraded";
    } catch {
      health.checks.ollama = "down";
    }
  } else {
    health.checks.ollama = "skipped";
  }

  // Determine overall status
  if (health.checks.evolution_api === "down" || health.checks.ollama === "down") {
    health.status = "degraded";
    return res.status(503).json(health); // 503 tells Coolify to restart or alert
  }

  res.status(200).json(health);
});

// ============================================================
// TIER 1: HIGH VALUE ADMIN OPERATIONS
// ============================================================

app.post(
  "/api/instance/create",
  verifyEnrollmentKey,
  strictIpRateLimit,
  verifyPlayIntegrityToken,
  async (req, res) => {
    const { deviceId } = req.body ?? {};
    const wantsPairing = req.body?.usePairingCode === true;

    if (!isValidDeviceId(deviceId)) {
      return res.status(400).json({ error: "Invalid device ID assignment" });
    }
    const phone = normalizePhone(req.body?.phoneNumber);
    if (!phone) {
      return res.status(400).json({ error: "Invalid phone number. Use country code + number, 8 to 15 digits." });
    }

    const instanceName = deriveInstanceName(phone);
    const deviceSecret = deriveDeviceSecret(deviceId);
    console.log(`[CREATE] instance=${instanceName} device=${deviceId} mode=${wantsPairing ? "pairing" : "qr"}`);

    const requestBody = {
      instanceName,
      token: deviceSecret,
      qrcode: true,
      integration: "WHATSAPP-BAILEYS",
      groupsIgnore: true,
      alwaysOnline: false,
      readMessages: false,
      readStatus: false,
      rejectCall: false,
      webhook: buildWebhookConfig(),
    };
    if (wantsPairing) requestBody.number = phone;

    try {
      const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": EVOLUTION_GLOBAL_KEY,
        },
        body: JSON.stringify(requestBody),
      });

      const data = await evoResponse.json().catch(() => ({}));
      const rawText = JSON.stringify(data);

      console.log(`[CREATE] Evolution responded with status ${evoResponse.status}`);

      if (evoResponse.ok) {
        registerInstance(instanceName, deviceId);
        await configureWebhook(instanceName);

        let pairingCode = null;
        if (wantsPairing) {
          pairingCode = data?.qrcode?.pairingCode ?? data?.pairingCode ?? null;
          if (!pairingCode) pairingCode = await fetchPairingCode(instanceName, deviceSecret, phone);
        }
        console.log(`[CREATE] ✅ created ${instanceName}, pairingCode ${pairingCode ? "present" : "absent"}`);
        return res.status(201).json({ instanceName, deviceSecret, pairingCode });
      }

      const alreadyExists =
        [400, 403, 409].includes(evoResponse.status) && /already (in use|exists)/i.test(rawText);

      if (alreadyExists) {
        const access = await instanceAccess(instanceName, deviceSecret);
        console.log(`[CREATE] ${instanceName} already exists, access=${access}`);

        if (access === "owned") {
          registerInstance(instanceName, deviceId);
          await configureWebhook(instanceName);

          const state = await getInstanceState(instanceName, deviceSecret);
          let pairingCode = null;
          if (wantsPairing && state !== "open") {
            pairingCode = await fetchPairingCode(instanceName, deviceSecret, phone);
          }
          console.log(`[CREATE] ✅ reused ${instanceName}, state=${state}, pairingCode ${pairingCode ? "present" : "absent"}`);
          return res.status(200).json({
            instanceName,
            deviceSecret,
            alreadyExisted: true,
            connectionState: state,
            pairingCode,
          });
        }
        if (access === "foreign") {
          return res.status(409).json({ error: "This number is linked to a different device." });
        }
        return res.status(502).json({ error: "Could not verify the existing instance. Try again." });
      }

      console.warn(`[CREATE] ❌ Evolution rejected creation of ${instanceName} (HTTP ${evoResponse.status})`);
      return res.status(evoResponse.status >= 400 ? evoResponse.status : 502).json({
        error: "Evolution API rejected instance creation",
        details: data?.response?.message ?? data?.message ?? data?.error ?? null,
      });
    } catch (err) {
      console.error(`[CREATE] ❌ Evolution API context error: ${err.message}`);
      return res.status(500).json({ error: "Evolution API context error", details: err.message });
    }
  }
);

app.post("/api/device/fcm", verifyDynamicHmac, async (req, res) => {
  const { fcmToken } = req.body ?? {};
  const claimedInstance = req.get("x-instance-name");

  // Enhanced logging to diagnose Android-to-Gateway mismatches
  console.log(`[FCM] Registration attempt -> deviceId: ${req.deviceId}, instance: ${claimedInstance || 'none'}`);

  if (typeof fcmToken !== "string" || fcmToken.length < 10 || fcmToken.length > 4096) {
    console.error(`[FCM] ❌ Invalid FCM token length from device ${req.deviceId}`);
    return res.status(400).json({ error: "Invalid FCM token format" });
  }

  // 1. Always save the token for this deviceId
  deviceFcmTokens.set(req.deviceId, fcmToken);
  console.log(`[FCM] ✅ Stored FCM token for device ${req.deviceId}`);

  // 2. If an instance name is provided, verify ownership and link them
  if (claimedInstance && isValidInstanceName(claimedInstance)) {
    const access = await instanceAccess(claimedInstance, req.deviceToken);
    if (access === "owned") {
      registerInstance(claimedInstance, req.deviceId);
      console.log(`[FCM] ✅ Successfully linked instance ${claimedInstance} to device ${req.deviceId}`);
    } else {
      console.warn(`[FCM] ❌ Device ${req.deviceId} does NOT own instance ${claimedInstance} (access check returned: ${access})`);
      // We still return 200 for the token storage, but warn about the instance link failure
    }
  } else {
    console.log(`[FCM] ℹ️ Token stored, but no valid 'x-instance-name' header provided. Will link on first message.`);
  }

  return res.status(200).json({ success: true, message: "FCM token registered" });
});
app.post("/api/instance/release", verifyDynamicHmac, async (req, res) => {
  const instanceName = resolveInstanceName(req);
  if (!instanceName) return res.status(400).json({ error: "Invalid instance name" });

  console.log(`[RELEASE] Release request for ${instanceName} from device ${req.deviceId}`);

  try {
    const access = await instanceAccess(instanceName, req.deviceToken);

    if (access === "missing") {
      unregisterInstance(instanceName, req.deviceId);
      return res.status(200).json({ success: true, message: "Instance already deleted" });
    }
    if (access === "foreign") {
      console.error(`[RELEASE] ❌ Device ${req.deviceId} does not own ${instanceName}`);
      return res.status(403).json({ error: "This device does not own that instance" });
    }
    if (access === "error") {
      return res.status(502).json({ error: "Could not verify instance ownership" });
    }

    try {
      await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/logout/${encodeURIComponent(instanceName)}`, {
        method: "DELETE",
        headers: { apikey: EVOLUTION_GLOBAL_KEY },
      });
    } catch (err) {
      console.warn(`[RELEASE] Logout failed (best effort): ${err.message}`);
    }

    const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/delete/${encodeURIComponent(instanceName)}`, {
      method: "DELETE",
      headers: { apikey: EVOLUTION_GLOBAL_KEY, "Content-Type": "application/json" },
    });

    if (evoResponse.ok || evoResponse.status === 404) {
      console.log(`[RELEASE] ✅ ${instanceName} released`);
      unregisterInstance(instanceName, req.deviceId);
      return res.status(200).json({ success: true, message: "Instance released or already deleted" });
    }

    const errorData = await evoResponse.text();
    console.error(`[RELEASE] ❌ Evolution failed to delete ${instanceName}: HTTP ${evoResponse.status}`);
    return res.status(evoResponse.status).json({ error: "Evolution failed to delete", details: errorData });
  } catch (err) {
    console.error(`[RELEASE] ❌ Failed to release instance: ${err.message}`);
    return res.status(500).json({ error: "Failed to release instance", details: err.message });
  }
});

// ============================================================
// TIER 2: ROUTINE OPERATIONS
// ============================================================

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
  const instanceName = resolveInstanceName(req);
  if (!instanceName) return res.status(400).json({ error: "Invalid instance name" });

  try {
    const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(instanceName)}`, {
      method: "GET",
      headers: { "apikey": req.deviceToken },
    });
    const data = await evoResponse.json().catch(() => ({}));
    return res.status(evoResponse.status).json(data);
  } catch (err) {
    console.error(`[STATUS] Failed to pull state connection: ${err.message}`);
    return res.status(500).json({ error: "Failed to pull state connection", details: err.message });
  }
});

// ============================================================
// WEBHOOKS (FCM + Money Lending Compliance)
// ============================================================

function jidToPhone(jid) {
  if (typeof jid !== "string") return null;
  // Updated to also match @lid and @hosted.lid formats
  const m = jid.match(/^(\d{8,15})(?::\d+)?@(?:s\.whatsapp\.net|c\.us|lid|hosted\.lid)$/);
  return m ? m[1] : null;
}

function extractMessageText(message) {
  if (!message || typeof message !== "object") return "";
  const inner = message.ephemeralMessage?.message || message.viewOnceMessage?.message || message;
  return (
    inner.conversation ||
    inner.extendedTextMessage?.text ||
    inner.imageMessage?.caption ||
    inner.videoMessage?.caption ||
    ""
  );
}

app.post("/webhook/evolution", verifyWebhookSecret, async (req, res) => {
  try {
    const payload = req.body ?? {};
    const instanceName = payload.instance;
    const event = String(payload.event ?? "").toLowerCase().replace(/_/g, ".");
    const items = Array.isArray(payload.data) ? payload.data : payload.data ? [payload.data] : [];

    console.log(`[WEBHOOK] Received event: ${event} for instance: ${instanceName}`);

        if (event === "messages.upsert") {
      for (const item of items) {
        const key = item?.key;
        if (!key) continue; // REMOVED: key.fromMe check to allow AI replies and multi-device sync

        const phoneNumber =
          jidToPhone(key.remoteJidAlt) || jidToPhone(key.senderPn) || jidToPhone(key.remoteJid);
        
        if (!phoneNumber) {
          console.log(`[WEBHOOK] Skipped non-user or unresolved JID: ${key.remoteJid}`);
          continue;
        }

        const protocol = item.message?.protocolMessage;
        if (protocol && (protocol.type === 0 || protocol.type === "REVOKE" || protocol.type === 7)) {
          const messageId = protocol.key?.id;
          if (messageId) {
            console.log(`[WEBHOOK] Message revoked/deleted: ${messageId}`);
            await sendFcmData(instanceName, {
              type: "MESSAGE_DELETED",
              messageId,
              phoneNumber,
              originalText: "",
            });
          }
          continue;
        }

        const messageText = extractMessageText(item.message);
        const isMedia = !!(item.message?.imageMessage || item.message?.videoMessage || item.message?.audioMessage || item.message?.documentMessage || item.message?.stickerMessage);

        if (!messageText && !isMedia) {
          console.log(`[WEBHOOK] Skipped message with no text or recognizable media content`);
          continue;
        }

                console.log(`[WEBHOOK] Syncing message from ${phoneNumber} (${messageText.length} chars), fromMe: ${key.fromMe}`);
        
        await sendFcmData(instanceName, {
          type: key.fromMe ? "SENT_WHATSAPP_MESSAGE" : "NEW_WHATSAPP_MESSAGE",
          phoneNumber,
          pushName: item.pushName || "Unknown",
          messageText: messageText ? messageText.slice(0, MAX_FCM_TEXT) : "[Media Message]",
          messageId: key.id || "",
          instanceName,
          isFromMe: String(key.fromMe), // FCM requires string values
          hasMedia: String(isMedia),    // FCM requires string values
        });
      }
    }
      if (event === "messages.update") {
      for (const item of items) {
        const key = item?.key;
        const status = item?.update?.status; // 1=PENDING, 2=SERVER_ACK, 3=DELIVERY_ACK, 4=READ
        if (!key || !status) continue;

        const phoneNumber = jidToPhone(key.remoteJidAlt) || jidToPhone(key.remoteJid);
        if (!phoneNumber) continue;

        console.log(`[WEBHOOK] Message status update: ${key.id} -> status ${status} (fromMe: ${key.fromMe})`);
        await sendFcmData(instanceName, {
          type: "MESSAGE_STATUS_UPDATE",
          messageId: key.id,
          phoneNumber,
          status: String(status),
          isFromMe: String(key.fromMe),
        });
      }
    }
    if (event === "messages.delete" || event === "message.revoke") {
      for (const item of items) {
        const messageId = item?.key?.id || item?.id;
        if (!messageId) continue;
        console.log(`[WEBHOOK] Message deleted: ${messageId}`);
        await sendFcmData(instanceName, {
          type: "MESSAGE_DELETED",
          messageId,
          phoneNumber: jidToPhone(item?.key?.remoteJidAlt) || jidToPhone(item?.key?.remoteJid) || "",
          originalText: String(item?.message?.conversation || "").slice(0, MAX_FCM_TEXT),
        });
      }
    }

    if (event === "presence.update") {
      for (const item of items) {
        const jid = item?.id;
        const presence = item?.presence || item?.presences?.[jid]?.lastKnownPresence;
        const phoneNumber = jidToPhone(jid);
        if (!phoneNumber || !presence) continue;

        console.log(`[WEBHOOK] Presence update: ${phoneNumber} is ${presence}`);
        await sendFcmData(instanceName, {
          type: "PRESENCE_UPDATE",
          phoneNumber,
          isOnline: presence === "available" || presence === "composing" || presence === "recording",
        });
      }
    }

    res.status(200).json({ success: true });
  } catch (err) {
    console.error("[WEBHOOK] Error processing Evolution payload:", err.message);
    res.status(500).json({ error: "Webhook processing failed" });
  }
});

// ============================================================
// MEMORY LEAK CLEANUP INTERVAL
// ============================================================
const CLEANUP_INTERVAL_MS = 60 * 60 * 1000; // Run every hour
setInterval(() => {
  const now = Date.now();

  for (const [key, val] of rateLimits) {
    if (now - val.windowStart > RATE_LIMIT_WINDOW_MS) rateLimits.delete(key);
  }

  const DAY_MS = 24 * 60 * 60 * 1000;
  for (const [key, val] of instanceCreationLimits) {
    if (now - val.windowStart > DAY_MS) instanceCreationLimits.delete(key);
  }

  cleanupNonces(now);
  console.log(`[CLEANUP] Pruned expired rate limit and nonce entries.`);
}, CLEANUP_INTERVAL_MS);


// --- INITIALIZATION ---
const server = app.listen(PORT, async () => {
  console.log(`\n========================================`);
  console.log(`Proxy system active and listening on port ${PORT}`);
  console.log(`========================================\n`);

  // Initialize Firebase Admin using Modular API
  try {
    const firebasePath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "/run/secrets/serviceAccountKey.json";
    console.log(`[FCM] Attempting to load Firebase config from: ${firebasePath}`);

    initializeApp({
      credential: cert(firebasePath)
    });
    isFirebaseReady = true; // <-- UPDATED: Flag for health check
    console.log("[FCM] ✅ Firebase Admin initialized successfully.");
  } catch (err) {
    console.error("[FCM] ❌ Failed to initialize Firebase Admin. FCM pushes will fail.", err.message);
  }

  if (AI_PROVIDER === "ollama") {
    console.log(`\n[OLLAMA] Verifying target model allocations: [${MODEL_NAME}] across runners...`);
    for (const runner of RUNNERS) {
      try {
        await waitForRunner(runner);
        console.log(`[OLLAMA] ✅ Runner ready: ${safeUrl(runner.url)}`);
      } catch (err) {
        console.error(`[OLLAMA] ❌ Runner diagnostic alert: ${err.message}`);
      }
    }
    console.log("");
  }
});

export default app;

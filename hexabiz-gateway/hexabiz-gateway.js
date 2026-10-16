`
import express from "express";
import helmet from "helmet";
import fetch from "node-fetch";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";

// ============================================================================
// HexaSynq Gateway — Production-Ready Security & Orchestration Layer
// Node.js 20+ | ES Modules | Hexagon Bizolutions
// ============================================================================
function positiveInt(value, fallback) {
  const n = Number.parseInt(value ?? "", 10);
  return Number.isSafeInteger(n) && n > 0 ? n : fallback;
}

function nonNegativeInt(value, fallback) {
  const n = Number.parseInt(value ?? "", 10);
  return Number.isSafeInteger(n) && n >= 0 ? n : fallback;
}

function envBool(value, fallback = false) {
  if (value == null || value === "") return fallback;
  return ["1", "true", "yes", "on"].includes(String(value).toLowerCase());
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function safeUrl(value) {
  try {
    const u = new URL(value);
    u.username = "";
    u.password = "";
    return u.toString().replace(/\/$/, "");
  } catch {
    return "[invalid-url]";
  }
}

function safeEqualText(a, b) {
  const left = Buffer.from(String(a ?? ""), "utf8");
  const right = Buffer.from(String(b ?? ""), "utf8");
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function isValidDeviceId(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{8,128}$/.test(value);
}

function normalizePhone(value) {
  const digits = String(value ?? "").replace(/\D/g, "");
  return /^\d{8,15}$/.test(digits) ? digits : null;
}

function isValidInstanceName(value) {
  return typeof value === "string" && /^(?:dev_\d{8,15}|device_[a-f0-9]{32})$/.test(value);
}

function deriveInstanceName(phoneDigits) {
  return `dev_${phoneDigits}`;
}

function deriveLegacyInstanceName(deviceId) {
  return `device_${crypto.createHash("sha256").update(deviceId).digest("hex").slice(0, 32)}`;
}

function truncateUtf8(value, maxBytes) {
  const text = String(value ?? "");
  const bytes = Buffer.from(text, "utf8");
  if (bytes.length <= maxBytes) return text;
  let end = maxBytes;
  while (end > 0 && (bytes[end] & 0xc0) === 0x80) end -= 1;
  return bytes.subarray(0, end).toString("utf8");
}

function extractPrompt(value, maxLength) {
  if (typeof value === "string") return value.slice(0, maxLength);
  if (!Array.isArray(value)) return "";
  return value
    .filter((m) => m && typeof m === "object" && typeof m.content === "string")
    .map((m) => `${String(m.role ?? "user")}: ${m.content}`)
    .join("\n")
    .slice(0, maxLength);
}

function evictOldest(map, max) {
  while (map.size > max) {
    const oldest = map.keys().next();
    if (oldest.done) break;
    map.delete(oldest.value);
  }
}


const PORT = positiveInt(process.env.PORT, 3000);
const EVOLUTION_SERVER_URL = (process.env.EVOLUTION_SERVER_URL || "http://whatsapp_api:8080").replace(/\/+$/, "");
const EVOLUTION_GLOBAL_KEY = process.env.EVOLUTION_GLOBAL_KEY;
const APP_ENROLLMENT_KEY = process.env.APP_ENROLLMENT_KEY;
const GATEWAY_PUBLIC_URL = (process.env.GATEWAY_PUBLIC_URL || "https://gateway.hexabizsolutions.cloud").replace(/\/+$/, "");
const AI_PROVIDER = (process.env.AI_PROVIDER || "ollama").toLowerCase();
const MODEL_NAME = process.env.OLLAMA_DEFAULT_MODEL || "synq:latest";
const POLLINATIONS_BASE_URL = process.env.POLLINATIONS_BASE_URL;
const POLLINATIONS_API_KEY = process.env.POLLINATIONS_API_KEY;
const FALLBACK_MODEL = process.env.FALLBACK_MODEL || "openai/gpt-4o-mini";
const OUTBOUND_TIMEOUT_MS = positiveInt(process.env.OUTBOUND_TIMEOUT_MS, 30000);
const HMAC_MAX_SKEW_SECONDS = positiveInt(process.env.HMAC_MAX_SKEW_SECONDS, 300);
const RATE_LIMIT_WINDOW_MS = positiveInt(process.env.RATE_LIMIT_WINDOW_MS, 60000);
const MAX_REQUESTS_PER_WINDOW = positiveInt(process.env.MAX_REQUESTS_PER_WINDOW, 30);
const INSTANCE_CREATE_LIMIT = positiveInt(process.env.INSTANCE_CREATE_LIMIT, 3);
const MAX_PROMPT_LENGTH = positiveInt(process.env.MAX_PROMPT_LENGTH, 12000);
const MAX_MESSAGES = positiveInt(process.env.MAX_MESSAGES, 40);
const MAX_QUEUE_SIZE = positiveInt(process.env.MAX_QUEUE_SIZE, 50);
const QUEUE_WAIT_MS = positiveInt(process.env.QUEUE_WAIT_MS, 10000);
const FCM_TEXT_BYTES = positiveInt(process.env.FCM_TEXT_BYTES, 700);
const MAX_JSON_BYTES = positiveInt(process.env.MAX_JSON_BYTES, 2 * 1024 * 1024);
const TRUST_PROXY_HOPS = nonNegativeInt(process.env.TRUST_PROXY_HOPS, 1);
const REQUIRE_PLAY_INTEGRITY = envBool(process.env.REQUIRE_PLAY_INTEGRITY, false);
const PLAY_INTEGRITY_VERIFIER_URL = process.env.PLAY_INTEGRITY_VERIFIER_URL;
const FIREBASE_SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "/run/secrets/serviceAccountKey.json";
const MAPPINGS_FILE = process.env.MAPPINGS_FILE_PATH || path.join(process.env.DATA_DIR || "/data", "gateway_mappings.json");

const RUNNERS = (process.env.OLLAMA_RUNNERS || "http://ollama:11434")
  .split(",").map((v) => v.trim().replace(/\/+$/, "")).filter(Boolean)
  .map((url) => ({ url, active: 0 }));

const MAX_CONCURRENT_PER_RUNNER = positiveInt(process.env.MAX_CONCURRENT_PER_RUNNER, 2);
const MAX_ACTIVE_AI = AI_PROVIDER === "ollama"
  ? Math.max(1, RUNNERS.length * MAX_CONCURRENT_PER_RUNNER)
  : positiveInt(process.env.MAX_CONCURRENT_AI, 8);

const WEBHOOK_SECRET = process.env.EVOLUTION_WEBHOOK_SECRET
  || (EVOLUTION_GLOBAL_KEY
    ? crypto.createHmac("sha256", EVOLUTION_GLOBAL_KEY).update("webhook:evolution").digest("hex")
    : null);

const WEBHOOK_EVENTS = [
  "MESSAGES_UPSERT", "MESSAGES_UPDATE", "MESSAGES_DELETE",
  "PRESENCE_UPDATE", "CONNECTION_UPDATE"
];

const MAX_NONCES = 20000;
const MAX_WEBHOOK_SEEN = 30000;

// Fail fast on critical missing config
if (!EVOLUTION_GLOBAL_KEY || !APP_ENROLLMENT_KEY) {
  console.error("[CONFIG] FATAL: EVOLUTION_GLOBAL_KEY and APP_ENROLLMENT_KEY are required.");
  process.exit(1);
}
if (AI_PROVIDER !== "ollama" && AI_PROVIDER !== "pollinations") {
  console.error("[CONFIG] FATAL: AI_PROVIDER must be 'ollama' or 'pollinations'.");
  process.exit(1);
}
if (AI_PROVIDER === "pollinations" && (!POLLINATIONS_API_KEY || !POLLINATIONS_BASE_URL)) {
  console.error("[CONFIG] FATAL: AI_PROVIDER=pollinations requires POLLINATIONS_API_KEY and POLLINATIONS_BASE_URL.");
  process.exit(1);
}
if (REQUIRE_PLAY_INTEGRITY && !PLAY_INTEGRITY_VERIFIER_URL) {
  console.error("[CONFIG] FATAL: REQUIRE_PLAY_INTEGRITY=true requires PLAY_INTEGRITY_VERIFIER_URL.");
  process.exit(1);
}


const app = express();
app.disable("x-powered-by");
app.set("trust proxy", TRUST_PROXY_HOPS);
app.use(helmet({
  contentSecurityPolicy: false, // Adjust if serving strict CSP HTML
}));

app.use(express.json({
  limit: MAX_JSON_BYTES,
  verify: (req, _res, buffer) => {
    req.rawBody = Buffer.from(buffer);
  }
}));


const instanceToDevice = new Map();
const deviceToInstance = new Map();
const deviceTokens = new Map();
const instanceTokens = new Map();
const deviceRateLimits = new Map();
const createRateLimits = new Map();
const consumedNonces = new Map();
const webhookSeen = new Map();
const aiWaiters = [];

let activeAiJobs = 0;
let firebaseReady = false;
let firebaseError = null;
let mappingsDirty = false;
let saveTimer = null;

function deviceSecret(deviceId) {
  return crypto.createHmac("sha256", EVOLUTION_GLOBAL_KEY).update(`device:${deviceId}`).digest("hex");
}

function writeMappings() {
  try {
    const data = {
      version: 2,
      instanceToDevice: Object.fromEntries(instanceToDevice),
      deviceFcmTokens: Object.fromEntries(deviceTokens),
      instanceFcmTokens: Object.fromEntries(instanceTokens),
      updatedAt: new Date().toISOString()
    };
    const dir = path.dirname(MAPPINGS_FILE);
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    const tmp = `${MAPPINGS_FILE}.tmp.${process.pid}.${crypto.randomBytes(5).toString("hex")}`;
    fs.writeFileSync(tmp, JSON.stringify(data), { encoding: "utf8", mode: 0o600 });
    fs.renameSync(tmp, MAPPINGS_FILE);
    mappingsDirty = false;
  } catch (err) {
    // Graceful degradation: if FS is read-only (e.g., ephemeral container), log and continue in-memory
    console.warn(`[PERSISTENCE] Save failed (running in memory-only mode): ${err.message}`);
    mappingsDirty = false; 
  }
}

function scheduleSave() {
  mappingsDirty = true;
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    writeMappings();
  }, 100);
  saveTimer.unref?.();
}

function loadMappings() {
  try {
    if (!fs.existsSync(MAPPINGS_FILE)) return;
    const data = JSON.parse(fs.readFileSync(MAPPINGS_FILE, "utf8"));
    if (data.instanceToDevice && typeof data.instanceToDevice === "object") {
      for (const [instance, device] of Object.entries(data.instanceToDevice)) {
        if (isValidInstanceName(instance) && isValidDeviceId(device)) {
          instanceToDevice.set(instance, device);
          if (!deviceToInstance.has(device)) deviceToInstance.set(device, instance);
        }
      }
    }
    if (data.deviceFcmTokens && typeof data.deviceFcmTokens === "object") {
      for (const [id, token] of Object.entries(data.deviceFcmTokens)) {
        if (isValidDeviceId(id) && typeof token === "string" && token.length >= 10 && token.length <= 4096) {
          deviceTokens.set(id, token);
        }
      }
    }
    if (data.instanceFcmTokens && typeof data.instanceFcmTokens === "object") {
      for (const [id, token] of Object.entries(data.instanceFcmTokens)) {
        if (isValidInstanceName(id) && typeof token === "string" && token.length >= 10 && token.length <= 4096) {
          instanceTokens.set(id, token);
        }
      }
    }
    console.log(`[PERSISTENCE] Loaded ${instanceToDevice.size} instance mappings and ${deviceTokens.size} device tokens.`);
  } catch (err) {
    console.error(`[PERSISTENCE] Could not load ${MAPPINGS_FILE}: ${err.message}`);
  }
}

function attachMapping(instanceName, deviceId, { allowMove = false } = {}) {
  const currentOwner = instanceToDevice.get(instanceName);
  const currentInstance = deviceToInstance.get(deviceId);
  
  if (currentOwner && currentOwner !== deviceId && !allowMove) {
    throw new Error("Instance is already associated with another device");
  }
  if (currentInstance && currentInstance !== instanceName && !allowMove) {
    throw new Error("Device is already associated with another instance");
  }
  if (allowMove && currentInstance && currentInstance !== instanceName) {
    if (instanceToDevice.get(currentInstance) === deviceId) instanceToDevice.delete(currentInstance);
    instanceTokens.delete(currentInstance);
  }
  if (allowMove && currentOwner && currentOwner !== deviceId) {
    if (deviceToInstance.get(currentOwner) === instanceName) deviceToInstance.delete(currentOwner);
  }
  
  instanceToDevice.set(instanceName, deviceId);
  deviceToInstance.set(deviceId, instanceName);
  const token = deviceTokens.get(deviceId);
  if (token) instanceTokens.set(instanceName, token);
  scheduleSave();
}

function detachInstance(instanceName, expectedDeviceId) {
  if (instanceToDevice.get(instanceName) !== expectedDeviceId) return false;
  instanceToDevice.delete(instanceName);
  if (deviceToInstance.get(expectedDeviceId) === instanceName) deviceToInstance.delete(expectedDeviceId);
  instanceTokens.delete(instanceName);
  scheduleSave();
  return true;
}

loadMappings();

function ipKey(req) {
  return String(req.ip || req.socket.remoteAddress || "unknown").replace(/^::ffff:/, "");
}

function checkWindow(map, key, limit, windowMs) {
  const now = Date.now();
  const current = map.get(key);
  if (!current || now - current.startedAt >= windowMs) {
    map.set(key, { count: 1, startedAt: now });
    return true;
  }
  if (current.count >= limit) return false;
  current.count += 1;
  return true;
}

function verifyEnrollment(req, res, next) {
  const key = req.get("x-enrollment-key");
  if (!key || !safeEqualText(key, APP_ENROLLMENT_KEY)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function verifyHmac(req, res, next) {
  const id = req.get("x-device-id");
  const signature = req.get("x-signature");
  const timestampText = req.get("x-timestamp");
  const nonce = req.get("x-nonce");

  if (!isValidDeviceId(id) || !signature || !/^[a-fA-F0-9]{64}$/.test(signature)
      || !timestampText || !/^\d{10,13}$/.test(timestampText)
      || !nonce || !/^[A-Za-z0-9._~-]{16,128}$/.test(nonce)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const timestamp = Number(timestampText);
  const timestampSeconds = timestamp > 9_999_999_999 ? Math.floor(timestamp / 1000) : timestamp;
  if (Math.abs(Math.floor(Date.now() / 1000) - timestampSeconds) > HMAC_MAX_SKEW_SECONDS) {
    return res.status(401).json({ error: "Signature expired" });
  }

  const secret = deviceSecret(id);
  const raw = req.rawBody ? req.rawBody.toString("utf8") : "";
  const expected = crypto.createHmac("sha256", secret).update(`${timestampText}.${nonce}.${raw}`, "utf8").digest("hex");
  
  if (!safeEqualText(signature.toLowerCase(), expected)) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const nonceKey = `${id}:${nonce}`;
  const now = Date.now();
  
  for (const [key, expiry] of consumedNonces) {
    if (expiry <= now) consumedNonces.delete(key);
  }
  
  if (consumedNonces.has(nonceKey)) {
    return res.status(401).json({ error: "Replay detected" });
  }
  
  consumedNonces.set(nonceKey, now + HMAC_MAX_SKEW_SECONDS * 1000);
  evictOldest(consumedNonces, MAX_NONCES);

  if (!checkWindow(deviceRateLimits, id, MAX_REQUESTS_PER_WINDOW, RATE_LIMIT_WINDOW_MS)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  req.deviceId = id;
  req.deviceToken = secret;
  next();
}

async function verifyPlayIntegrity(req, res, next) {
  if (!REQUIRE_PLAY_INTEGRITY) return next();
  const token = req.get("x-play-integrity-token");
  if (!token) return res.status(401).json({ error: "Play Integrity token required" });
  
  try {
    const response = await fetchWithTimeout(PLAY_INTEGRITY_VERIFIER_URL, {
      method: "POST",
      headers: { 
        "Content-Type": "application/json", 
        "Authorization": `Bearer ${process.env.PLAY_INTEGRITY_VERIFIER_KEY || ""}` 
      },
      body: JSON.stringify({ token, packageName: process.env.ANDROID_PACKAGE_NAME || "" })
    });
    
    if (!response.ok) {
      await discard(response);
      return res.status(401).json({ error: "Play Integrity verification failed" });
    }
    
    const result = await response.json();
    if (result?.valid !== true) {
      await discard(response);
      return res.status(401).json({ error: "Play Integrity verification failed" });
    }
    await discard(response);
    next();
  } catch (err) {
    console.error(`[INTEGRITY] Verification service failed: ${err.message}`);
    return res.status(503).json({ error: "Integrity verification unavailable" });
  }
}

function verifyWebhook(req, res, next) {
  // Header only: secrets in query strings end up in proxy/access logs.
  const supplied = req.get("x-webhook-secret");
  if (!supplied || !safeEqualText(supplied, WEBHOOK_SECRET)) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

// ----------------------------------------------------------------------------
// 6. Network & Evolution API Helpers
// ----------------------------------------------------------------------------
async function fetchWithTimeout(url, options = {}, timeoutMs = OUTBOUND_TIMEOUT_MS) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    // Keep the timeout active until the body has been consumed, then clear it.
    for (const reader of ["json", "text", "arrayBuffer"]) {
      const original = response[reader]?.bind(response);
      if (!original) continue;
      response[reader] = async (...args) => {
        try { return await original(...args); } finally { clearTimeout(timeout); }
      };
    }
    return response;
  } catch (err) {
    clearTimeout(timeout);
    throw err;
  }
}

async function discard(response) {
  try { await response.arrayBuffer(); } catch { /* ignore */ }
}

function evolutionHeaders(key = EVOLUTION_GLOBAL_KEY, json = false) {
  return { apikey: key, ...(json ? { "Content-Type": "application/json" } : {}) };
}

function webhookConfig() {
  return {
    enabled: true,
    url: `${GATEWAY_PUBLIC_URL}/webhook/evolution`,
    events: WEBHOOK_EVENTS,
    webhook_by_events: false,
    webhook_base64: false,
    headers: { "x-webhook-secret": WEBHOOK_SECRET }
  };
}

async function instanceExists(name) {
  try {
    const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/fetchInstances?instanceName=${encodeURIComponent(name)}`, {
      headers: evolutionHeaders()
    });
    if (!r.ok) {
      await discard(r);
      return r.status === 404 ? false : null;
    }
    const body = await r.json();
    const entries = Array.isArray(body) ? body : (Array.isArray(body?.instances) ? body.instances : body ? [body] : []);
    return entries.some((item) => (item?.name || item?.instanceName || item?.instance?.instanceName) === name);
  } catch (err) {
    console.error(`[EVOLUTION] instanceExists failed: ${err.message}`);
    return null;
  }
}

async function instanceAccess(name, secret) {
  try {
    const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(name)}`, {
      headers: evolutionHeaders(secret)
    });
    await discard(r);
    if (r.ok) return "owned";
    const exists = await instanceExists(name);
    if (exists === false) return "missing";
    if (exists === true) return "foreign";
    return "error";
  } catch (err) {
    console.error(`[EVOLUTION] Ownership check failed: ${err.message}`);
    return "error";
  }
}

async function getInstanceState(name, secret) {
  try {
    const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(name)}`, {
      headers: evolutionHeaders(secret)
    });
    if (!r.ok) {
      await discard(r);
      return null;
    }
    const data = await r.json();
    return data?.instance?.state ?? data?.state ?? null;
  } catch { 
    return null; 
  }
}

async function configureWebhook(name) {
  const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/webhook/set/${encodeURIComponent(name)}`, {
    method: "POST", 
    headers: evolutionHeaders(EVOLUTION_GLOBAL_KEY, true),
    body: JSON.stringify({ webhook: webhookConfig() })
  });
  if (!r.ok) {
    const details = truncateUtf8(await r.text().catch(() => ""), 500);
    throw new Error(`Evolution webhook/set returned HTTP ${r.status}: ${details}`);
  }
  await discard(r);
}

async function deleteEvolutionInstance(name) {
  try {
    const logout = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/logout/${encodeURIComponent(name)}`, {
      method: "DELETE", headers: evolutionHeaders(EVOLUTION_GLOBAL_KEY)
    });
    await discard(logout);
  } catch (err) {
    console.warn(`[RELEASE] Logout failed: ${err.message}`);
  }
  const response = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/delete/${encodeURIComponent(name)}`, {
    method: "DELETE", headers: evolutionHeaders(EVOLUTION_GLOBAL_KEY)
  });
  return response;
}

async function requestPairingCode(name, secret, phone) {
  const url = `${EVOLUTION_SERVER_URL}/instance/connect/${encodeURIComponent(name)}?number=${encodeURIComponent(phone)}`;
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await sleep(attempt === 1 ? 1200 : 2500);
    try {
      const r = await fetchWithTimeout(url, { headers: evolutionHeaders(secret) });
      const body = await r.json().catch(() => ({}));
      const code = body?.pairingCode ?? body?.qrcode?.pairingCode ?? null;
      if (r.ok && code) return code;
      console.warn(`[PAIRING] Attempt ${attempt} returned HTTP ${r.status}; codePresent=${Boolean(code)}`);
    } catch (err) {
      console.warn(`[PAIRING] Attempt ${attempt} failed: ${err.message}`);
    }
  }
  return null;
}

function resolveInstanceName(req) {
  const header = req.get("x-instance-name");
  if (header) return isValidInstanceName(header) ? header : null;
  return deviceToInstance.get(req.deviceId) || deriveLegacyInstanceName(req.deviceId);
}

// ----------------------------------------------------------------------------
// 7. AI Concurrency Control
// ----------------------------------------------------------------------------
function makeSlotRelease() {
  let released = false;
  return () => {
    if (released) return;
    released = true;
    releaseAiSlot();
  };
}

function reserveAiSlot() {
  if (activeAiJobs < MAX_ACTIVE_AI) {
    activeAiJobs += 1;
    return Promise.resolve(makeSlotRelease());
  }
  if (aiWaiters.length >= MAX_QUEUE_SIZE) return Promise.resolve(null);
  
  return new Promise((resolve) => {
    const waiter = { resolve, timer: null };
    waiter.timer = setTimeout(() => {
      const index = aiWaiters.indexOf(waiter);
      if (index >= 0) aiWaiters.splice(index, 1);
      resolve(null);
    }, QUEUE_WAIT_MS);
    aiWaiters.push(waiter);
  });
}

function releaseAiSlot() {
  const next = aiWaiters.shift();
  if (next) {
    clearTimeout(next.timer);
    next.resolve(makeSlotRelease());
  } else {
    activeAiJobs = Math.max(0, activeAiJobs - 1);
  }
}

async function withAiSlot(task) {
  const release = await reserveAiSlot();
  if (!release) {
    const err = new Error("AI queue is full");
    err.statusCode = 503;
    throw err;
  }
  try { return await task(); }
  finally { release(); }
}

async function runOllama(payload, endpoint) {
  const runner = RUNNERS
    .filter((item) => item.active < MAX_CONCURRENT_PER_RUNNER)
    .sort((a, b) => a.active - b.active)[0];
    
  if (!runner) {
    const err = new Error("No Ollama runner has available capacity");
    err.statusCode = 503;
    throw err;
  }
  
  runner.active += 1;
  try {
    const response = await fetchWithTimeout(`${runner.url}${endpoint}`, {
      method: "POST", 
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ...payload, model: MODEL_NAME, stream: false })
    });
    let data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
    
    // Normalise /api/generate ({ response }) to the same shape as /api/chat ({ message }).
    if (endpoint === "/api/generate" && typeof data?.response === "string") {
      data = { ...data, message: { role: "assistant", content: data.response } };
    }
    return { source: "Ollama", data };
  } finally {
    runner.active -= 1;
  }
}

function validateMessages(messages) {
  if (!Array.isArray(messages) || messages.length < 1 || messages.length > MAX_MESSAGES) return null;
  let total = 0;
  const safe = [];
  for (const message of messages) {
    if (!message || typeof message !== "object" || !["system", "user", "assistant"].includes(message.role)
        || typeof message.content !== "string") return null;
    total += Buffer.byteLength(message.content, "utf8");
    if (total > MAX_PROMPT_LENGTH) return null;
    safe.push({ role: message.role, content: message.content });
  }
  return safe;
}

async function callPollinations(promptOrMessages) {
  if (!POLLINATIONS_API_KEY || !POLLINATIONS_BASE_URL) throw new Error("Pollinations fallback is not configured");
  const prompt = extractPrompt(promptOrMessages, MAX_PROMPT_LENGTH);
  if (!prompt.trim()) throw new Error("Prompt is empty");
  
  const response = await fetchWithTimeout(POLLINATIONS_BASE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${POLLINATIONS_API_KEY}` },
    body: JSON.stringify({ model: FALLBACK_MODEL, messages: [{ role: "user", content: prompt }] })
  });
  
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(`Pollinations returned HTTP ${response.status}`);
  
  const content = data?.choices?.[0]?.message?.content?.trim();
  if (!content) throw new Error("Pollinations returned an empty response");
  
  return { source: "Pollinations-Fallback", data: { message: { role: "assistant", content } } };
}

async function runAi(messages, prompt) {
  return withAiSlot(async () => {
    let primaryError = null;
    if (AI_PROVIDER === "ollama") {
      try {
        if (messages) return await runOllama({ messages }, "/api/chat");
        return await runOllama({ prompt }, "/api/generate");
      } catch (err) {
        primaryError = err;
        console.error(`[AI] Ollama failed: ${err.message}`);
      }
    }
    try { 
      return await callPollinations(messages || prompt); 
    } catch (err) {
      const combined = new Error(`AI providers failed: ${primaryError?.message || "primary unavailable"}; fallback: ${err.message}`);
      combined.statusCode = 502;
      throw combined;
    }
  });
}

// ----------------------------------------------------------------------------
// 8. WhatsApp Event & FCM Helpers
// ----------------------------------------------------------------------------
function jidToPhone(jid) {
  if (typeof jid !== "string") return null;
  const match = jid.match(/^(\d{8,15})(?::\d+)?@(?:s\.whatsapp\.net|c\.us|lid|hosted\.lid)$/i);
  return match?.[1] ?? null;
}

function extractMessageText(message) {
  if (!message || typeof message !== "object") return "";
  let current = message;
  for (let i = 0; i < 5; i += 1) {
    const wrapper = current.ephemeralMessage?.message
      || current.viewOnceMessage?.message
      || current.viewOnceMessageV2?.message
      || current.documentWithCaptionMessage?.message;
    if (!wrapper) break;
    current = wrapper;
  }
  return current.conversation
    || current.extendedTextMessage?.text
    || current.imageMessage?.caption
    || current.videoMessage?.caption
    || current.documentMessage?.caption
    || current.buttonsResponseMessage?.selectedDisplayText
    || current.templateButtonReplyMessage?.selectedDisplayText
    || current.listResponseMessage?.title
    || current.listResponseMessage?.singleSelectReply?.selectedRowId
    || "";
}

function eventItems(payload) {
  const data = payload?.data;
  if (Array.isArray(data)) return data;
  return data && typeof data === "object" ? [data] : [];
}

function payloadTextBudget(payload) {
  const result = {};
  let budget = 2800; // FCM aggregate data payload limit is ~4KB; reserve space for keys/metadata
  for (const [key, value] of Object.entries(payload)) {
    const text = String(value ?? "");
    if (key === "messageText" || key === "originalText") {
      const max = Math.min(FCM_TEXT_BYTES, Math.max(0, budget));
      result[key] = truncateUtf8(text, max);
    } else {
      result[key] = text;
    }
    budget -= Buffer.byteLength(key, "utf8") + Buffer.byteLength(result[key], "utf8") + 8;
  }
  if (budget < 0) {
    for (const key of ["pushName", "originalText", "messageText"]) {
      if (budget >= 0) break;
      if (result[key]) {
        const currentBytes = Buffer.byteLength(result[key], "utf8");
        const trim = Math.min(currentBytes, Math.abs(budget) + 100);
        result[key] = truncateUtf8(result[key], Math.max(0, currentBytes - trim));
        budget += trim;
      }
    }
  }
  return result;
}

async function sendFcm(instanceName, payload) {
  const deviceId = instanceToDevice.get(instanceName);
  const token = (deviceId && deviceTokens.get(deviceId)) || instanceTokens.get(instanceName);
  
  if (!deviceId || !token) {
    console.warn(`[FCM] No verified FCM mapping for instance ${instanceName}; delivery skipped.`);
    return { sent: false, reason: "mapping_missing" };
  }
  if (!firebaseReady) {
    console.error(`[FCM] Firebase unavailable; delivery skipped for ${instanceName}.`);
    return { sent: false, reason: "firebase_unavailable" };
  }
  
  const data = payloadTextBudget(Object.fromEntries(Object.entries(payload).map(([k, v]) => [k, String(v ?? "")])));
  try {
    await getMessaging().send({ token, data, android: { priority: "high" } });
    console.log(`[FCM] Sent type=${data.type || "data"} instance=${instanceName} device=${deviceId}`);
    return { sent: true };
  } catch (err) {
    console.error(`[FCM] Send failed instance=${instanceName} device=${deviceId} code=${err.code || "unknown"} message=${err.message}`);
    if (["messaging/invalid-registration-token", "messaging/registration-token-not-registered"].includes(err.code)) {
      if (deviceTokens.get(deviceId) === token) deviceTokens.delete(deviceId);
      if (instanceTokens.get(instanceName) === token) instanceTokens.delete(instanceName);
      scheduleSave();
    }
    return { sent: false, reason: err.code || "send_failed" };
  }
}

function webhookAlreadyDelivered(instanceName, id) {
  const key = `${instanceName}:${id}`;
  const expiry = webhookSeen.get(key);
  if (expiry == null) return false;
  if (expiry <= Date.now()) {
    webhookSeen.delete(key);
    return false;
  }
  return true;
}

function rememberWebhookDelivered(instanceName, id) {
  webhookSeen.set(`${instanceName}:${id}`, Date.now() + 10 * 60 * 1000);
  evictOldest(webhookSeen, MAX_WEBHOOK_SEEN);
}
app.get("/", (_req, res) => {
  res.type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>HexaSynq Gateway</title><style>body{font-family:system-ui;background:#0a0a0f;color:#eee;display:grid;place-items:center;min-height:100vh;margin:0}.card{max-width:640px;padding:2rem;border:1px solid #26303a;border-radius:16px;background:#13131f}h1{color:#00ddeb}small{color:#aab}</style></head><body><main class="card"><h1>HexaSynq Gateway</h1><p>Secure AI and WhatsApp orchestration layer by Hexagon Bizolutions.</p><p><small>Use authenticated API endpoints; operational details are available through /health.</small></p></main></body></html>`);
});

app.get("/health/live", (_req, res) => res.status(200).json({ status: "ok", uptime: process.uptime() }));

app.get("/health", async (_req, res) => {
  const checks = {
    evolution_api: "unknown",
    ollama: AI_PROVIDER === "ollama" ? "unknown" : "skipped",
    firebase: firebaseReady ? "ok" : "down"
  };
  
  try {
    const response = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/`, {}, 5000);
    checks.evolution_api = response.ok || response.status === 404 ? "ok" : "degraded";
    await discard(response);
  } catch { 
    checks.evolution_api = "down"; 
  }
  
  if (AI_PROVIDER === "ollama") {
    if (!RUNNERS.length) {
      checks.ollama = "down";
    } else {
      try {
        const response = await fetchWithTimeout(`${RUNNERS[0].url}/api/tags`, {}, 5000);
        checks.ollama = response.ok ? "ok" : "degraded";
        await discard(response);
      } catch { 
        checks.ollama = "down"; 
      }
    }
  }
  
  const required = [checks.evolution_api, checks.firebase, ...(AI_PROVIDER === "ollama" ? [checks.ollama] : [])];
  const status = required.every((value) => value === "ok" || value === "skipped") ? "ok" : "degraded";
  res.status(status === "ok" ? 200 : 503).json({ status, timestamp: new Date().toISOString(), uptime: process.uptime(), checks });
});

app.post("/api/instance/create", verifyEnrollment, async (req, res) => {
  if (!checkWindow(createRateLimits, ipKey(req), INSTANCE_CREATE_LIMIT, 24 * 60 * 60 * 1000)) {
    return res.status(429).json({ error: "Instance creation limit reached for this network. Try again later." });
  }
  
  const { deviceId, fcmToken } = req.body ?? {};
  const phone = normalizePhone(req.body?.phoneNumber);
  const wantsPairing = req.body?.usePairingCode === true;
  
  if (!isValidDeviceId(deviceId)) return res.status(400).json({ error: "Invalid device ID" });
  if (!phone) return res.status(400).json({ error: "Invalid phone number; use country code and 8–15 digits." });
  if (fcmToken != null && (typeof fcmToken !== "string" || fcmToken.length < 10 || fcmToken.length > 4096)) {
    return res.status(400).json({ error: "Invalid FCM token" });
  }
  
  const name = deriveInstanceName(phone);
  const secret = deviceSecret(deviceId);

  // Local mapping conflicts are checked BEFORE touching Evolution
  const existingOwner = instanceToDevice.get(name);
  if (existingOwner && existingOwner !== deviceId) {
    const access = await instanceAccess(name, secret);
    if (access !== "owned") return res.status(409).json({ error: "This number is linked to a different device." });
  }
  
  const priorInstance = deviceToInstance.get(deviceId);
  if (priorInstance && priorInstance !== name) {
    return res.status(409).json({ error: "This device is already linked to a different instance. Release it first." });
  }

  const requestBody = {
    instanceName: name, token: secret, qrcode: true, integration: "WHATSAPP-BAILEYS",
    groupsIgnore: true, alwaysOnline: false, readMessages: false, readStatus: false,
    rejectCall: false, webhook: webhookConfig()
  };
  if (wantsPairing) requestBody.number = phone;
  
  try {
    const response = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/create`, {
      method: "POST", headers: evolutionHeaders(EVOLUTION_GLOBAL_KEY, true), body: JSON.stringify(requestBody)
    });
    const body = await response.json().catch(() => ({}));
    let created = response.ok;
    let reused = false;
    
    if (!created && [400, 403, 409].includes(response.status) && /already|exists|in use/i.test(JSON.stringify(body))) {
      const access = await instanceAccess(name, secret);
      if (access === "owned") { created = true; reused = true; }
      else if (access === "foreign") return res.status(409).json({ error: "This number is linked to a different device." });
      else return res.status(502).json({ error: "Could not verify the existing instance." });
    }
    
    if (!created) {
      console.warn(`[CREATE] Evolution rejected ${name}: HTTP ${response.status}`);
      return res.status(502).json({ error: "Evolution API rejected instance creation", details: body?.message || body?.error || null });
    }

    // Re-check after the await (race condition protection); roll back a freshly created instance on conflict.
    try {
      if (fcmToken) deviceTokens.set(deviceId, fcmToken);
      attachMapping(name, deviceId);
    } catch (err) {
      console.warn(`[CREATE] Mapping conflict for ${name}: ${err.message}`);
      if (!reused) {
        try {
          const del = await deleteEvolutionInstance(name);
          await discard(del);
        } catch (cleanupErr) {
          console.error(`[CREATE] Cleanup of ${name} failed: ${cleanupErr.message}`);
        }
      }
      return res.status(409).json({ error: "Instance mapping conflict." });
    }

    try { await configureWebhook(name); }
    catch (err) { console.error(`[WEBHOOK] Configure failed for ${name}: ${err.message}`); }
    
    let pairingCode = body?.qrcode?.pairingCode ?? body?.pairingCode ?? null;
    if (wantsPairing && !pairingCode) pairingCode = await requestPairingCode(name, secret, phone);
    const state = reused ? await getInstanceState(name, secret) : null;
    
    return res.status(reused ? 200 : 201).json({
      instanceName: name, deviceSecret: secret, pairingCode,
      ...(reused ? { alreadyExisted: true, connectionState: state } : {})
    });
  } catch (err) {
    console.error(`[CREATE] Failed for ${name}: ${err.message}`);
    return res.status(502).json({ error: "Could not communicate with Evolution API" });
  }
});

app.post("/api/device/fcm", verifyHmac, async (req, res) => {
  const token = req.body?.fcmToken;
  const claimed = req.body?.instanceName || req.get("x-instance-name") || deviceToInstance.get(req.deviceId);
  
  if (typeof token !== "string" || token.length < 10 || token.length > 4096) {
    return res.status(400).json({ error: "Invalid FCM token" });
  }
  
  let verifiedInstance = null;
  if (claimed) {
    if (!isValidInstanceName(claimed)) return res.status(400).json({ error: "Invalid instance name" });
    const access = await instanceAccess(claimed, req.deviceToken);
    if (access === "foreign") return res.status(403).json({ error: "This device does not own that instance" });
    if (access === "missing") return res.status(404).json({ error: "Instance does not exist" });
    if (access !== "owned") return res.status(502).json({ error: "Could not verify instance ownership" });
    
    const owner = instanceToDevice.get(claimed);
    if (owner && owner !== req.deviceId) return res.status(409).json({ error: "Instance mapping conflict" });
    const prior = deviceToInstance.get(req.deviceId);
    if (prior && prior !== claimed) return res.status(409).json({ error: "Device is already mapped to another instance" });
    verifiedInstance = claimed;
  }
  
  deviceTokens.set(req.deviceId, token);
  if (verifiedInstance) attachMapping(verifiedInstance, req.deviceId);
  scheduleSave();
  
  console.log(`[FCM] Registered token for device=${req.deviceId} instance=${verifiedInstance || "unlinked"}`);
  return res.status(200).json({ success: true, instanceName: verifiedInstance });
});

app.post("/api/instance/release", verifyHmac, async (req, res) => {
  const name = resolveInstanceName(req);
  if (!name) return res.status(400).json({ error: "Invalid instance name" });
  
  const access = await instanceAccess(name, req.deviceToken);
  if (access === "missing") {
    detachInstance(name, req.deviceId);
    return res.status(200).json({ success: true, message: "Instance already deleted" });
  }
  if (access === "foreign") return res.status(403).json({ error: "This device does not own that instance" });
  if (access !== "owned") return res.status(502).json({ error: "Could not verify instance ownership" });
  
  try {
    const response = await deleteEvolutionInstance(name);
    if (!response.ok && response.status !== 404) {
      const details = truncateUtf8(await response.text().catch(() => ""), 500);
      return res.status(502).json({ error: "Evolution failed to delete instance", details });
    }
    await discard(response);
    detachInstance(name, req.deviceId);
    return res.status(200).json({ success: true, message: "Instance released or already deleted" });
  } catch (err) {
    console.error(`[RELEASE] Failed for ${name}: ${err.message}`);
    return res.status(502).json({ error: "Failed to release instance" });
  }
});

app.post("/api/chat", verifyHmac, verifyPlayIntegrity, async (req, res) => {
  const body = req.body ?? {};
  const messages = body.messages == null ? null : validateMessages(body.messages);
  const prompt = typeof body.prompt === "string" ? body.prompt.slice(0, MAX_PROMPT_LENGTH) : "";
  
  if (body.messages != null && !messages) return res.status(400).json({ error: "Invalid or oversized messages array" });
  if (!messages && !prompt.trim()) return res.status(400).json({ error: "A prompt or valid messages array is required" });
  
  try {
    const result = await runAi(messages, prompt);
    return res.status(200).json(result);
  } catch (err) {
    const status = err.statusCode || 502;
    console.error(`[AI] Request failed: ${err.message}`);
    return res.status(status).json({ error: "AI request failed", details: err.message });
  }
});

app.get("/api/instance/status", verifyHmac, async (req, res) => {
  const name = resolveInstanceName(req);
  if (!name) return res.status(400).json({ error: "Invalid instance name" });
  
  const access = await instanceAccess(name, req.deviceToken);
  if (access === "foreign") return res.status(403).json({ error: "This device does not own that instance" });
  if (access === "missing") return res.status(404).json({ error: "Instance not found" });
  if (access !== "owned") return res.status(502).json({ error: "Could not verify instance ownership" });
  
  try {
    const response = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(name)}`, {
      headers: evolutionHeaders(req.deviceToken)
    });
    const data = await response.json().catch(() => ({}));
    return res.status(response.status).json(data);
  } catch (err) {
    console.error(`[STATUS] Failed for ${name}: ${err.message}`);
    return res.status(502).json({ error: "Failed to retrieve instance state" });
  }
});

app.post("/webhook/evolution", verifyWebhook, async (req, res) => {
  const payload = req.body ?? {};
  const instanceName = payload.instance || payload.instanceName;
  const event = String(payload.event ?? "").toLowerCase().replace(/_/g, ".");
  
  if (!isValidInstanceName(instanceName)) return res.status(400).json({ error: "Invalid instance in webhook" });
  if (!instanceToDevice.has(instanceName)) {
    console.warn(`[WEBHOOK] No local device mapping for instance=${instanceName}`);
    return res.status(200).json({ success: true, ignored: "mapping_missing" });
  }
  
  try {
    const items = eventItems(payload);
    
    if (event === "messages.upsert") {
      for (const item of items) {
        const key = item?.key;
        if (!key) continue;
        
        const messageId = String(key.id || "");
        const dedupeId = messageId ? `upsert:${messageId}:${Boolean(key.fromMe)}` : null;
        if (dedupeId && webhookAlreadyDelivered(instanceName, dedupeId)) continue;
        
        const jid = key.remoteJidAlt || key.senderPn || key.remoteJid;
        const phone = jidToPhone(jid);
        if (!phone) {
          console.info(`[WEBHOOK] Skipped unresolved JID instance=${instanceName} jidType=${typeof jid} fromMe=${Boolean(key.fromMe)}`);
          continue;
        }
        
        const protocol = item?.message?.protocolMessage;
        if (protocol && [0, 7, "REVOKE"].includes(protocol.type)) {
          const deletedId = protocol.key?.id;
          if (deletedId) {
            const result = await sendFcm(instanceName, {
              type: "MESSAGE_DELETED", messageId: deletedId, phoneNumber: phone, originalText: ""
            });
            if (result.sent && dedupeId) rememberWebhookDelivered(instanceName, dedupeId);
          }
          continue;
        }
        
        const text = extractMessageText(item?.message);
        const message = item?.message || {};
        const isMedia = Boolean(message.imageMessage || message.videoMessage || message.audioMessage
          || message.documentMessage || message.stickerMessage || message.ptvMessage);
          
        if (!text && !isMedia) {
          console.info(`[WEBHOOK] Skipped unsupported message type instance=${instanceName} messageId=${messageId || "none"}`);
          continue;
        }
        
        const result = await sendFcm(instanceName, {
          type: key.fromMe ? "SENT_WHATSAPP_MESSAGE" : "NEW_WHATSAPP_MESSAGE",
          phoneNumber: phone,
          pushName: truncateUtf8(item?.pushName || "Unknown", 80),
          messageText: text ? truncateUtf8(text, FCM_TEXT_BYTES) : "[Media Message]",
          messageId,
          instanceName,
          isFromMe: String(Boolean(key.fromMe)),
          hasMedia: String(isMedia)
        });
        if (result.sent && dedupeId) rememberWebhookDelivered(instanceName, dedupeId);
      }
    } else if (event === "messages.update") {
      for (const item of items) {
        const key = item?.key;
        const status = item?.update?.status;
        if (!key?.id || status == null) continue;
        const phone = jidToPhone(key.remoteJidAlt) || jidToPhone(key.remoteJid);
        if (!phone) continue;
        await sendFcm(instanceName, {
          type: "MESSAGE_STATUS_UPDATE", messageId: key.id, phoneNumber: phone,
          status: String(status), isFromMe: String(Boolean(key.fromMe))
        });
      }
    } else if (event === "messages.delete" || event === "message.revoke") {
      for (const item of items) {
        const messageId = item?.key?.id || item?.id;
        if (!messageId) continue;
        await sendFcm(instanceName, {
          type: "MESSAGE_DELETED", messageId,
          phoneNumber: jidToPhone(item?.key?.remoteJidAlt) || jidToPhone(item?.key?.remoteJid) || "",
          originalText: truncateUtf8(item?.message?.conversation || "", FCM_TEXT_BYTES)
        });
      }
    } else if (event === "presence.update") {
      for (const item of items) {
        const jid = item?.id;
        const presence = item?.presence || item?.presences?.[jid]?.lastKnownPresence;
        const phone = jidToPhone(jid);
        if (!phone || !presence) continue;
        await sendFcm(instanceName, {
          type: "PRESENCE_UPDATE", phoneNumber: phone,
          isOnline: String(["available", "composing", "recording"].includes(presence))
        });
      }
    } else if (event === "connection.update") {
      const data = payload.data || {};
      await sendFcm(instanceName, {
        type: "CONNECTION_UPDATE",
        connectionState: String(data?.state || data?.instance?.state || "unknown"),
        instanceName
      });
    }
    
    return res.status(200).json({ success: true });
  } catch (err) {
    console.error(`[WEBHOOK] Processing failed event=${event} instance=${instanceName}: ${err.message}`);
    return res.status(500).json({ error: "Webhook processing failed" });
  }
});

// ----------------------------------------------------------------------------
// 10. Global Error Handler & Cleanup
// ----------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  if (err?.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  if (err instanceof SyntaxError && "body" in err) return res.status(400).json({ error: "Malformed JSON" });
  console.error(`[HTTP] Unhandled middleware error: ${err?.message || "unknown"}`);
  return res.status(500).json({ error: "Internal server error" });
});

const cleanupTimer = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of deviceRateLimits) if (now - entry.startedAt > RATE_LIMIT_WINDOW_MS) deviceRateLimits.delete(key);
  for (const [key, entry] of createRateLimits) if (now - entry.startedAt > 24 * 60 * 60 * 1000) createRateLimits.delete(key);
  for (const [key, expiry] of consumedNonces) if (expiry <= now) consumedNonces.delete(key);
  for (const [key, expiry] of webhookSeen) if (expiry <= now) webhookSeen.delete(key);
}, 60 * 60 * 1000);
cleanupTimer.unref?.();

// ----------------------------------------------------------------------------
// 11. Initialization & Graceful Shutdown
// ----------------------------------------------------------------------------
async function initializeFirebase() {
  try {
    if (getApps().length === 0) {
      initializeApp({ credential: cert(FIREBASE_SERVICE_ACCOUNT_PATH) });
    }
    getMessaging();
    firebaseReady = true;
    firebaseError = null;
    console.log("[FCM] Firebase Admin initialized.");
  } catch (err) {
    firebaseReady = false;
    firebaseError = err.message;
    console.error(`[FCM] Initialization failed (FCM pushes will be disabled): ${err.message}`);
  }
}

await initializeFirebase();

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[STARTUP] HexaSynq Gateway listening on port ${PORT}`);
  console.log(`[CONFIG] Evolution=${safeUrl(EVOLUTION_SERVER_URL)} | Public=${safeUrl(GATEWAY_PUBLIC_URL)} | AI=${AI_PROVIDER} | Model=${MODEL_NAME} | MaxActiveAI=${MAX_ACTIVE_AI} | Queue=${MAX_QUEUE_SIZE}`);
  console.log(`[PERSISTENCE] File=${MAPPINGS_FILE}`);
  if (firebaseError) console.error(`[STARTUP] FCM degraded: ${firebaseError}`);
});

async function shutdown(signal) {
  console.log(`[SHUTDOWN] Received ${signal}; closing server gracefully.`);
  clearInterval(cleanupTimer);
  if (saveTimer) clearTimeout(saveTimer);
  
  if (mappingsDirty) {
    try { writeMappings(); } 
    catch (err) { console.error(`[PERSISTENCE] Final save failed: ${err.message}`); }
  }
  
  server.close(() => {
    console.log("[SHUTDOWN] Server closed. Exiting.");
    process.exit(0);
  });
  
  // Force exit if graceful shutdown hangs
  setTimeout(() => {
    console.error("[SHUTDOWN] Force exit after timeout.");
    process.exit(1);
  }, 10000).unref();
}

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

export default app;s

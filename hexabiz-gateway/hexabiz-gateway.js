import express from "express";
import helmet from "helmet";
import fetch from "node-fetch";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import fsSync from "node:fs";
import path from "node:path";
import { initializeApp, cert, getApps } from "firebase-admin/app";
import { getMessaging } from "firebase-admin/messaging";

// Auto-load local .env file if present so environment variables are populated
for (const file of [".env", path.join(process.cwd(), ".env")]) {
  try {
    if (fsSync.existsSync(file)) {
      const content = fsSync.readFileSync(file, "utf8");
      for (const line of content.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#")) continue;
        const idx = trimmed.indexOf("=");
        if (idx > 0) {
          const key = trimmed.slice(0, idx).trim();
          let val = trimmed.slice(idx + 1).trim();

          if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
            val = val.slice(1, -1);
          }
          if (!process.env[key]) process.env[key] = val;
        }
      }
    }
  } catch { /* ignore */ }
}

// HexaSynq Gateway — Node.js 20+, ESM
// Required dependencies: express, helmet, node-fetch, firebase-admin

const PORT = Number.parseInt(process.env.PORT || "3000", 10);
const HOST = process.env.HOST || "0.0.0.0";
const EVOLUTION_SERVER_URL = (process.env.EVOLUTION_SERVER_URL || "http://whatsapp_api:8080").replace(/\/+$/, "");
const EVOLUTION_GLOBAL_KEY = process.env.EVOLUTION_GLOBAL_KEY || process.env.EVOLUTION_API_KEY || "";
const OLLAMA_BASE_URL = (process.env.OLLAMA_BASE_URL || "http://ollama:11434").replace(/\/+$/, "");
const OLLAMA_DEFAULT_MODEL = process.env.OLLAMA_DEFAULT_MODEL || "synq:latest";
const POLLINATIONS_BASE_URL = (process.env.POLLINATIONS_BASE_URL || "https://gen.pollinations.ai").replace(/\/+$/, "");
const POLLINATIONS_API_KEY = process.env.POLLINATIONS_API_KEY || "";
const POLLINATIONS_MODEL = process.env.POLLINATIONS_MODEL || "openai/gpt-5.4-nano";
// Media-specific Pollinations model names (configurable without code changes)
const POLLINATIONS_AUDIO_MODEL = process.env.POLLINATIONS_AUDIO_MODEL || "microsoft/mai-transcribe-2";
// Maximum decoded media bytes accepted by the media endpoints.
const MAX_MEDIA_DECODED_BYTES = positiveInt(process.env.MAX_MEDIA_DECODED_BYTES, 8 * 1_048_576);
// Per-IP rate limit for media endpoints (requests per window).
const MEDIA_RATE_LIMIT_WINDOW_MS = positiveInt(process.env.MEDIA_RATE_LIMIT_WINDOW_MS, 60_000);
const MEDIA_RATE_LIMIT_MAX = positiveInt(process.env.MEDIA_RATE_LIMIT_MAX, 20);
const ENROLLMENT_KEY = process.env.ENROLLMENT_KEY || process.env.APP_ENROLLMENT_KEY || "";
const WEBHOOK_SECRET =
  process.env.WEBHOOK_SECRET ||
  (EVOLUTION_GLOBAL_KEY
    ? crypto
        .createHmac("sha256", EVOLUTION_GLOBAL_KEY)
        .update("webhook:evolution")
        .digest("hex")
    : "");
const EVOLUTION_WEBSOCKET_EVENTS = [
  "MESSAGES_SET", "MESSAGES_UPSERT", "MESSAGES_UPDATE", "MESSAGES_DELETE",
  "SEND_MESSAGE", "CONTACTS_SET", "CONTACTS_UPSERT", "CONTACTS_UPDATE",
  "CHATS_SET", "CHATS_UPSERT", "CHATS_UPDATE", "CHATS_DELETE",
  "PRESENCE_UPDATE", "CONNECTION_UPDATE", "QRCODE_UPDATED",
];
const PLAY_INTEGRITY_REQUIRED = process.env.PLAY_INTEGRITY_REQUIRED === "true";
const PLAY_INTEGRITY_VERIFIER_URL = process.env.PLAY_INTEGRITY_VERIFIER_URL || "";
const PLAY_INTEGRITY_VERIFIER_KEY = process.env.PLAY_INTEGRITY_VERIFIER_KEY || "";
const SERVICE_ACCOUNT_PATH = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || "/run/secrets/serviceAccountKey.json";
const DATA_DIR = process.env.DATA_DIR || "/data";
const MAPPINGS_FILE_PATH = process.env.MAPPINGS_FILE_PATH || path.join(DATA_DIR, "gateway_mappings.json");
const REQUEST_TIMEOUT_MS = positiveInt(process.env.REQUEST_TIMEOUT_MS, 15_000);
const AI_TIMEOUT_MS = positiveInt(process.env.AI_TIMEOUT_MS, 45_000);
const MAX_BODY_BYTES = positiveInt(process.env.MAX_BODY_BYTES, 12 * 1_048_576);
const MAX_CLOCK_SKEW_MS = positiveInt(process.env.MAX_CLOCK_SKEW_MS, 5 * 60_000);
const NONCE_TTL_MS = positiveInt(process.env.NONCE_TTL_MS, 10 * 60_000);
const MAX_NONCES = positiveInt(process.env.MAX_NONCES, 20_000);
const MAX_AI_CONCURRENCY = positiveInt(process.env.MAX_AI_CONCURRENCY, 4);
const MAX_AI_QUEUE = positiveInt(process.env.MAX_AI_QUEUE, 30);
const MAX_PROMPT_CHARS = positiveInt(process.env.MAX_PROMPT_CHARS, 20_000);

// AI Provider Configuration: supports POLLINATIONS (or POLLINATION) and HEXABIZ (or OLLAMA)
const AI_PROVIDER_RAW = (process.env.AI_PROVIDER || "HEXABIZ").trim().toUpperCase();
const AI_PROVIDER = (AI_PROVIDER_RAW === "POLLINATIONS" || AI_PROVIDER_RAW === "POLLINATION")
  ? "POLLINATIONS"
  : "HEXABIZ";
const POLLINATIONS_MAX_COMPLETION_TOKENS = positiveInt(
  process.env.POLLINATIONS_MAX_COMPLETION_TOKENS,
  200
);

// Supabase Storage Configuration (Locally hosted Supabase Storage WA-Copilot)
const SUPABASE_URL = (process.env.SUPABASE_URL || "https://datacore-qw8cvyeyjo.hexabizsolutions.cloud").replace(/\/+$/, "");
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY || "";
const SUPABASE_BUCKET = process.env.SUPABASE_BUCKET || "WA-Copilot";

function getSupabaseSubfolder(mediaType, mimeType = "") {
  const normType = String(mediaType || "").toLowerCase();
  const normMime = String(mimeType || "").toLowerCase();
  if (normType === "image" || normMime.startsWith("image/")) return "image";
  if (normType === "voice" || normType === "audio" || normMime.startsWith("audio/")) return "voice-notes";
  if (normType === "video" || normMime.startsWith("video/")) return "videos";
  return "docs";
}

function mimeTypeToExtension(mimeType, mediaType) {
  const m = String(mimeType || "").toLowerCase();
  if (m.includes("jpeg") || m.includes("jpg")) return "jpg";
  if (m.includes("png")) return "png";
  if (m.includes("webp")) return "webp";
  if (m.includes("ogg") || m.includes("opus")) return "ogg";
  if (m.includes("mpeg") || m.includes("mp3")) return "mp3";
  if (m.includes("mp4") || m.includes("m4a")) return "mp4";
  if (m.includes("wav")) return "wav";
  if (m.includes("pdf")) return "pdf";
  if (m.includes("doc")) return "docx";
  if (m.includes("txt")) return "txt";
  const type = String(mediaType || "").toLowerCase();
  if (type === "image") return "jpg";
  if (type === "voice" || type === "audio") return "ogg";
  if (type === "video") return "mp4";
  return "bin";
}

async function uploadToSupabaseStorage(phoneNumber, mediaType, mimeType, fileBuffer, customFileName = "") {
  if (!SUPABASE_SERVICE_ROLE_KEY) {
    debugLog("SUPABASE", "Warning: SUPABASE_SERVICE_ROLE_KEY is not set; skipping upload.");
    return { uploaded: false, path: null, signedUrl: null };
  }

  const normPhone = normalizePhone(phoneNumber) || "unassigned_owner";
  const subfolder = getSupabaseSubfolder(mediaType, mimeType);
  const ext = mimeTypeToExtension(mimeType, mediaType);
  const safeName = customFileName
    ? String(customFileName).replace(/[^a-zA-Z0-9_.-]/g, "_")
    : `media_${Date.now()}_${crypto.randomBytes(4).toString("hex")}.${ext}`;

  const objectPath = `${normPhone}/${subfolder}/${safeName}`;

  try {
    const uploadUrl = `${SUPABASE_URL}/storage/v1/object/${SUPABASE_BUCKET}/${objectPath}`;
    const uploadRes = await fetch(uploadUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "content-type": mimeType || "application/octet-stream",
        "x-upsert": "true",
      },
      body: fileBuffer,
    });

    if (!uploadRes.ok) {
      debugLog("SUPABASE_UPLOAD_FAIL", `Upload HTTP ${uploadRes.status}`);
      return { uploaded: false, path: objectPath, signedUrl: null };
    }

    // Generate short-lived signed URL (300 seconds)
    const signUrl = `${SUPABASE_URL}/storage/v1/object/sign/${SUPABASE_BUCKET}/${objectPath}`;
    const signRes = await fetch(signUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ expiresIn: 300 }),
    });

    let signedUrl = null;
    if (signRes.ok) {
      const signData = await signRes.json().catch(() => ({}));
      const rawSigned = signData?.signedURL || signData?.signedUrl || signData?.url;
      if (rawSigned) {
        signedUrl = rawSigned.startsWith("http") ? rawSigned : `${SUPABASE_URL}${rawSigned}`;
      }
    }

    // Metadata-only log: Never log phone numbers, keys, content, or signed URL
    debugLog("SUPABASE_SUCCESS", `Uploaded object to bucket subfolder=${subfolder}`);
    return { uploaded: true, path: objectPath, signedUrl };
  } catch (error) {
    debugLog("SUPABASE_ERROR", "Supabase storage error", { error: error?.message });
    return { uploaded: false, path: objectPath, signedUrl: null };
  }
}

function parseMcpJsonResponse(bodyText, contentType = "") {
  if (!bodyText.trim()) return null;
  if (contentType.includes("application/json")) {
    try { return JSON.parse(bodyText); } catch { return null; }
  }
  const messages = bodyText
    .split(/\r?\n/)
    .filter((line) => line.startsWith("data:"))
    .map((line) => line.slice(5).trim())
    .filter(Boolean);
  for (const message of messages.reverse()) {
    try { return JSON.parse(message); } catch { /* try next SSE data block */ }
  }
  try { return JSON.parse(bodyText); } catch { return null; }
}

async function transcribeAudioFromUrl(audioUrl, language = "") {
  if (!POLLINATIONS_API_KEY) throw new Error("Pollinations API key is not configured");
  const endpoint = `${POLLINATIONS_BASE_URL}/mcp/pollinations`;
  const headers = {
    authorization: `Bearer ${POLLINATIONS_API_KEY}`,
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
  };
  const postMcp = async (payload, sessionId = "") => {
    const requestHeaders = { ...headers };
    if (payload.method !== "initialize") requestHeaders["mcp-protocol-version"] = "2025-03-26";
    if (sessionId) requestHeaders["mcp-session-id"] = sessionId;
    const response = await fetch(endpoint, {
      method: "POST",
      headers: requestHeaders,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(AI_TIMEOUT_MS),
    });
    const responseText = await response.text();
    if (!response.ok) throw new Error(`Pollinations audio URL transcription returned HTTP ${response.status}`);
    return {
      data: parseMcpJsonResponse(responseText, response.headers.get("content-type") || ""),
      sessionId: response.headers.get("mcp-session-id") || sessionId,
    };
  };

  const initialized = await postMcp({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-03-26",
      capabilities: {},
      clientInfo: { name: "hexasynq-gateway", version: "1.0.0" },
    },
  });
  if (initialized.data?.error) throw new Error("Pollinations MCP initialization failed");
  const sessionId = initialized.sessionId;
  await postMcp({ jsonrpc: "2.0", method: "notifications/initialized" }, sessionId);

  const listed = await postMcp({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} }, sessionId);
  const tool = listed.data?.result?.tools?.find((item) => item.name === "transcribeAudio");
  const properties = tool?.inputSchema?.properties || {};
  const audioUrlField = ["audioUrl", "audio_url", "url"].find((key) => properties[key]);
  if (!audioUrlField) throw new Error("Pollinations audio URL transcription tool is unavailable");
  const args = { [audioUrlField]: audioUrl };
  if (language && properties.language) args.language = language;
  if (properties.model) args.model = POLLINATIONS_AUDIO_MODEL;
  const called = await postMcp({
    jsonrpc: "2.0",
    id: 3,
    method: "tools/call",
    params: { name: "transcribeAudio", arguments: args },
  }, sessionId);
  const result = called.data?.result;
  if (!result || result.isError || called.data?.error) {
    throw new Error("Pollinations failed to transcribe the stored audio URL");
  }
  const structured = result.structuredContent || {};
  const transcript = structured.transcript || structured.text || structured.content ||
    result.content?.find((item) => item.type === "text")?.text;
  if (typeof transcript !== "string" || !transcript.trim()) {
    throw new Error("Pollinations returned an empty transcription for the stored audio URL");
  }
  return transcript.trim();
}

// Debug Logging Configuration
const ENABLE_LOGS_DEBUG = process.env.ENABLE_LOGS_DEBUG === "true";

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

/**
 * Safely stringify data for logging, truncating if it exceeds a reasonable length
 * to prevent console flooding (e.g., from large base64 payloads).
 */
function safeStringify(data, maxLength = 8000) {
  try {
    const str = JSON.stringify(data, null, 2);
    if (str.length > maxLength) {
      return str.slice(0, maxLength) + "\n... [TRUNCATED FOR LOGGING]";
    }
    return str;
  } catch (e) {
    return `[Error stringifying data: ${e.message}]`;
  }
}

/**
 * Debug logger that only outputs when ENABLE_LOGS_DEBUG is true.
 */
function debugLog(tag, message, data = null) {
  if (!ENABLE_LOGS_DEBUG) return;
  const timestamp = new Date().toISOString();
  let output = `[DEBUG][${timestamp}][${tag}] ${message}`;
  if (data !== null) {
    output += `\n${safeStringify(data)}`;
  }
  process.stderr.write(output + "\n");
}

function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function jsonError(res, status, error, details) {
  const payload = { ok: false, error };
  if (details) payload.details = details;
  debugLog("HTTP_ERROR", `Returning error ${status}: ${error}`, payload);
  return res.status(status).json(payload);
}

function normalizePhone(value) {
  const digits = String(value || "").replace(/\D/g, "");
  return /^\d{8,15}$/.test(digits) ? digits : null;
}

function normalizeDeviceId(value) {
  const id = String(value || "").trim();
  return /^[A-Za-z0-9_-]{8,128}$/.test(id) ? id : null;
}

function instanceNameForPhone(phone, deviceId) {
  if (deviceId) {
    return `${deviceId}_${phone}`;
  }
  return `dev_${phone}`;
}

function deriveDeviceSecret(deviceId) {
  if (!EVOLUTION_GLOBAL_KEY) throw new Error("EVOLUTION_GLOBAL_KEY is not configured");
  return crypto.createHmac("sha256", EVOLUTION_GLOBAL_KEY).update(`device:${deviceId}`).digest("hex");
}

function timingSafeHexEqual(a, b) {
  if (!/^[a-f0-9]+$/i.test(String(a)) || !/^[a-f0-9]+$/i.test(String(b))) return false;
  return safeEqual(String(a).toLowerCase(), String(b).toLowerCase());
}

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", process.env.TRUST_PROXY === "true" ? 1 : false);
app.use(helmet({ contentSecurityPolicy: false }));

// Capture exact raw JSON bytes for HMAC verification. Do not re-serialize req.body for signatures.
app.use(express.json({
  limit: MAX_BODY_BYTES,
  verify(req, _res, buffer) {
    req.rawBody = buffer.toString("utf8");
  },
}));

// ============================================================================
// GLOBAL DEBUG LOGGING MIDDLEWARE
// ============================================================================
app.use((req, res, next) => {
  const headersForLog = { ...req.headers };
  for (const name of ["authorization", "x-enrollment-key", "x-signature", "x-api-key"]) {
    if (headersForLog[name]) headersForLog[name] = "[redacted]";
  }
  const isMediaRequest = req.originalUrl.startsWith("/api/media/") || req.originalUrl.startsWith("/v1/audio/transcriptions");
  const bodyForLog = isMediaRequest && req.body && typeof req.body === "object"
    ? Object.fromEntries(Object.entries(req.body).map(([key, value]) =>
      /base64|^audio$/i.test(key) && typeof value === "string"
        ? [key, `[redacted ${Buffer.byteLength(value, "utf8")} encoded bytes]`]
        : [key, value]
    ))
    : req.body;
  debugLog("HTTP_IN", `${req.method} ${req.originalUrl}`, {
    headers: headersForLog,
    body: bodyForLog,
    rawBodyPreview: isMediaRequest ? "[media request body omitted]" : req.rawBody ? req.rawBody.slice(0, 500) + (req.rawBody.length > 500 ? "...[truncated]" : "") : undefined
  });

  // Intercept res.json to log outgoing responses
  const originalJson = res.json;
  res.json = function(data) {
    debugLog("HTTP_OUT", `${req.method} ${req.originalUrl} [${res.statusCode}]`, { body: data });
    return originalJson.call(this, data);
  };

  // Intercept res.send to log outgoing responses (for non-JSON sends)
  const originalSend = res.send;
  res.send = function(data) {
    const logData = typeof data === 'string' && data.length > 1000 
      ? data.slice(0, 1000) + "...[truncated]" 
      : data;
    debugLog("HTTP_OUT", `${req.method} ${req.originalUrl} [${res.statusCode}]`, { body: logData });
    return originalSend.call(this, data);
  };

  next();
});

app.use((error, _req, res, next) => {
  if (error instanceof SyntaxError && "body" in error) return jsonError(res, 400, "Invalid JSON body");
  if (error?.type === "entity.too.large") return jsonError(res, 413, "Request body too large");
  return next(error);
});

let firebaseMessaging = null;
let firebaseStatus = "not_initialized";
try {
  if (getApps().length > 0) {
    firebaseMessaging = getMessaging();
    firebaseStatus = "initialized_existing_app";
  } else {
    debugLog("FIREBASE", "Initializing Firebase Admin from service account", { path: SERVICE_ACCOUNT_PATH });
    const serviceAccount = JSON.parse(await fs.readFile(SERVICE_ACCOUNT_PATH, "utf8"));
    initializeApp({ credential: cert(serviceAccount) });
    firebaseMessaging = getMessaging();
    firebaseStatus = "initialized";
  }
} catch (error) {
  firebaseStatus = `unavailable: ${error instanceof Error ? error.message : "initialization failed"}`;
  debugLog("FIREBASE_ERROR", "Firebase initialization failed", { error: error instanceof Error ? error.message : "unknown" });
}

const emptyStore = () => ({ version: 1, devices: {}, instances: {} });
let store = emptyStore();
let storeReady = false;
let storeWriteChain = Promise.resolve();
const provisionLocks = new Map();
const nonceCache = new Map();
const webhookDedupeCache = new Map();
const webhookInFlight = new Set();
let aiActive = 0;
const aiQueue = [];

// Per-IP sliding-window rate limit map for media endpoints.
const mediaRateLimitMap = new Map();

function checkMediaRateLimit(ip) {
  const now = Date.now();
  let entry = mediaRateLimitMap.get(ip);
  if (!entry || (now - entry.windowStart) >= MEDIA_RATE_LIMIT_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
  }
  entry.count += 1;
  mediaRateLimitMap.set(ip, entry);
  if (mediaRateLimitMap.size > 10_000) {
    for (const [key, value] of mediaRateLimitMap) {
      if ((now - value.windowStart) >= MEDIA_RATE_LIMIT_WINDOW_MS) mediaRateLimitMap.delete(key);
    }
  }
  return entry.count <= MEDIA_RATE_LIMIT_MAX;
}

async function loadStore() {
  debugLog("STORE", "Loading store from disk", { path: MAPPINGS_FILE_PATH });
  await fs.mkdir(path.dirname(MAPPINGS_FILE_PATH), { recursive: true });
  try {
    const raw = await fs.readFile(MAPPINGS_FILE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || typeof parsed.devices !== "object" || typeof parsed.instances !== "object") {
      throw new Error("Mapping file has an invalid shape");
    }
    store = { version: 1, devices: parsed.devices || {}, instances: parsed.instances || {} };
    debugLog("STORE", "Store loaded successfully", { devicesCount: Object.keys(store.devices).length, instancesCount: Object.keys(store.instances).length });
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    debugLog("STORE", "Store file not found, initializing empty store");
    store = emptyStore();
    await persistStore();
  }
  
  const instances = {};
  for (const [deviceId, record] of Object.entries(store.devices)) {
    if (!record || typeof record !== "object" || typeof record.instanceName !== "string" || !record.instanceName) {
      delete store.devices[deviceId];
      continue;
    }
    const existing = instances[record.instanceName];
    if (existing && existing !== deviceId) {
      delete store.devices[existing];
      delete store.devices[deviceId];
      delete instances[record.instanceName];
      continue;
    }
    instances[record.instanceName] = deviceId;
  }
  store.instances = instances;
  storeReady = true;
  await persistStore();
}

async function persistStore() {
  debugLog("STORE", "Persisting store to disk", { path: MAPPINGS_FILE_PATH, devicesCount: Object.keys(store.devices).length });
  const snapshot = JSON.stringify(store, null, 2);
  const write = storeWriteChain.catch(() => undefined).then(async () => {
    await fs.mkdir(path.dirname(MAPPINGS_FILE_PATH), { recursive: true });
    const tempPath = `${MAPPINGS_FILE_PATH}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      await fs.writeFile(tempPath, snapshot, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await fs.rename(tempPath, MAPPINGS_FILE_PATH);
      debugLog("STORE", "Store persisted successfully");
    } catch (error) {
      try { await fs.unlink(tempPath); } catch { /* temp file may not exist */ }
      debugLog("STORE_ERROR", "Failed to persist store", { error: error instanceof Error ? error.message : "unknown" });
      throw error;
    }
  });
  storeWriteChain = write;
  return write;
}

function cleanExpired(cache, ttlMs) {
  const now = Date.now();
  for (const [key, time] of cache) if (now - time > ttlMs) cache.delete(key);
}

function rememberOnce(cache, key, ttlMs, maxSize) {
  cleanExpired(cache, ttlMs);
  if (cache.has(key)) return false;
  if (cache.size >= maxSize) {
    const oldest = cache.keys().next().value;
    if (oldest !== undefined) cache.delete(oldest);
  }
  cache.set(key, Date.now());
  return true;
}

function getDeviceRecord(deviceId) {
  const record = store.devices[deviceId];
  return record && typeof record === "object" ? record : null;
}

function requireEnrollment(req, res, next) {
  if (!ENROLLMENT_KEY) return jsonError(res, 503, "Enrollment is not configured");
  const supplied = req.get("x-enrollment-key") || "";
  if (!safeEqual(supplied, ENROLLMENT_KEY)) return jsonError(res, 401, "Invalid enrollment key");
  return next();
}

function verifyDeviceRequest(req, res, next) {
  if (!EVOLUTION_GLOBAL_KEY) return jsonError(res, 503, "Device authentication is not configured");
  const deviceId = normalizeDeviceId(req.get("x-device-id"));
  const timestampText = String(req.get("x-timestamp") || "");
  const nonce = String(req.get("x-nonce") || "");
  const signature = String(req.get("x-signature") || "");
  
  if (!deviceId || !/^\d{10,16}$/.test(timestampText) || !/^[A-Za-z0-9_-]{12,128}$/.test(nonce) || !/^[a-f0-9]{64}$/i.test(signature)) {
    return jsonError(res, 401, "Missing or invalid device authentication headers");
  }
  
  const timestamp = Number(timestampText);
  const timestampMs = timestamp < 1e12 ? timestamp * 1000 : timestamp;
  if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > MAX_CLOCK_SKEW_MS) {
    return jsonError(res, 401, "Request timestamp expired");
  }
  
  const nonceKey = `${deviceId}:${nonce}`;
  if (nonceCache.has(nonceKey)) {
    cleanExpired(nonceCache, NONCE_TTL_MS);
    if (nonceCache.has(nonceKey)) return jsonError(res, 401, "Request nonce already used");
  }
  
  let secret;
  try { secret = deriveDeviceSecret(deviceId); } catch { return jsonError(res, 503, "Device authentication is not configured"); }
  
  const rawBody = typeof req.rawBody === "string" ? req.rawBody : "";
  const expected = crypto.createHmac("sha256", secret).update(`${timestampText}.${nonce}.${rawBody}`).digest("hex");
  if (!timingSafeHexEqual(signature, expected)) return jsonError(res, 401, "Invalid request signature");
  
  if (!rememberOnce(nonceCache, nonceKey, NONCE_TTL_MS, MAX_NONCES)) return jsonError(res, 401, "Request nonce already used");
  
  req.deviceId = deviceId;
  req.deviceRecord = getDeviceRecord(deviceId);
  return next();
}

async function evolutionRequest(route, { method = "GET", body, timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const headers = { accept: "application/json" };
  if (EVOLUTION_GLOBAL_KEY) headers.apikey = EVOLUTION_GLOBAL_KEY;
  if (body !== undefined) headers["content-type"] = "application/json";
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    debugLog("EVOLUTION_REQ", `Calling ${method} ${route}`, { url: `${EVOLUTION_SERVER_URL}${route}`, hasBody: !!body, body });
    const response = await fetch(`${EVOLUTION_SERVER_URL}${route}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text.slice(0, 1000) }; }
    
    debugLog("EVOLUTION_RES", `Response from ${method} ${route}`, { status: response.status, data });
    
    if (!response.ok) {
      const error = new Error(`Evolution API returned HTTP ${response.status}`);
      error.status = response.status;
      error.data = data;
      throw error;
    }
    return data;
  } finally {
    clearTimeout(timeout);
  }
}

async function deleteEvolutionInstance(instanceName) {
  return evolutionRequest(`/instance/delete/${encodeURIComponent(instanceName)}`, { method: "DELETE" });
}

async function logoutEvolutionInstance(instanceName) {
  try {
    return await evolutionRequest(`/instance/logout/${encodeURIComponent(instanceName)}`, { method: "DELETE" });
  } catch (error) {
    process.stderr.write(`[LOGOUT] Evolution logout failed for ${instanceName}: ${error?.message}\n`);
    return null;
  }
}

async function configureEvolutionWebsocket(instanceName) {
  await evolutionRequest(`/websocket/set/${encodeURIComponent(instanceName)}`, {
    method: "POST",
    body: { websocket: { enabled: true, events: EVOLUTION_WEBSOCKET_EVENTS } },
  });
}

async function verifyPlayIntegrity(req, deviceId) {
  if (!PLAY_INTEGRITY_REQUIRED) return true;
  const token = String(req.get("x-play-integrity-token") || "");
  if (!token || !PLAY_INTEGRITY_VERIFIER_URL || !PLAY_INTEGRITY_VERIFIER_KEY) return false;
  
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    debugLog("PLAY_INTEGRITY_REQ", "Verifying Play Integrity", { deviceId, verifierUrl: PLAY_INTEGRITY_VERIFIER_URL });
    const response = await fetch(PLAY_INTEGRITY_VERIFIER_URL, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${PLAY_INTEGRITY_VERIFIER_KEY}` },
      body: JSON.stringify({ token, deviceId, requestPackageName: process.env.ANDROID_PACKAGE_NAME || "" }),
      signal: controller.signal,
    });
    
    const result = await response.json().catch(() => ({}));
    debugLog("PLAY_INTEGRITY_RES", "Play Integrity verification response", { status: response.status, valid: result?.valid });
    
    if (!response.ok) return false;
    return result?.valid === true && result?.deviceId === deviceId;
  } catch (error) {
    debugLog("PLAY_INTEGRITY_ERROR", "Play Integrity verification failed", { error: error instanceof Error ? error.message : "unknown" });
    return false;
  } finally { 
    clearTimeout(timeout); 
  }
}

function withProvisionLock(key, task) {
  const previous = provisionLocks.get(key) || Promise.resolve();
  const current = previous.catch(() => undefined).then(task);
  provisionLocks.set(key, current);
  return current.finally(() => { if (provisionLocks.get(key) === current) provisionLocks.delete(key); });
}

function truncateUtf8(value, maxBytes) {
  let output = String(value ?? "");
  while (Buffer.byteLength(output, "utf8") > maxBytes) {
    output = output.slice(0, Math.max(0, output.length - Math.max(1, Math.ceil((Buffer.byteLength(output, "utf8") - maxBytes) / 3))));
  }
  return output;
}

async function sendPush(deviceId, eventType, payload) {
  const record = getDeviceRecord(deviceId);
  if (!record?.fcmToken) return { sent: false, reason: "no_fcm_token" };
  if (!firebaseMessaging) return { sent: false, reason: "firebase_unavailable" };

  const data = {};
  for (const [key, value] of Object.entries({ eventType, ...payload })) {
    if (value === undefined || value === null) continue;
    data[key] = typeof value === "string" ? value : JSON.stringify(value);
  }
  
  if (typeof data.messageText === "string") data.messageText = truncateUtf8(data.messageText, 1_500);
  let encoded = JSON.stringify(data);
  while (Buffer.byteLength(encoded, "utf8") > 3_500) {
    const candidates = Object.keys(data)
      .filter((key) => !["eventType", "instanceName", "messageId", "chatId", "messageText"].includes(key))
      .sort((a, b) => Buffer.byteLength(data[b], "utf8") - Buffer.byteLength(data[a], "utf8"));
    if (candidates.length) {
      const key = candidates[0];
      data[key] = truncateUtf8(data[key], Math.max(16, Math.floor(Buffer.byteLength(data[key], "utf8") * 0.65)));
    } else if (typeof data.messageText === "string" && data.messageText.length > 0) {
      data.messageText = truncateUtf8(data.messageText, Math.max(0, Buffer.byteLength(data.messageText, "utf8") - 256));
    } else {
      return { sent: false, reason: "payload_too_large" };
    }
    encoded = JSON.stringify(data);
  }
  
  try {
    debugLog("FCM_SEND", `Sending push to device ${deviceId}`, { 
      eventType, 
      fcmTokenPreview: record.fcmToken ? record.fcmToken.substring(0, 15) + "..." : "none", 
      data 
    });
    await firebaseMessaging.send({
      token: record.fcmToken,
      data,
      android: { priority: "high", ttl: 60 * 60 * 1000 },
    });
    return { sent: true };
  } catch (error) {
    const code = error?.code || "unknown";
    debugLog("FCM_ERROR", `FCM send failed for ${deviceId}`, { code, message: error instanceof Error ? error.message : "unknown" });
    if (code === "messaging/registration-token-not-registered" || code === "messaging/invalid-registration-token") {
      const previousToken = record.fcmToken;
      delete record.fcmToken;
      try { await persistStore(); } catch { record.fcmToken = previousToken; }
    }
    return { sent: false, reason: code };
  }
}

function runAiTask(task) {
  return new Promise((resolve, reject) => {
    aiQueue.push({ task, resolve, reject });
    pumpAiQueue();
  });
}

function pumpAiQueue() {
  while (aiActive < MAX_AI_CONCURRENCY && aiQueue.length > 0) {
    const entry = aiQueue.shift();
    aiActive += 1;
    Promise.resolve().then(entry.task).then(entry.resolve, entry.reject).finally(() => {
      aiActive -= 1;
      pumpAiQueue();
    });
  }
}

function chatMessagesFromBody(body) {
  if (Array.isArray(body?.messages)) {
    if (body.messages.length === 0) return null;
    const messages = [];
    for (const item of body.messages) {
      if (!item || typeof item !== "object" || !["system", "user", "assistant"].includes(item.role) || typeof item.content !== "string" || !item.content.trim()) {
        return null;
      }
      messages.push({ role: item.role, content: item.content });
    }
    return messages;
  }
  if (typeof body?.prompt === "string" && body.prompt.trim()) {
    return [{ role: "user", content: body.prompt }];
  }
  return null;
}

async function ollamaChat(messages) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const ollamaMessages = messages.filter((m) => m.role !== "system");
    debugLog("OLLAMA_REQ", `Calling ${OLLAMA_BASE_URL}/api/chat`, { model: OLLAMA_DEFAULT_MODEL, messages: ollamaMessages });
    
    const response = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: OLLAMA_DEFAULT_MODEL, messages: ollamaMessages, stream: false }),
      signal: controller.signal,
    });
    
    const data = await response.json().catch(() => ({}));
    debugLog("OLLAMA_RES", `Response from Ollama`, { status: response.status, data });
    
    if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
    const content = data?.message?.content;
    if (typeof content !== "string" || !content.trim()) throw new Error("Ollama returned an empty response");
    return { content, model: data?.model || OLLAMA_DEFAULT_MODEL, provider: "ollama" };
  } finally { 
    clearTimeout(timeout); 
  }
}

async function pollinationsChat(messages) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);

  try {
    const headers = { "content-type": "application/json", accept: "application/json" };
    if (POLLINATIONS_API_KEY) headers.authorization = `Bearer ${POLLINATIONS_API_KEY}`;

    const requestBody = {
      model: POLLINATIONS_MODEL,
      messages,
      max_completion_tokens: POLLINATIONS_MAX_COMPLETION_TOKENS,
      stream: false,
      safe: false,
      reasoning_effort: "low",
      temperature: 0,
    };

    debugLog("POLLINATIONS_REQ", `Calling ${POLLINATIONS_BASE_URL}/v1/chat/completions`, {
      model: POLLINATIONS_MODEL,
      messageCount: messages.length,
      messageShapes: messages.map((message) => ({
        role: message.role,
        contentType: Array.isArray(message.content) ? "multimodal" : "text",
        partTypes: Array.isArray(message.content) ? message.content.map((part) => part.type) : undefined,
      })),
      max_completion_tokens: POLLINATIONS_MAX_COMPLETION_TOKENS,
    });

    const response = await fetch(`${POLLINATIONS_BASE_URL}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
      signal: controller.signal,
    });

    const data = await response.json().catch(() => ({}));
    debugLog("POLLINATIONS_RES", `Response from Pollinations Chat`, { status: response.status, data });

    if (!response.ok) {
      const error = new Error(`Pollinations returned HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }

    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) {
      throw new Error("Pollinations returned an empty response");
    }

    return { content, model: data?.model || POLLINATIONS_MODEL, provider: "pollinations" };
  } finally {
    clearTimeout(timeout);
  }
}

async function generateChatReply(messages) {
  const primaryProvider = AI_PROVIDER === "POLLINATIONS" ? "pollinations" : "ollama";
  const fallbackProvider = AI_PROVIDER === "POLLINATIONS" ? "ollama" : "pollinations";
  const providers = { ollama: ollamaChat, pollinations: pollinationsChat };

  try {
    const result = await providers[primaryProvider](messages);
    return { ...result, fallbackUsed: false };
  } catch (primaryError) {
    process.stderr.write(`[AI:FALLBACK] Primary provider ${primaryProvider} failed. Attempting ${fallbackProvider}. Reason: ${primaryError?.message || "unknown error"}\n`);
    debugLog("AI_FALLBACK", `Primary provider ${primaryProvider} failed`, { error: primaryError?.message });

    try {
      const result = await providers[fallbackProvider](messages);
      return { ...result, fallbackUsed: true };
    } catch (fallbackError) {
      process.stderr.write(`[AI:ERROR] Both providers failed. Primary=${primaryProvider}, Fallback=${fallbackProvider}\n`);
      debugLog("AI_ERROR", `Both providers failed`, { primary: primaryError?.message, fallback: fallbackError?.message });

      const error = new Error("AI providers are currently unavailable");
      error.cause = { primary: primaryError?.message || "unknown error", fallback: fallbackError?.message || "unknown error" };
      throw error;
    }
  }
}

// ============================================================================
// Media endpoint helpers
// ============================================================================

function requireMediaRateLimit(req, res, next) {
  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  if (!checkMediaRateLimit(ip)) {
    return jsonError(res, 429, "Media rate limit exceeded; retry after a short wait");
  }
  return next();
}

function decodeBase64Field(res, value, fieldName) {
  if (typeof value !== "string" || value.length === 0) {
    jsonError(res, 400, `${fieldName} must be a non-empty base64 string`);
    return null;
  }
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    jsonError(res, 400, `${fieldName} contains invalid base64 characters`);
    return null;
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0) {
    jsonError(res, 400, `${fieldName} decoded to zero bytes`);
    return null;
  }
  if (decoded.length > MAX_MEDIA_DECODED_BYTES) {
    jsonError(res, 413, `${fieldName} exceeds the maximum allowed size of ${MAX_MEDIA_DECODED_BYTES} bytes decoded`);
    return null;
  }
  return decoded;
}

// ============================================================================
// POST /api/media/transcribe & /v1/audio/transcriptions
// ============================================================================

app.post(
  ["/api/media/transcribe", "/v1/audio/transcriptions"],
  requireEnrollment,
  requireMediaRateLimit,
  async (req, res) => {
    const mimeType = typeof req.body?.mimeType === "string" ? req.body.mimeType.trim().toLowerCase() : "";
    const normalizedMime = mimeType.split(";")[0].trim();

    const AUDIO_FORMATS = {
      "audio/ogg": { extension: "ogg", mime: "audio/ogg" },
      "audio/mpeg": { extension: "mp3", mime: "audio/mpeg" },
      "audio/mp3": { extension: "mp3", mime: "audio/mpeg" },
      "audio/mp4": { extension: "m4a", mime: "audio/mp4" },
      "audio/x-m4a": { extension: "m4a", mime: "audio/mp4" },
      "audio/wav": { extension: "wav", mime: "audio/wav" },
      "audio/x-wav": { extension: "wav", mime: "audio/wav" },
      "audio/webm": { extension: "webm", mime: "audio/webm" },
    };

    const audioFormat = AUDIO_FORMATS[normalizedMime];
    if (!audioFormat) {
      return jsonError(res, 400, "Unsupported audio format. Use OGG, MP3, MP4/M4A, WAV, or WebM.");
    }

    let language = typeof req.body?.language === "string" ? req.body.language.trim().toLowerCase() : "";
    if (!language) {
      const ownerPhone = String(req.body?.ownerPhone || req.body?.phoneNumber || req.headers["x-phone-number"] || req.headers["x-owner-phone"] || req.headers["x-instance-name"] || "").replace(/\D/g, "");
      if (ownerPhone.startsWith("92")) {
        language = "ur";
      }
    }

    const decoded = decodeBase64Field(res, req.body?.audio, "audio");
    if (!decoded) return;

    if (aiQueue.length >= MAX_AI_QUEUE && aiActive >= MAX_AI_CONCURRENCY) {
      return jsonError(res, 429, "AI queue is full; retry shortly");
    }

    try {
      debugLog("MEDIA_TRANSCRIBE_START", "Starting transcription task", { mimeType: audioFormat.mime, language, audioSizeBytes: decoded.length });
      const ownerPhone = String(req.body?.ownerPhone || req.body?.phoneNumber || "").replace(/\D/g, "");
      const storageResult = await uploadToSupabaseStorage(
        ownerPhone,
        "audio",
        audioFormat.mime,
        decoded,
        req.body?.fileName || ""
      );
      if (!storageResult.uploaded || !storageResult.signedUrl) {
        return jsonError(res, 502, "Audio could not be stored for URL-based transcription; please retry");
      }
      
      const transcript = await runAiTask(async () => {
        return transcribeAudioFromUrl(storageResult.signedUrl, language);
      });

      debugLog("MEDIA_TRANSCRIBE_SUCCESS", "Transcription completed successfully", { transcriptPreview: transcript.slice(0, 100) });
      return res.json({ ok: true, transcript });
    } catch (error) {
      const status = Number.isInteger(error?.status) ? error.status : error?.name === "AbortError" ? 504 : 502;
      process.stderr.write(`[MEDIA:TRANSCRIBE] Failed with status ${status}\n`);
      debugLog("MEDIA_TRANSCRIBE_ERROR", "Transcription failed", { status, error: error instanceof Error ? error.message : "unknown" });

      return jsonError(
        res,
        status,
        status === 429 ? "Transcription rate limit reached; retry shortly" : status === 504 ? "Transcription timed out; please retry" : "Transcription failed; please retry"
      );
    }
  }
);

// ============================================================================
// POST /api/media/analyse
// ============================================================================

app.post("/api/media/analyse", requireEnrollment, requireMediaRateLimit, async (req, res) => {
  const decoded = decodeBase64Field(res, req.body?.imageBase64, "imageBase64");
  if (!decoded) return;

  if (aiQueue.length >= MAX_AI_QUEUE && aiActive >= MAX_AI_CONCURRENCY) {
    return jsonError(res, 429, "AI queue is full; retry shortly");
  }

  try {
    debugLog("MEDIA_ANALYSE_START", "Starting image analysis task", { imageSizeBytes: decoded.length });
    const ownerPhone = String(req.body?.ownerPhone || req.body?.phoneNumber || "").replace(/\D/g, "");
    const storageResult = await uploadToSupabaseStorage(
      ownerPhone,
      "image",
      "image/jpeg",
      decoded,
      req.body?.fileName || ""
    );
    if (!storageResult.uploaded || !storageResult.signedUrl) {
      return jsonError(res, 502, "Image could not be stored for URL-based analysis; please retry");
    }
    
    const result = await runAiTask(async () => {
      const { content } = await pollinationsChat([
        {
          role: "user",
          content: [
            {
              type: "text",
              text: `Analyse this image and respond in this exact JSON format:
{
"description": "<1-2 sentence description of what you see>",
"quality": "<good|average|poor>",
"appraisal": "<if quality is good, write a warm enthusiastic compliment for the sender (1 sentence). If average or poor, leave this field as an empty string>"
}
Return only valid JSON. Do not add markdown fences or any other text outside the JSON object.`,
            },
            { type: "image_url", image_url: { url: storageResult.signedUrl, detail: "auto" } },
          ],
        },
      ]);
      if (!content) {
        const error = new Error("Pollinations returned an empty image analysis");
        error.status = 502;
        throw error;
      }
      return content;
    });

    let description = "";
    let quality = "unknown";
    let appraisal = null;

    try {
      const cleaned = result.replace(/^\`\`\`json\s*/i, "").replace(/^\`\`\`\s*/i, "").replace(/\`\`\`\s*$/, "").trim();
      const parsed = JSON.parse(cleaned);
      description = typeof parsed.description === "string" ? parsed.description.trim() : result.trim();
      quality = typeof parsed.quality === "string" && ["good", "average", "poor"].includes(parsed.quality.toLowerCase()) ? parsed.quality.toLowerCase() : "unknown";
      appraisal = quality === "good" && typeof parsed.appraisal === "string" && parsed.appraisal.trim() ? parsed.appraisal.trim() : null;
    } catch {
      description = result.trim();
      quality = "unknown";
      appraisal = null;
    }

    debugLog("MEDIA_ANALYSE_SUCCESS", "Image analysis completed", { description, quality, appraisal });
    return res.json({ ok: true, description, quality, appraisal });
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 502;
    process.stderr.write(`[MEDIA:ANALYSE] Error: ${error instanceof Error ? error.message : "unknown"}\n`);
    debugLog("MEDIA_ANALYSE_ERROR", "Image analysis failed", { status, error: error instanceof Error ? error.message : "unknown" });
    return jsonError(res, status, status === 429 ? "AI queue is full; retry shortly" : "Image analysis failed; please retry");
  }
});

// ============================================================================
// POST /api/media/process & /api/media/auto-process
// ============================================================================

app.post(
  ["/api/media/process", "/api/media/auto-process"],
  requireEnrollment,
  requireMediaRateLimit,
  async (req, res) => {
    const rawMediaType = String(req.body?.mediaType || "").toLowerCase();
    const mimeType = String(req.body?.mimeType || "application/octet-stream").trim().toLowerCase();
    const ownerPhone = String(req.body?.ownerPhone || req.body?.phoneNumber || "").replace(/\D/g, "");
    const fileName = req.body?.fileName || req.body?.filename;

    const base64Content = req.body?.mediaBase64 || req.body?.audio || req.body?.imageBase64;
    const decoded = decodeBase64Field(res, base64Content, "mediaBase64");
    if (!decoded) return;

    if (aiQueue.length >= MAX_AI_QUEUE && aiActive >= MAX_AI_CONCURRENCY) {
      return jsonError(res, 429, "AI queue is full; retry shortly");
    }

    try {
      // 1. Upload to Supabase Storage in WA-Copilot/{phone}/{subfolder}/
      const storageResult = await uploadToSupabaseStorage(
        ownerPhone,
        rawMediaType,
        mimeType,
        decoded,
        fileName
      );
      if (!storageResult.uploaded || !storageResult.signedUrl) {
        debugLog("MEDIA_PROCESS_STORAGE_REQUIRED", "Media analysis stopped because Supabase upload or signed URL creation failed", {
          mediaType: rawMediaType,
          uploaded: storageResult.uploaded,
          signedUrlAvailable: Boolean(storageResult.signedUrl),
        });
        return jsonError(res, 502, "Media could not be stored for URL-based analysis; please retry");
      }

      // 2. Perform AI Analysis
      const isImage = rawMediaType === "image" || mimeType.startsWith("image/");
      const isAudio = rawMediaType === "voice" || rawMediaType === "audio" || mimeType.startsWith("audio/");
      const isVideo = rawMediaType === "video" || mimeType.startsWith("video/");

      let rawAnalysis = "";
      await runAiTask(async () => {
        if (isImage) {
          const response = await pollinationsChat([
            {
              role: "user",
              content: [
                { type: "text", text: "Analyze this image in 1-2 clear, informative sentences for a user assistant." },
                { type: "image_url", image_url: { url: storageResult.signedUrl, detail: "auto" } },
              ],
            },
          ]);
          rawAnalysis = response.content;
        } else if (isAudio) {
          const language = ownerPhone.startsWith("92") ? "ur" : "";
          rawAnalysis = await transcribeAudioFromUrl(storageResult.signedUrl, language);
        } else if (isVideo) {
          rawAnalysis = `Video file (${(decoded.length / 1024).toFixed(0)} KB) received and stored in video archive.`;
        } else {
          rawAnalysis = `Document (${fileName || "file"}) received and stored in document archive.`;
        }
      });

      // 3. Enclose description in appropriate tag
      let mediaDescription = "";
      if (isAudio) {
        mediaDescription = `<audio_message>\n${rawAnalysis}\n</audio_message>`;
      } else if (isImage) {
        mediaDescription = `<Image_message>\n${rawAnalysis}\n</Image_message>`;
      } else {
        mediaDescription = `<Media_description>\n${rawAnalysis}\n</Media_description>`;
      }

      // Metadata-only log: Never log phone numbers, keys, content, or signed URL
      debugLog("MEDIA_PROCESS_SUCCESS", "Media process completed", {
        mediaType: rawMediaType,
        uploaded: storageResult.uploaded,
      });

      return res.json({
        ok: true,
        mediaType: rawMediaType,
        mediaDescription,
        Media_description: mediaDescription,
        storagePath: storageResult.path,
        uploaded: storageResult.uploaded,
      });
    } catch (error) {
      debugLog("MEDIA_PROCESS_ERROR", "Media process failed", { error: error?.message });
      return jsonError(res, 502, "Media processing failed; please retry");
    }
  }
);

app.get("/", (_req, res) => res.json({ service: "HexaSynq Gateway", ok: true }));
app.get("/health/live", (_req, res) => res.json({ ok: true, status: "live" }));

app.get("/health", async (_req, res) => {
  const status = {
    ok: true,
    service: "HexaSynq Gateway",
    mappingsLoaded: storeReady,
    firebase: firebaseMessaging ? "initialized" : "unavailable",
    firebaseDetail: firebaseStatus,
    evolutionConfigured: Boolean(EVOLUTION_SERVER_URL && EVOLUTION_GLOBAL_KEY),
    ollamaConfigured: Boolean(OLLAMA_BASE_URL && OLLAMA_DEFAULT_MODEL),
    aiQueue: { active: aiActive, waiting: aiQueue.length, maxConcurrent: MAX_AI_CONCURRENCY, maxWaiting: MAX_AI_QUEUE },
  };
  let httpStatus = 200;
  if (!storeReady) { status.ok = false; httpStatus = 503; }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2_000);
    const response = await fetch(`${OLLAMA_BASE_URL}/api/tags`, { signal: controller.signal });
    clearTimeout(timeout);
    status.ollama = response.ok ? "reachable" : `http_${response.status}`;
  } catch { 
    status.ollama = "unreachable"; 
  }
  res.status(httpStatus).json(status);
});

app.post("/api/instance/create", requireEnrollment, async (req, res) => {
  const deviceId = normalizeDeviceId(req.body?.deviceId);
  const phoneNumber = normalizePhone(req.body?.phoneNumber);
  const fcmToken = typeof req.body?.fcmToken === "string" ? req.body.fcmToken.trim() : "";
  const usePairingCode = req.body?.usePairingCode === true;
  
  if (!deviceId) return jsonError(res, 400, "deviceId must be 8–128 safe characters");
  if (!phoneNumber) return jsonError(res, 400, "phoneNumber must contain 8–15 digits");
  if (!EVOLUTION_GLOBAL_KEY) return jsonError(res, 503, "Evolution API is not configured");
  if (PLAY_INTEGRITY_REQUIRED && !(await verifyPlayIntegrity(req, deviceId))) return jsonError(res, 403, "Play Integrity verification failed");

  try {
    const result = await withProvisionLock(deviceId, async () => {
      const instanceName = instanceNameForPhone(phoneNumber, deviceId);
      let existing = getDeviceRecord(deviceId);

      if (!existing && store.instances[instanceName]) {
        existing = getDeviceRecord(store.instances[instanceName]);
      }

      if (existing) {
        if (existing.deviceId && existing.deviceId !== deviceId) {
          const error = new Error("This instance is already linked to another device");
          error.status = 409;
          throw error;
        }
        if (existing.phoneNumber && existing.phoneNumber !== phoneNumber) {
          const error = new Error("This device is already linked to a different WhatsApp number");
          error.status = 409;
          throw error;
        }

        existing.deviceId = deviceId;
        existing.phoneNumber = phoneNumber;
        existing.instanceName = instanceName;
        store.devices[deviceId] = existing;
        store.instances[instanceName] = deviceId;

        if (fcmToken && existing.fcmToken !== fcmToken) {
          existing.fcmToken = fcmToken;
          existing.updatedAt = new Date().toISOString();
        }
        await persistStore();

        let websocketConfigured = true;
        try { await configureEvolutionWebsocket(instanceName); }
        catch (error) {
          websocketConfigured = false;
          process.stderr.write(`[WEBSOCKET] Configure failed for existing instance ${instanceName}: ${error?.status || error?.code || "unknown"}\n`);
        }
        
        let pairingCode = null;
        if (usePairingCode) {
          try {
            const connect = await evolutionRequest(`/instance/connect/${encodeURIComponent(instanceName)}?number=${encodeURIComponent(phoneNumber)}`);
            pairingCode = connect?.pairingCode || connect?.pairing_code || connect?.code || null;
          } catch (connectError) {
            process.stderr.write(`[PAIRING] Existing instance pairing code connect error: ${connectError?.message}\n`);
          }
        }
        return { instanceName, deviceSecret: deriveDeviceSecret(deviceId), created: false, existing: true, pairingCode, websocketConfigured };
      }

      const otherDeviceId = store.instances[instanceName];
      if (otherDeviceId && otherDeviceId !== deviceId) {
        const error = new Error("This WhatsApp number is already linked to another device");
        error.status = 409;
        throw error;
      }

      let createdByThisRequest = false;
      let createdInstance = false;
      let pairingCode = null;
      try {
        const created = await evolutionRequest("/instance/create", {
          method: "POST",
          body: {
            instanceName,
            token: deriveDeviceSecret(deviceId),
            qrcode: !usePairingCode,
            integration: "WHATSAPP-BAILEYS",
            reject_call: true,
            groups_ignore: true,
            always_online: false,
            read_messages: false,
            read_status: false,
            webhook: {
              url: `${process.env.PUBLIC_GATEWAY_URL || "https://gateway.hexabizsolutions.cloud"}/webhook/evolution`,
              enabled: true,
              webhook_by_events: true,
              webhook_base64: false,
              events: ["MESSAGES_UPSERT", "MESSAGES_UPDATE", "MESSAGES_DELETE", "SEND_MESSAGE", "CONNECTION_UPDATE", "PRESENCE_UPDATE", "QRCODE_UPDATED"],
              headers: WEBHOOK_SECRET ? { "x-webhook-secret": WEBHOOK_SECRET } : {},
            },
          },
        });
        createdByThisRequest = true;
        createdInstance = true;
        pairingCode = created?.pairingCode || created?.pairing_code || created?.instance?.pairingCode || null;
      } catch (createError) {
        const isAlreadyExists = createError.status === 403 || createError.status === 409 || /already/i.test(createError?.data?.response?.message || createError?.message || "");
        const [checksumPrefix] = instanceName.split("_");
        if (isAlreadyExists && checksumPrefix === deviceId) {
          process.stdout.write(`[INSTANCE] Auto-linking existing Evolution instance: ${instanceName}\n`);
        } else {
          throw createError;
        }
      }

      if (usePairingCode && !pairingCode) {
        try {
          const connect = await evolutionRequest(`/instance/connect/${encodeURIComponent(instanceName)}?number=${encodeURIComponent(phoneNumber)}`);
          pairingCode = connect?.pairingCode || connect?.pairing_code || connect?.code || null;
        } catch (connectError) {
          process.stderr.write(`[PAIRING] Pairing code connect error: ${connectError?.message}\n`);
        }
      }
      
      let websocketConfigured = true;
      try { await configureEvolutionWebsocket(instanceName); }
      catch (error) {
        websocketConfigured = false;
        process.stderr.write(`[WEBSOCKET] Configure failed for instance ${instanceName}: ${error?.status || error?.code || "unknown"}\n`);
      }
      
      const record = {
        deviceId,
        phoneNumber,
        instanceName,
        fcmToken: fcmToken || undefined,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      store.devices[deviceId] = record;
      store.instances[instanceName] = deviceId;
      try {
        await persistStore();
      } catch (persistError) {
        delete store.devices[deviceId];
        delete store.instances[instanceName];
        if (createdByThisRequest && createdInstance && !otherDeviceId) {
          try { await deleteEvolutionInstance(instanceName); } catch { /* leave cleanup for operator */ }
        }
        throw persistError;
      }
      return { instanceName, deviceSecret: deriveDeviceSecret(deviceId), created: createdInstance, existing: !createdInstance, pairingCode, websocketConfigured };
    });
    return res.status(result.created ? 201 : 200).json({ ok: true, ...result });
  } catch (error) {
    const status = Number.isInteger(error?.status) ? error.status : 502;
    return jsonError(res, status, error instanceof Error ? error.message : "Instance creation failed");
  }
});

app.post("/api/device/fcm", verifyDeviceRequest, async (req, res) => {
  const token = typeof req.body?.fcmToken === "string" ? req.body.fcmToken.trim() : "";
  if (!token || token.length > 4096) return jsonError(res, 400, "A valid fcmToken is required");
  const record = getDeviceRecord(req.deviceId);
  if (!record) return jsonError(res, 404, "Device is not linked; create or link an instance first");
  
  const previousToken = record.fcmToken;
  const previousUpdatedAt = record.updatedAt;
  record.fcmToken = token;
  record.updatedAt = new Date().toISOString();
  try {
    await persistStore();
    return res.json({ ok: true, registered: true, instanceName: record.instanceName });
  } catch {
    record.fcmToken = previousToken;
    record.updatedAt = previousUpdatedAt;
    return jsonError(res, 500, "Could not persist FCM token");
  }
});

app.post("/api/device/fcm/test", verifyDeviceRequest, async (req, res) => {
  const record = getDeviceRecord(req.deviceId);
  if (!record) return jsonError(res, 404, "Device is not linked to an instance");
  if (!record.fcmToken) return jsonError(res, 409, "token_missing");
  if (!firebaseMessaging) return jsonError(res, 503, "firebase_unavailable");
  
  const result = await sendPush(req.deviceId, "FCM_TEST_PING", {
    instanceName: record.instanceName,
    sentAt: new Date().toISOString(),
  });
  
  if (result.sent) return res.json({ ok: true, sent: true, instanceName: record.instanceName });
  if (result.reason === "no_fcm_token") return jsonError(res, 409, "token_missing");
  if (result.reason === "firebase_unavailable") return jsonError(res, 503, "firebase_unavailable");
  return jsonError(res, 502, "FCM test push failed", { reason: result.reason });
});

app.post("/api/instance/release", verifyDeviceRequest, async (req, res) => {
  const record = getDeviceRecord(req.deviceId);
  if (!record) return res.json({ ok: true, released: false, reason: "not_linked" });
  const requestedInstance = typeof req.body?.instanceName === "string" ? req.body.instanceName : record.instanceName;
  if (requestedInstance !== record.instanceName) return jsonError(res, 403, "Instance does not belong to this device");

  const isPermanent = req.body?.permanent === true || req.body?.mode === "permanent";

  if (isPermanent) {
    try {
      await deleteEvolutionInstance(record.instanceName);
    } catch (e) {
      process.stderr.write(`[DELETE] Evolution delete failed for ${record.instanceName}: ${e?.message}\n`);
    }

    const oldRecord = { ...record };
    delete store.instances[record.instanceName];
    delete store.devices[req.deviceId];
    try {
      await persistStore();
      return res.json({ ok: true, released: true, mode: "permanent", instanceName: requestedInstance });
    } catch {
      store.devices[req.deviceId] = oldRecord;
      store.instances[oldRecord.instanceName] = req.deviceId;
      return jsonError(res, 500, "Could not persist instance release");
    }
  } else {
    await logoutEvolutionInstance(record.instanceName);
    delete record.fcmToken;
    record.updatedAt = new Date().toISOString();
    try {
      await persistStore();
    } catch { /* non-fatal */ }
    return res.json({ ok: true, released: true, mode: "temporary", instanceName: requestedInstance });
  }
});

app.post("/api/chat", verifyDeviceRequest, async (req, res) => {
  const record = getDeviceRecord(req.deviceId);
  if (!record) return jsonError(res, 404, "Device is not linked to an instance");
  const messages = chatMessagesFromBody(req.body);
  if (!messages || messages.length === 0) return jsonError(res, 400, "Provide a non-empty prompt or messages array");
  if (messages.reduce((sum, message) => sum + message.content.length, 0) > MAX_PROMPT_CHARS) return jsonError(res, 413, "Prompt is too long");
  if (aiQueue.length >= MAX_AI_QUEUE && aiActive >= MAX_AI_CONCURRENCY) return jsonError(res, 429, "AI queue is full; retry shortly");
  
  try {
    debugLog("CHAT_REQ", "Processing chat request", { messagesCount: messages.length });
    const result = await runAiTask(async () => {
      return generateChatReply(messages);
    });
    debugLog("CHAT_RES", "Chat request completed", { model: result.model, provider: result.provider, fallbackUsed: result.fallbackUsed, responsePreview: result.content.slice(0, 100) });
    return res.json({ ok: true, response: result.content, model: result.model, provider: result.provider });
  } catch (error) {
    debugLog("CHAT_ERROR", "Chat request failed", { error: error instanceof Error ? error.message : "unknown" });
    return jsonError(res, 502, error instanceof Error ? error.message : "AI request failed");
  }
});

app.get("/api/instance/status", verifyDeviceRequest, async (req, res) => {
  const record = getDeviceRecord(req.deviceId);
  if (!record) return jsonError(res, 404, "Device is not linked to an instance");
  try {
    const data = await evolutionRequest(`/instance/connectionState/${encodeURIComponent(record.instanceName)}`);
    return res.json({ ok: true, instanceName: record.instanceName, state: data?.instance?.state || data?.state || "unknown", evolution: data });
  } catch (error) {
    return jsonError(res, 502, "Could not retrieve Evolution instance status", error instanceof Error ? error.message : undefined);
  }
});

function webhookAuthorized(req) {
  if (!WEBHOOK_SECRET) return process.env.ALLOW_UNSIGNED_EVOLUTION_WEBHOOKS === "true";
  return safeEqual(req.get("x-webhook-secret") || "", WEBHOOK_SECRET);
}

function webhookEventName(body) {
  return String(body?.event || body?.type || body?.eventType || "").toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.|\.$/g, "");
}

function extractInstanceName(body) {
  return String(body?.instance || body?.instanceName || body?.data?.instance || body?.instance?.instanceName || "").trim();
}

function unwrapMessage(msg) {
  let current = msg;
  let isViewOnce = false;
  let iterations = 0;
  while (current && typeof current === "object" && iterations < 10) {
    iterations++;
    const vo = current.viewOnceMessage || current.viewOnceMessageV2 || current.viewOnceMessageV2Extension;
    if (vo) {
      isViewOnce = true;
      current = vo.message || vo;
      continue;
    }
    const eph = current.ephemeralMessage;
    if (eph) {
      current = eph.message || eph;
      continue;
    }
    const docWithCaption = current.documentWithCaptionMessage;
    if (docWithCaption) {
      current = docWithCaption.message || docWithCaption;
      continue;
    }
    if (current.message && typeof current.message === "object" && Object.keys(current).length <= 2) {
      current = current.message;
      continue;
    }
    break;
  }
  if (!isViewOnce && current && typeof current === "object") {
    if (current.imageMessage?.viewOnce || current.videoMessage?.viewOnce || current.ptvMessage?.viewOnce || current.audioMessage?.viewOnce || current.documentMessage?.viewOnce || current.viewOnce) {
      isViewOnce = true;
    }
  }
  return { message: current, isViewOnce };
}

function extractMessageText(rawMessage) {
  if (!rawMessage || typeof rawMessage !== "object") return "";
  const { message, isViewOnce } = unwrapMessage(rawMessage);
  if (!message || typeof message !== "object") return "";
  const candidates = [
    message.conversation,
    message.extendedTextMessage?.text,
    message.imageMessage?.caption,
    message.videoMessage?.caption,
    message.documentMessage?.caption,
    message.buttonsResponseMessage?.selectedDisplayText,
    message.templateButtonReplyMessage?.selectedDisplayText,
    message.listResponseMessage?.title,
    message.listResponseMessage?.singleSelectReply?.selectedRowId,
    message.interactiveResponseMessage?.body?.text,
    message.pollCreationMessage?.name,
  ];
  let text = candidates.find((value) => typeof value === "string" && value.trim());
  if (!text) {
    if (message.imageMessage) text = "Photo";
    else if (message.videoMessage) text = "Video";
    else if (message.audioMessage) text = "Voice message";
    else if (message.documentMessage) text = message.documentMessage.fileName || "Document";
  }
  if (typeof text === "string" && text.trim()) {
    return isViewOnce ? `👁️ View Once: ${text.trim()}` : text.trim();
  }
  return isViewOnce ? "👁️ View Once Message" : "";
}

function webhookMessageId(data, key) {
  return String(key?.id || data?.keyId || data?.id || data?.messageId || data?.message?.id || "");
}

function webhookDedupeKey(body, eventName, instanceName, messageId, status = "") {
  if (messageId) return `${instanceName}:${eventName}:${messageId}${status ? `:${status}` : ""}`;
  return `${instanceName}:${eventName}:${crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex")}`;
}

function presencePhoneNumber(data, key, presences) {
  const candidates = [
    data?.phoneNumber, data?.senderPn, data?.remoteJidAlt, data?.chatId,
    key?.senderPn, key?.remoteJidAlt, key?.remoteJid, data?.id,
    ...Object.keys(presences || {}),
  ];
  for (const candidate of candidates) {
    if (typeof candidate !== "string") continue;
    const value = candidate.trim();
    const jid = value.match(/^([0-9]+)(?::[0-9]+)?@(s\.whatsapp\.net|c\.us)$/i);
    const directPhone = /^\+?[0-9]{8,15}$/.test(value) ? value.replace(/\D/g, "") : "";
    const digits = jid?.[1] || directPhone;
    if (digits.length >= 8 && digits.length <= 15) return digits;
  }
  return "";
}

app.post("/webhook/evolution", (req, res) => {
  if (!webhookAuthorized(req)) return jsonError(res, 401, "Invalid webhook secret");
  
  debugLog("WEBHOOK_RAW", "Received raw webhook payload", req.body);

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const instanceName = extractInstanceName(body);
  const eventName = webhookEventName(body);
  let deviceId = store.instances[instanceName];
  
  if (!deviceId) {
    const [instPrefix] = instanceName.split("_");
    if (instPrefix && store.devices[instPrefix]) {
      deviceId = instPrefix;
      store.instances[instanceName] = deviceId;
    }
  }
  if (!deviceId) return res.status(200).json({ ok: true, ignored: true, reason: "unmapped_instance" });

  const data = body.data && typeof body.data === "object" ? body.data : {};
  const key = data.key || data.message?.key || {};
  const eventMap = [
    ["messages.upsert", "NEW_WHATSAPP_MESSAGE"],
    ["messages.update", "MESSAGE_STATUS_UPDATE"],
    ["messages.delete", "MESSAGE_DELETED"],
    ["send.message", "SENT_WHATSAPP_MESSAGE"],
    ["connection.update", "CONNECTION_UPDATE"],
    ["presence.update", "PRESENCE_UPDATE"],
  ];
  const mapped = eventMap.find(([prefix]) => eventName === prefix || eventName.startsWith(`${prefix}.`));
  if (!mapped) return res.status(200).json({ ok: true, ignored: true, reason: "unsupported_event", event: eventName });

  const isPresenceEvent = mapped[1] === "PRESENCE_UPDATE";
  const messageId = isPresenceEvent ? "" : webhookMessageId(data, key);
  const statusText = String(data.update?.status || data.status || "");
  const dedupeKey = webhookDedupeKey(body, eventName, instanceName, messageId, statusText);
  
  if (isPresenceEvent) {
    if (webhookInFlight.has(dedupeKey)) {
      return res.status(200).json({ ok: true, duplicate: true });
    }
    webhookInFlight.add(dedupeKey);
  } else {
    cleanExpired(webhookDedupeCache, 10 * 60_000);
    if (webhookDedupeCache.has(dedupeKey) || webhookInFlight.has(dedupeKey)) {
      return res.status(200).json({ ok: true, duplicate: true });
    }
    rememberOnce(webhookDedupeCache, dedupeKey, 10 * 60_000, 20_000);
    webhookInFlight.add(dedupeKey);
  }

  const rawMsg = data.message || data;
  const { message: effectiveMsg, isViewOnce } = unwrapMessage(rawMsg);
  const rawJid = String(data.id || key.remoteJid || data.remoteJid || data.chatId || "");
  const presencesObj = data.presences && typeof data.presences === "object" ? data.presences : {};
  const firstPresence = Object.values(presencesObj)[0];
  const presenceState = String(firstPresence?.lastKnownPresence || data.presence || data.status || data.state || "").toLowerCase();
  const isOnline = presenceState === "available" || presenceState === "composing" || presenceState === "recording" || presenceState === "online";
  const cleanPhone = isPresenceEvent
    ? presencePhoneNumber(data, key, presencesObj)
    : rawJid.substring(0, 30).replace(/[^0-9]/g, "");

  const payload = {
    eventId: crypto.createHash("sha256").update(dedupeKey).digest("hex"),
    instanceName,
    messageId,
    chatId: rawJid,
    phoneNumber: cleanPhone,
    fromMe: String(key.fromMe ?? data.fromMe ?? false),
    timestamp: String(data.messageTimestamp || data.timestamp || body.date_time || body.timestamp || ""),
    messageText: extractMessageText(rawMsg),
    messageType: String(effectiveMsg && typeof effectiveMsg === "object" ? Object.keys(effectiveMsg).find((name) => name.endsWith("Message")) || "text" : "text"),
    mediaType: String(
      effectiveMsg?.imageMessage ? "image" :
      effectiveMsg?.videoMessage || effectiveMsg?.ptvMessage ? "video" :
      effectiveMsg?.audioMessage ? "audio" :
      effectiveMsg?.documentMessage ? "document" :
      effectiveMsg?.stickerMessage ? "sticker" :
      (isViewOnce ? "image" : "")
    ),
    hasMedia: String(Boolean(effectiveMsg && typeof effectiveMsg === "object" && Object.keys(effectiveMsg).some((name) => name.endsWith("Message") && name !== "extendedTextMessage"))),
    isViewOnce: String(isViewOnce),
    status: String(data.update?.status || data.status || ""),
    isOnline: String(isOnline),
    presenceState: presenceState,
    notificationTitle: mapped[1] === "PRESENCE_UPDATE" && isOnline
      ? String(data.pushName || data.name || "Contact is online").slice(0, 100)
      : String(data.pushName || data.notifyName || data.name || "WhatsApp message").slice(0, 100),
  };

  debugLog("WEBHOOK_PROCESSED", "Webhook processed, scheduling FCM push", { eventType: mapped[1], instanceName, deviceId, payload });

  res.status(200).json({ ok: true, accepted: true, notification: "scheduled" });
  
  setImmediate(() => {
    void sendPush(deviceId, mapped[1], payload)
      .then((result) => {
        if (!result.sent) process.stderr.write(`[FCM] Push failed event=${mapped[1]} reason=${result.reason || "unknown"} instance=${instanceName}\n`);
      })
      .catch((error) => {
        process.stderr.write(`[FCM] Unexpected push error event=${mapped[1]} instance=${instanceName} reason=${error?.code || "unknown"}\n`);
      })
      .finally(() => webhookInFlight.delete(dedupeKey));
  });
});

app.use((error, _req, res, _next) => {
  const status = Number.isInteger(error?.status) ? error.status : 500;
  return jsonError(res, status, status >= 500 ? "Internal server error" : (error?.message || "Request failed"));
});

await loadStore();
const server = app.listen(PORT, HOST, () => {
  process.stdout.write(`HexaSynq Gateway listening on ${HOST}:${PORT}\n`);
  debugLog("SERVER", "Gateway started successfully", { port: PORT, host: HOST, aiProvider: AI_PROVIDER });
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`Received ${signal}; shutting down\n`);
  debugLog("SERVER", `Shutting down due to ${signal}`);
  server.close(async () => {
    try { await storeWriteChain; } catch { /* persistence failure already surfaced to caller */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
process.on("SIGINT", () => { void shutdown("SIGINT"); });

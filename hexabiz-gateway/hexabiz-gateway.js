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
const MAX_BODY_BYTES = positiveInt(process.env.MAX_BODY_BYTES, 1_048_576);
const MAX_CLOCK_SKEW_MS = positiveInt(process.env.MAX_CLOCK_SKEW_MS, 5 * 60_000);
const NONCE_TTL_MS = positiveInt(process.env.NONCE_TTL_MS, 10 * 60_000);
const MAX_NONCES = positiveInt(process.env.MAX_NONCES, 20_000);
const MAX_AI_CONCURRENCY = positiveInt(process.env.MAX_AI_CONCURRENCY, 4);
const MAX_AI_QUEUE = positiveInt(process.env.MAX_AI_QUEUE, 30);
const MAX_PROMPT_CHARS = positiveInt(process.env.MAX_PROMPT_CHARS, 20_000);

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(value || "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}
function jsonError(res, status, error, details) {
  const payload = { ok: false, error };
  if (details) payload.details = details;
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
function instanceNameForPhone(phone) {
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
    const serviceAccount = JSON.parse(await fs.readFile(SERVICE_ACCOUNT_PATH, "utf8"));
    initializeApp({ credential: cert(serviceAccount) });
    firebaseMessaging = getMessaging();
    firebaseStatus = "initialized";
  }
} catch (error) {
  firebaseStatus = `unavailable: ${error instanceof Error ? error.message : "initialization failed"}`;
  // Gateway remains available; FCM sends will return an explicit service-unavailable error.
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

async function loadStore() {
  await fs.mkdir(path.dirname(MAPPINGS_FILE_PATH), { recursive: true });
  try {
    const raw = await fs.readFile(MAPPINGS_FILE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || typeof parsed.devices !== "object" || typeof parsed.instances !== "object") {
      throw new Error("Mapping file has an invalid shape");
    }
    store = { version: 1, devices: parsed.devices || {}, instances: parsed.instances || {} };
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    store = emptyStore();
    await persistStore();
  }
  // Reconcile reverse mappings and discard malformed records without guessing ownership.
  const instances = {};
  for (const [deviceId, record] of Object.entries(store.devices)) {
    if (!record || typeof record !== "object" || typeof record.instanceName !== "string" || !record.instanceName) {
      delete store.devices[deviceId];
      continue;
    }
    const existing = instances[record.instanceName];
    if (existing && existing !== deviceId) {
      // Ambiguous ownership is unsafe. Keep neither mapping; operator can reconcile manually.
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
  // Capture a stable snapshot at call time. Recover the queue after a prior write
  // failure so one disk error does not permanently poison every future save.
  const snapshot = JSON.stringify(store, null, 2);
  const write = storeWriteChain.catch(() => undefined).then(async () => {
    await fs.mkdir(path.dirname(MAPPINGS_FILE_PATH), { recursive: true });
    const tempPath = `${MAPPINGS_FILE_PATH}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
    try {
      await fs.writeFile(tempPath, snapshot, { encoding: "utf8", mode: 0o600, flag: "wx" });
      await fs.rename(tempPath, MAPPINGS_FILE_PATH);
    } catch (error) {
      try { await fs.unlink(tempPath); } catch { /* temp file may not exist */ }
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
  // Only consume a nonce after authenticating the signature; otherwise anyone who
  // guesses a device ID could burn arbitrary nonce values for that device.
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
    const response = await fetch(`${EVOLUTION_SERVER_URL}${route}`, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: controller.signal,
    });
    const text = await response.text();
    let data;
    try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text.slice(0, 1000) }; }
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
    const response = await fetch(PLAY_INTEGRITY_VERIFIER_URL, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${PLAY_INTEGRITY_VERIFIER_KEY}` },
      body: JSON.stringify({ token, deviceId, requestPackageName: process.env.ANDROID_PACKAGE_NAME || "" }),
      signal: controller.signal,
    });
    if (!response.ok) return false;
    const result = await response.json();
    // The verifier service must validate Google's token, package name, app recognition,
    // licensing/device verdicts, freshness, and bind the verdict to this device/request.
    return result?.valid === true && result?.deviceId === deviceId;
  } catch {
    return false;
  } finally { clearTimeout(timeout); }
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
  // Keep the message itself as the priority field. FCM data payloads have a strict
  // size limit; long messages/media metadata are clipped, never allowed to block sync.
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
    await firebaseMessaging.send({
      token: record.fcmToken,
      data,
      android: { priority: "high", ttl: 60 * 60 * 1000 },
    });
    return { sent: true };
  } catch (error) {
    const code = error?.code || "unknown";
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
    return body.messages.filter((item) => item && ["system", "user", "assistant"].includes(item.role) && typeof item.content === "string")
      .map((item) => ({ role: item.role, content: item.content.slice(0, MAX_PROMPT_CHARS) }));
  }
  if (typeof body?.prompt === "string") return [{ role: "user", content: body.prompt.slice(0, MAX_PROMPT_CHARS) }];
  return null;
}
async function ollamaChat(messages) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const response = await fetch(`${OLLAMA_BASE_URL}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: OLLAMA_DEFAULT_MODEL, messages, stream: false }),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
    const content = data?.message?.content;
    if (typeof content !== "string" || !content.trim()) throw new Error("Ollama returned an empty response");
    return { content, model: data?.model || OLLAMA_DEFAULT_MODEL, provider: "ollama" };
  } finally { clearTimeout(timeout); }
}
async function pollinationsChat(messages) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), AI_TIMEOUT_MS);
  try {
    const headers = { "content-type": "application/json", accept: "application/json" };
    if (POLLINATIONS_API_KEY) headers.authorization = `Bearer ${POLLINATIONS_API_KEY}`;
    const response = await fetch(`${POLLINATIONS_BASE_URL}/v1/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify({ model: POLLINATIONS_MODEL, messages, stream: false }),
      signal: controller.signal,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(`Pollinations returned HTTP ${response.status}`);
    const content = data?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || !content.trim()) throw new Error("Pollinations returned an empty response");
    return { content, model: data?.model || POLLINATIONS_MODEL, provider: "pollinations" };
  } finally { clearTimeout(timeout); }
}

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
  } catch { status.ollama = "unreachable"; }
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
      const existing = getDeviceRecord(deviceId);
      const instanceName = instanceNameForPhone(phoneNumber);
      if (existing) {
        if (existing.phoneNumber !== phoneNumber || existing.instanceName !== instanceName) {
          const error = new Error("This device is already linked to a different WhatsApp number");
          error.status = 409;
          throw error;
        }
        if (fcmToken && existing.fcmToken !== fcmToken) {
          const previousToken = existing.fcmToken;
          const previousUpdatedAt = existing.updatedAt;
          existing.fcmToken = fcmToken;
          existing.updatedAt = new Date().toISOString();
          try { await persistStore(); } catch (error) {
            existing.fcmToken = previousToken;
            existing.updatedAt = previousUpdatedAt;
            throw error;
          }
        }
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

      // Do not delete on a failed create unless this request can prove it created the instance.
      let createdByThisRequest = false;
      let createdInstance = false;
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
        let pairingCode = created?.pairingCode || created?.pairing_code || created?.instance?.pairingCode || null;
        if (usePairingCode && !pairingCode) {
          try {
            const connect = await evolutionRequest(`/instance/connect/${encodeURIComponent(instanceName)}?number=${encodeURIComponent(phoneNumber)}`);
            pairingCode = connect?.pairingCode || connect?.pairing_code || connect?.code || null;
          } catch (connectError) {
            process.stderr.write(`[PAIRING] New instance pairing code connect error: ${connectError?.message}\n`);
          }
        }
        let websocketConfigured = true;
        try { await configureEvolutionWebsocket(instanceName); }
        catch (error) {
          websocketConfigured = false;
          process.stderr.write(`[WEBSOCKET] Configure failed for new instance ${instanceName}: ${error?.status || error?.code || "unknown"}\n`);
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
          // Safe only because this invocation received a successful create response and
          // no mapping existed for the instance before the request.
          if (createdByThisRequest && createdInstance && !otherDeviceId) {
            try { await deleteEvolutionInstance(instanceName); } catch { /* leave cleanup for operator if Evolution is unavailable */ }
          }
          throw persistError;
        }
        return { instanceName, deviceSecret: deriveDeviceSecret(deviceId), created: true, existing: false, pairingCode, websocketConfigured };
      } catch (error) {
        // Never attempt destructive rollback for errors where ownership is uncertain.
        throw error;
      }
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
    // Keep in-memory state consistent with the last known durable state.
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
  // Release removes the gateway association only. It deliberately does not delete the
  // Evolution instance; deletion is a separate, explicit administrative operation.
  const oldRecord = { ...record };
  delete store.instances[record.instanceName];
  delete store.devices[req.deviceId];
  try {
    await persistStore();
    return res.json({ ok: true, released: true, instanceName: requestedInstance });
  } catch {
    // Restore the mapping if the release did not reach durable storage.
    store.devices[req.deviceId] = oldRecord;
    store.instances[oldRecord.instanceName] = req.deviceId;
    return jsonError(res, 500, "Could not persist instance release");
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
    const result = await runAiTask(async () => {
      try { return await ollamaChat(messages); }
      catch (primaryError) {
        try { return await pollinationsChat(messages); }
        catch (fallbackError) {
          const error = new Error("AI providers are currently unavailable");
          error.cause = { primary: primaryError?.message, fallback: fallbackError?.message };
          throw error;
        }
      }
    });
    return res.json({ ok: true, response: result.content, model: result.model, provider: result.provider });
  } catch (error) {
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
function extractMessageText(message) {
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
  const text = candidates.find((value) => typeof value === "string" && value.trim());
  return typeof text === "string" ? text.trim() : "";
}
function webhookMessageId(data, key) {
  return String(key?.id || data?.id || data?.messageId || data?.message?.id || "");
}
function webhookDedupeKey(body, eventName, instanceName, messageId) {
  if (messageId) return `${instanceName}:${eventName}:${messageId}`;
  return `${instanceName}:${eventName}:${crypto.createHash("sha256").update(JSON.stringify(body)).digest("hex")}`;
}
app.post("/webhook/evolution", (req, res) => {
  if (!webhookAuthorized(req)) return jsonError(res, 401, "Invalid webhook secret");
  const body = req.body && typeof req.body === "object" ? req.body : {};
  const instanceName = extractInstanceName(body);
  const eventName = webhookEventName(body);
  if (!instanceName || !eventName) return jsonError(res, 400, "Webhook payload is missing instance or event");
  const deviceId = store.instances[instanceName];
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

  const messageId = webhookMessageId(data, key);
  const dedupeKey = webhookDedupeKey(body, eventName, instanceName, messageId);
  cleanExpired(webhookDedupeCache, 10 * 60_000);
  if (webhookDedupeCache.has(dedupeKey) || webhookInFlight.has(dedupeKey)) {
    return res.status(200).json({ ok: true, duplicate: true });
  }
  rememberOnce(webhookDedupeCache, dedupeKey, 10 * 60_000, 20_000);
  webhookInFlight.add(dedupeKey);

  const message = data.message || data;
  const payload = {
    eventId: crypto.createHash("sha256").update(dedupeKey).digest("hex"),
    instanceName,
    messageId,
    chatId: String(key.remoteJid || data.remoteJid || data.chatId || ""),
    phoneNumber: String(key.remoteJid || data.remoteJid || data.chatId || "").substring(0, 30).replace(/[^0-9]/g, ""),
    fromMe: String(key.fromMe ?? data.fromMe ?? false),
    timestamp: String(data.messageTimestamp || data.timestamp || body.date_time || body.timestamp || ""),
    messageText: extractMessageText(message),
    messageType: String(message && typeof message === "object" ? Object.keys(message).find((name) => name.endsWith("Message")) || "text" : "text"),
    hasMedia: String(Boolean(message && typeof message === "object" && Object.keys(message).some((name) => name.endsWith("Message") && name !== "extendedTextMessage"))),
    status: String(data.update?.status || data.status || ""),
    notificationTitle: String(data.pushName || data.notifyName || data.name || "WhatsApp message").slice(0, 100),
  };

  // Return to Evolution immediately. FCM is best-effort and never blocks the
  // webhook response or the Android app's independent Evolution/WebSocket sync.
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
  // Do not expose stack traces or upstream credentials to clients.
  const status = Number.isInteger(error?.status) ? error.status : 500;
  return jsonError(res, status, status >= 500 ? "Internal server error" : (error?.message || "Request failed"));
});

await loadStore();
const server = app.listen(PORT, HOST, () => {
  process.stdout.write(`HexaSynq Gateway listening on ${HOST}:${PORT}\n`);
});

let shuttingDown = false;
async function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  process.stdout.write(`Received ${signal}; shutting down\n`);
  server.close(async () => {
    try { await storeWriteChain; } catch { /* persistence failure already surfaced to caller */ }
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10_000).unref();
}
process.on("SIGTERM", () => { void shutdown("SIGTERM"); });
process.on("SIGINT", () => { void shutdown("SIGINT"); });

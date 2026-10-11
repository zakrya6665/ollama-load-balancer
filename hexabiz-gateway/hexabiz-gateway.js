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

console.log("[CONFIG] Evolution Server URL:", EVOLUTION_SERVER_URL);
console.log("[CONFIG] Gateway Public URL:", GATEWAY_PUBLIC_URL);
console.log("[CONFIG] AI Provider:", AI_PROVIDER);

const rateLimits = new Map();
const usedNonces = new Map();
const instanceCreationLimits = new Map();
const instanceToDeviceMap = new Map(); // instanceName -> deviceId  (in-memory; rebuilt when the app re-registers its FCM token)
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

function buildWebhookConfig() {
  const config = {
    enabled: true,
    url: `${GATEWAY_PUBLIC_URL}/webhook/evolution?s=${WEBHOOK_SECRET}`,
    byEvents: false,
    base64: false,
    headers: { "x-webhook-secret": WEBHOOK_SECRET },
    events: WEBHOOK_EVENTS,
  };
  console.log(`[WEBHOOK] Configured webhook URL: ${config.url}`);
  return config;
}

/** true = exists, false = does not exist, null = could not tell. Uses the global key. */
async function instanceExists(instanceName) {
  try {
    console.log(`[EVOLUTION] Checking if instance exists: ${instanceName}`);
    const r = await fetchWithTimeout(
      `${EVOLUTION_SERVER_URL}/instance/fetchInstances?instanceName=${encodeURIComponent(instanceName)}`,
      { method: "GET", headers: { apikey: EVOLUTION_GLOBAL_KEY } }
    );
    console.log(`[EVOLUTION] fetchInstances status: ${r.status}`);
    if (r.status === 404) return false;
    if (!r.ok) return null;
    const body = await r.json().catch(() => null);
    const list = Array.isArray(body) ? body : body ? [body] : [];
    console.log(`[EVOLUTION] Instance ${instanceName} exists: ${list.length > 0}`);
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
    console.log(`[EVOLUTION] Checking instance access: ${instanceName}`);
    const r = await fetchWithTimeout(
      `${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(instanceName)}`,
      { method: "GET", headers: { apikey: deviceSecret } }
    );
    console.log(`[EVOLUTION] connectionState status: ${r.status}`);
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

/** Best effort: (re)attach the webhook to an existing instance. Needs Evolution v2 /webhook/set. */
async function configureWebhook(instanceName) {
  try {
    console.log(`[WEBHOOK] Attempting to configure webhook for: ${instanceName}`);
    const webhookConfig = buildWebhookConfig();
    console.log(`[WEBHOOK] Sending config to Evolution:`, JSON.stringify(webhookConfig, null, 2));
    
    const r = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/webhook/set/${encodeURIComponent(instanceName)}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: EVOLUTION_GLOBAL_KEY },
      body: JSON.stringify({ webhook: webhookConfig }),
    });
    
    console.log(`[WEBHOOK] webhook/set response status: ${r.status}`);
    if (!r.ok) {
      const errorText = await r.text();
      console.warn(`[WEBHOOK] webhook/set for ${instanceName} returned HTTP ${r.status}: ${errorText}`);
    } else {
      console.log(`[WEBHOOK] Successfully configured webhook for ${instanceName}`);
    }
  } catch (err) {
    console.error(`[WEBHOOK] webhook/set for ${instanceName} failed: ${err.message}`);
  }
}

/** Instance name for a signed request. Header first, then known mapping, then the old hash name. */
function resolveInstanceName(req) {
  const header = req.get("x-instance-name");
  if (header) {
    console.log(`[INSTANCE] Using instance name from header: ${header}`);
    return isValidInstanceName(header) ? header : null;
  }
  const mapped = deviceToInstanceMap.get(req.deviceId);
  if (mapped) {
    console.log(`[INSTANCE] Using instance name from mapping: ${mapped}`);
    return mapped;
  }
  const legacy = deriveLegacyInstanceName(req.deviceId);
  console.log(`[INSTANCE] Using legacy instance name: ${legacy}`);
  return legacy;
}

// ============================================================
// Security Middleware
// ============================================================

function verifyEnrollmentKey(req, res, next) {
  const supplied = req.get("x-enrollment-key");
  if (!supplied || !safeEqualText(supplied, APP_ENROLLMENT_KEY)) {
    console.warn(`[SECURITY] Invalid enrollment key from IP: ${req.ip}`);
    return res.status(401).json({ error: "Unauthorized" });
  }
  console.log(`[SECURITY] Enrollment key verified`);
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
  const LIMIT = 3;
  let entry = instanceCreationLimits.get(ip);
  if (!entry || now - entry.windowStart > WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    instanceCreationLimits.set(ip, entry);
  }
  if (entry.count >= LIMIT) {
    console.warn(`[SECURITY] IP ${ip} exceeded strict instance creation limit (${LIMIT}/24h).`);
    return res.status(429).json({ error: "Strict limit reached: Maximum 3 device linkings allowed per 24 hours." });
  }
  entry.count += 1;
  console.log(`[SECURITY] IP ${ip} instance creation count: ${entry.count}/${LIMIT}`);
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
    console.warn(`[SECURITY] Replay detected for device: ${deviceId}, nonce: ${nonce}`);
    return res.status(401).json({ error: "Replay detected" });
  }

  if (!checkRateLimit(deviceId)) {
    console.warn(`[SECURITY] Rate limit exceeded for device: ${deviceId}`);
    return res.status(429).json({ error: "Too many requests. Calm down." });
  }

  req.deviceId = deviceId;
  req.deviceToken = deviceSecret;
  console.log(`[SECURITY] HMAC verified for device: ${deviceId}`);
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
    console.log(`[FCM] ✅ Successfully pushed to device ${deviceId} for instance ${instanceName}`);
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

// --- TIER 1: HIGH VALUE ADMIN OPERATIONS ---
app.post(
  "/api/instance/create",
  verifyEnrollmentKey,
  strictIpRateLimit,
  verifyPlayIntegrityToken,
  async (req, res) => {
    console.log("\n========== [CREATE INSTANCE] START ==========");
    console.log(`[CREATE] Request from IP: ${req.ip}`);
    console.log(`[CREATE] Request body:`, JSON.stringify(req.body, null, 2));
    
    const { deviceId } = req.body ?? {};
    if (!isValidDeviceId(deviceId)) {
      console.error(`[CREATE]  Invalid device ID: ${deviceId}`);
      return res.status(400).json({ error: "Invalid device ID assignment" });
    }
    console.log(`[CREATE] ✅ Valid device ID: ${deviceId}`);

    const phone = normalizePhone(req.body?.phoneNumber);
    if (!phone) {
      console.error(`[CREATE] ❌ Invalid phone number: ${req.body?.phoneNumber}`);
      return res.status(400).json({ error: "Invalid phone number. Use country code + number, 8 to 15 digits." });
    }
    console.log(`[CREATE] ✅ Normalized phone: ${phone}`);

    const instanceName = deriveInstanceName(phone); // dev_<number>
    console.log(`[CREATE] Derived instance name: ${instanceName}`);
    
    const deviceSecret = deriveDeviceSecret(deviceId);
    console.log(`[CREATE] Generated device secret (first 8 chars): ${deviceSecret.slice(0, 8)}...`);

    const webhookConfig = buildWebhookConfig();
    console.log(`[CREATE] Webhook config:`, JSON.stringify(webhookConfig, null, 2));

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
      webhook: webhookConfig,
    };

    console.log(`[CREATE] Sending to Evolution:`);
    console.log(`[CREATE]   URL: ${EVOLUTION_SERVER_URL}/instance/create`);
    console.log(`[CREATE]   Body:`, JSON.stringify(requestBody, null, 2));

    try {
      const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/create`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "apikey": EVOLUTION_GLOBAL_KEY,
        },
        body: JSON.stringify(requestBody),
      });

      console.log(`[CREATE] Evolution response status: ${evoResponse.status}`);
      
      const data = await evoResponse.json().catch((err) => {
        console.error(`[CREATE] Failed to parse Evolution response JSON: ${err.message}`);
        return {};
      });
      
      const rawText = JSON.stringify(data);
      console.log(`[CREATE] Evolution response body:`, rawText);

      if (evoResponse.ok) {
        console.log(`[CREATE] ✅ Instance created successfully!`);
        registerInstance(instanceName, deviceId);
        console.log(`[CREATE] Returning success to client`);
        console.log("========== [CREATE INSTANCE] END ==========\n");
        return res.status(201).json({ instanceName, deviceSecret });
      }

      // Instance for this number already exists. Only the device whose secret is the instance
      // token may reuse it. Anyone else gets 409 instead of a "success" that won't work later.
      const alreadyExists =
        [400, 403, 409].includes(evoResponse.status) && /already (in use|exists)/i.test(rawText);

      if (alreadyExists) {
        console.log(`[CREATE] Instance already exists, checking ownership...`);
        const access = await instanceAccess(instanceName, deviceSecret);
        console.log(`[CREATE] Instance access result: ${access}`);
        
        if (access === "owned") {
          console.log(`[CREATE] ✅ Device owns existing instance, reusing`);
          registerInstance(instanceName, deviceId);
          await configureWebhook(instanceName); // heals instances created without a webhook
          console.log("========== [CREATE INSTANCE] END (REUSED) ==========\n");
          return res.status(200).json({ instanceName, deviceSecret, alreadyExisted: true });
        }
        if (access === "foreign") {
          console.log(`[CREATE] ❌ Instance exists but owned by different device`);
          // Wording avoids "already in use" / "already exists" on purpose: the Android app treats
          // those phrases as a recoverable case and would look for a secret that isn't there.
          console.log("========== [CREATE INSTANCE] END (FOREIGN) ==========\n");
          return res.status(409).json({ error: "This number is linked to a different device." });
        }
        console.log(`[CREATE] ❌ Could not verify existing instance`);
        console.log("========== [CREATE INSTANCE] END (ERROR) ==========\n");
        return res.status(502).json({ error: "Could not verify the existing instance. Try again." });
      }

      console.log(`[CREATE] ❌ Evolution rejected instance creation`);
      console.log("========== [CREATE INSTANCE] END (REJECTED) ==========\n");
      return res.status(evoResponse.status >= 400 ? evoResponse.status : 502).json({
        error: "Evolution API rejected instance creation",
        details: data?.response?.message ?? data?.message ?? data?.error ?? null,
      });
    } catch (err) {
      console.error(`[CREATE] ❌ Evolution API context error: ${err.message}`);
      console.error(`[CREATE] Stack trace:`, err.stack);
      console.log("========== [CREATE INSTANCE] END (EXCEPTION) ==========\n");
      return res.status(500).json({ error: "Evolution API context error", details: err.message });
    }
  }
);

// Endpoint for Android to register its FCM token
app.post("/api/device/fcm", verifyDynamicHmac, async (req, res) => {
  console.log(`[FCM] FCM registration request from device: ${req.deviceId}`);
  
  const { fcmToken } = req.body ?? {};
  if (typeof fcmToken !== "string" || fcmToken.length < 10 || fcmToken.length > 4096) {
    console.error(`[FCM] ❌ Invalid FCM token length: ${fcmToken?.length}`);
    return res.status(400).json({ error: "Invalid FCM token" });
  }
  
  deviceFcmTokens.set(req.deviceId, fcmToken);
  console.log(`[FCM] ✅ Stored FCM token for device ${req.deviceId}`);

  // Rebuild the instance -> device mapping after a gateway restart, but only if the device can
  // prove it owns the instance. Otherwise any device could claim someone else's messages.
  const claimed = req.get("x-instance-name");
  if (claimed && isValidInstanceName(claimed)) {
    console.log(`[FCM] Checking claimed instance: ${claimed}`);
    if ((await instanceAccess(claimed, req.deviceToken)) === "owned") {
      registerInstance(claimed, req.deviceId);
      console.log(`[FCM] ✅ Rebuilt instance mapping: ${claimed} -> ${req.deviceId}`);
    } else {
      console.warn(`[FCM] ❌ Device ${req.deviceId} does not own instance ${claimed}`);
    }
  }
  
  return res.status(200).json({ success: true });
});

app.post("/api/instance/release", verifyDynamicHmac, async (req, res) => {
  const instanceName = resolveInstanceName(req);
  if (!instanceName) return res.status(400).json({ error: "Invalid instance name" });

  console.log(`[RELEASE] Release request for instance: ${instanceName}, device: ${req.deviceId}`);

  try {
    const access = await instanceAccess(instanceName, req.deviceToken);
    console.log(`[RELEASE] Instance access result: ${access}`);

    if (access === "missing") {
      console.log(`[RELEASE] Instance already deleted`);
      unregisterInstance(instanceName, req.deviceId);
      return res.status(200).json({ success: true, message: "Instance already deleted" });
    }
    if (access === "foreign") {
      console.error(`[RELEASE] ❌ Device does not own instance`);
      return res.status(403).json({ error: "This device does not own that instance" });
    }
    if (access === "error") {
      console.error(`[RELEASE] ❌ Could not verify ownership`);
      return res.status(502).json({ error: "Could not verify instance ownership" });
    }

    // Ownership proven. Log out first (a connected instance may refuse deletion), then delete.
    try {
      console.log(`[RELEASE] Logging out instance ${instanceName}...`);
      await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/logout/${encodeURIComponent(instanceName)}`, {
        method: "DELETE",
        headers: { apikey: EVOLUTION_GLOBAL_KEY },
      });
      console.log(`[RELEASE] ✅ Logout successful`);
    } catch (err) {
      console.warn(`[RELEASE] Logout failed (best effort): ${err.message}`);
    }

    console.log(`[RELEASE] Deleting instance ${instanceName}...`);
    const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/delete/${encodeURIComponent(instanceName)}`, {
      method: "DELETE",
      headers: { apikey: EVOLUTION_GLOBAL_KEY, "Content-Type": "application/json" },
    });

    if (evoResponse.ok || evoResponse.status === 404) {
      console.log(`[RELEASE] ✅ Instance deleted`);
      unregisterInstance(instanceName, req.deviceId);
      return res.status(200).json({ success: true, message: "Instance released or already deleted" });
    }

    const errorData = await evoResponse.text();
    console.error(`[RELEASE] ❌ Evolution failed to delete: ${evoResponse.status} - ${errorData}`);
    return res.status(evoResponse.status).json({ error: "Evolution failed to delete", details: errorData });
  } catch (err) {
    console.error(`[RELEASE] ❌ Failed to release instance: ${err.message}`);
    return res.status(500).json({ error: "Failed to release instance", details: err.message });
  }
});

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
  const instanceName = resolveInstanceName(req);
  if (!instanceName) return res.status(400).json({ error: "Invalid instance name" });

  console.log(`[STATUS] Status request for instance: ${instanceName}`);

  try {
    // Evolution checks that the device secret matches this instance's token.
    const evoResponse = await fetchWithTimeout(`${EVOLUTION_SERVER_URL}/instance/connectionState/${encodeURIComponent(instanceName)}`, {
      method: "GET",
      headers: { "apikey": req.deviceToken },
    });
    const data = await evoResponse.json().catch(() => ({}));
    console.log(`[STATUS] Connection state: ${evoResponse.status}`);
    return res.status(evoResponse.status).json(data);
  } catch (err) {
    console.error(`[STATUS] Failed to pull state connection: ${err.message}`);
    return res.status(500).json({ error: "Failed to pull state connection", details: err.message });
  }
});

// ============================================================
// WEBHOOKS (FCM + Money Lending Compliance)
// ============================================================

/** Only real user JIDs. Groups (@g.us), status@broadcast and unresolved @lid return null. */
function jidToPhone(jid) {
  if (typeof jid !== "string") return null;
  const m = jid.match(/^(\d{8,15})(?::\d+)?@(?:s\.whatsapp\.net|c\.us)$/);
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
    // Evolution sends "messages.upsert"; normalise in case a version sends MESSAGES_UPSERT.
    const event = String(payload.event ?? "").toLowerCase().replace(/_/g, ".");
    const items = Array.isArray(payload.data) ? payload.data : payload.data ? [payload.data] : [];

    console.log(`[WEBHOOK] Received event: ${event} for instance: ${instanceName}`);

    // 1. Incoming messages (and delete-for-everyone, which arrives as a protocol message)
    if (event === "messages.upsert") {
      console.log(`[WEBHOOK] Processing ${items.length} message(s)`);
      for (const item of items) {
        const key = item?.key;
        if (!key || key.fromMe) {
          if (key?.fromMe) console.log(`[WEBHOOK] Skipping own message`);
          continue; // ignore the owner's own messages
        }

        // Newer WhatsApp accounts use @lid. Prefer the phone-number JID when Evolution provides it.
        const phoneNumber =
          jidToPhone(key.remoteJidAlt) || jidToPhone(key.senderPn) || jidToPhone(key.remoteJid);
        if (!phoneNumber) {
          console.log(`[WEBHOOK] Skipped non-user or unresolved JID: ${key.remoteJid}`);
          continue;
        }

        const protocol = item.message?.protocolMessage;
        if (protocol && (protocol.type === 0 || protocol.type === "REVOKE")) {
          const messageId = protocol.key?.id;
          if (messageId) {
            console.log(`[WEBHOOK] Message revoked: ${messageId}`);
            await sendFcmData(instanceName, {
              type: "MESSAGE_DELETED",
              messageId,
              phoneNumber,
              originalText: "", // WhatsApp does not resend the text; the app must look it up by messageId
            });
          }
          continue;
        }

        const messageText = extractMessageText(item.message);
        if (!messageText) {
          console.log(`[WEBHOOK] No text content in message, skipping`);
          continue;
        }

        console.log(`[WEBHOOK] Incoming message from ${phoneNumber}: ${messageText.slice(0, 50)}...`);
        await sendFcmData(instanceName, {
          type: "NEW_WHATSAPP_MESSAGE",
          phoneNumber,
          pushName: item.pushName || "Unknown",
          messageText: messageText.slice(0, MAX_FCM_TEXT),
          messageId: key.id || "",
          instanceName,
        });
      }
    }

    // 2. Anti-Delete Retention (Money Lending Compliance)
    if (event === "messages.delete" || event === "message.revoke") {
      console.log(`[WEBHOOK] Processing delete/revoke event`);
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

    // 3. Presence Tracking (Money Lending Compliance)
    // Only arrives for contacts the instance has subscribed to via Evolution's presence subscribe.
    if (event === "presence.update") {
      console.log(`[WEBHOOK] Processing presence update`);
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
    console.error("[WEBHOOK] Stack:", err.stack);
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
    console.log("[FCM] ✅ Firebase Admin initialized successfully.");
  } catch (err) {
    console.error("[FCM] ❌ Failed to initialize Firebase Admin. FCM pushes will fail.", err.message);
    console.error("[FCM] Stack:", err.stack);
  }

  if (AI_PROVIDER === "ollama") {
    console.log(`\n[OLLAMA] Verifying target model allocations: [${MODEL_NAME}] across runners...`);
    for (const runner of RUNNERS) {
      try {
        await waitForRunner(runner);
        console.log(`[OLLAMA] ✅ Runner ready: ${runner.url}`);
      } catch (err) {
        console.error(`[OLLAMA] ❌ Runner diagnostic alert: ${err.message}`);
      }
    }
    console.log("");
  }
});

export default app;

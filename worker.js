/**
 * Cloudflare Worker — Secure M3U Proxy + One-time AES Key bound to device
 *
 * - Reads m3u from a public R2 URL (cross-account public R2)
 * - Verifies uid/exp/sig, enforces single-device via KV (UID_BINDINGS)
 * - Generates one-time AES-GCM key per request, encrypts m3u with it
 * - Encrypts that one-time key with deviceKey (SHA-256 of x-device-id)
 * - Returns JSON { data, k } where both are base64(JSON{iv,ct})
 *
 * Also preserves:
 * - /api/create-token and /set-token: write 5-digit short code to KV (key short:{code})
 * - /r2/downloads.json → proxy to R2_BASE_URL + "downloads.json"
 * - root "/" redirects to not-found page per your rule
 */

const R2_BASE_URL = "https://pub-9f5086173bec4bb0bd47f6680eaa4037.r2.dev/"; // you provided
const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/channel-listott.html";
const ROOT_NOTFOUND_REDIRECT = "https://life4u22.blogspot.com/p/not-found.html";
const SIGN_SECRET = "mySuperSecretKey"; // <- Replace with your real secret

addEventListener("fetch", event => {
  event.respondWith(handleEventSafe(event));
});

async function handleEventSafe(event) {
  try {
    return await handleRequest(event.request, event);
  } catch (err) {
    console.error("Unhandled:", err);
    return new Response("Internal Server Error", { status: 500 });
  }
}

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;
  const ua = request.headers.get("User-Agent") || "";
  const lowUA = ua.toLowerCase();

  // === Root redirect rule (must redirect)
  if (path === "/") {
    return Response.redirect(ROOT_NOTFOUND_REDIRECT, 302);
  }

  // === Token management endpoints (preserve per your requirements) ===
  if (path === "/api/create-token" && request.method === "POST") {
    // expected body: JSON { uid, file }  -> create 5-digit code and store in KV as short:{code} -> { uid, file }
    try {
      const body = await request.json();
      const uid = body.uid || "";
      const file = body.file || "";
      const code = gen5DigitsNoZero(); // 5-digit not starting with 0
      const key = `short:${code}`;
      await UID_BINDINGS.put(key, JSON.stringify({ uid, file }));
      return new Response(JSON.stringify({ code }), { headers: { "Content-Type": "application/json" }});
    } catch (e) {
      return new Response("Bad Request", { status: 400 });
    }
  }

  if (path === "/set-token" && request.method === "POST") {
    // allows setting custom code: { code, uid, file }
    try {
      const body = await request.json();
      const code = String(body.code || "").slice(0,5);
      const uid = body.uid || "";
      const file = body.file || "";
      if (!/^\d{3,5}$/.test(code)) return new Response("Invalid code", { status: 400 });
      await UID_BINDINGS.put(`short:${code}`, JSON.stringify({ uid, file }));
      return new Response("OK");
    } catch (e) {
      return new Response("Bad Request", { status: 400 });
    }
  }

  // Proxy downloads.json from R2 if requested
  if (path === "/r2/downloads.json") {
    const target = `${R2_BASE_URL}downloads.json`;
    const resp = await fetch(target);
    return new Response(await resp.text(), { status: resp.status, headers: { "Content-Type": "application/json" }});
  }

  // === UA / crawler blocking ===
  if (
    lowUA.includes("curl") ||
    lowUA.includes("wget") ||
    lowUA.includes("python") ||
    lowUA.includes("postman") ||
    lowUA.includes("httpclient") ||
    lowUA.includes("java") ||
    lowUA.includes("insomnia")
  ) {
    return new Response("Crawler Blocked", { status: 403 });
  }

  // Basic OTT allowance: require Android and OTT-like UA tokens (do not change logic)
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  if (!isAndroid || !appType) {
    return Response.redirect(NON_OTT_REDIRECT_URL, 302);
  }

  // === Parameter checks (uid, exp, sig) - core logic (must be preserved)
  const uid = params.get("uid");
  const exp = Number(params.get("exp") || 0);
  const sig = params.get("sig");
  if (!uid || !exp || !sig) {
    return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });
  }

  // Check expiry (Malaysia/UTC+8 logic as you used earlier)
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp) {
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);
  }

  // Signature verify: HMAC-SHA256 on `${uid}:${exp}` using SIGN_SECRET
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);
  if (!sigValid) {
    return new Response("🚫 Invalid Signature", { status: 403 });
  }

  // === Device fingerprint handling: read from header x-device-id (per your project spec)
  const deviceIdHeader = request.headers.get("x-device-id");
  if (!deviceIdHeader) {
    return new Response("Missing device fingerprint", { status: 401 });
  }
  const deviceFingerprint = deviceIdHeader.trim();

  // === KV read/write: UID_BINDINGS
  const key = `uid:${uid}`;
  let stored = null;
  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    console.error(`KV Read Error ${key}`, e);
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  if (!stored) {
    // First bind
    const toStore = { device: deviceFingerprint, apps: [appType], createdAt: new Date().toISOString() };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} bound to device ${deviceFingerprint}`);
  } else if (stored.device === deviceFingerprint) {
    // same device — ensure appType recorded
    if (!stored.apps.includes(appType)) {
      stored.apps.push(appType);
      await UID_BINDINGS.put(key, JSON.stringify(stored));
      console.log(`🟡 UID ${uid} same device new app ${appType}`);
    } else {
      // normal access
    }
  } else {
    // different physical device — block
    console.log(`🚫 UID ${uid} different device. stored=${stored.device} now=${deviceFingerprint}`);
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // === At this point: authorized. Now handle serving encrypted m3u or passthrough endpoints.

  // If requested path is like /<filename>.m3u or /secured-m3u, serve encrypted m3u
  // We'll accept requests to: /secured-m3u OR any path that ends with .m3u (keep flexible)
  if (path === "/secured-m3u" || path.toLowerCase().endsWith(".m3u")) {
    // Determine file key: if path is /secured-m3u take ?file=..., else use path name
    let objectName = "";
    if (path === "/secured-m3u") {
      objectName = params.get("file") || "pl.m3u"; // default
    } else {
      objectName = path.startsWith("/") ? path.slice(1) : path;
    }
    if (!objectName) return new Response("No playlist specified", { status: 400 });

    // Build full public R2 URL
    const r2Url = R2_BASE_URL + encodeURIComponent(objectName);

    // Fetch the m3u from public R2 (cross-account public)
    const r2resp = await fetch(r2Url);
    if (!r2resp.ok) {
      return new Response("Playlist Not Found in R2", { status: 404 });
    }
    const playlistText = await r2resp.text();

    // === Generate one-time AES-256-GCM key (32 bytes)
    const oneTimeKey = crypto.getRandomValues(new Uint8Array(32));

    // === Encrypt playlistText with oneTimeKey (AES-GCM)
    const encData = await aesGcmEncryptText(playlistText, oneTimeKey);

    // === Derive deviceKey from deviceFingerprint (SHA-256)
    const deviceKeyRaw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceFingerprint));
    const deviceKey = new Uint8Array(deviceKeyRaw).slice(0, 32); // 32 bytes

    // === Encrypt oneTimeKey with deviceKey (AES-GCM)
    const encKeyBlob = await aesGcmEncryptBinary(oneTimeKey, deviceKey);

    // === Optional: store audit / usage in KV (not required, but helpful). We'll store lastAccess
    try {
      const meta = { lastAccess: Date.now(), file: objectName };
      await UID_BINDINGS.put(`${key}:meta`, JSON.stringify(meta), { expirationTtl: 3600 });
    } catch (e) { /* non-fatal */ }

    // === Return JSON
    return new Response(JSON.stringify({
      data: encData,
      k: encKeyBlob
    }), {
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
    });
  }

  // If no other route matched, fallback OK (you can expand as needed)
  return new Response("OK");
}

/* ------------------------
   Helpers
------------------------ */

function gen5DigitsNoZero() {
  // generate 5-digit number between 10000 and 99999 (no leading zero)
  const n = Math.floor(Math.random() * 90000) + 10000;
  return String(n);
}

/* =========================
   Crypto helpers
   - sign: HMAC-SHA256 return hex
   - timingSafeCompare: compare hex safely
   - aesGcmEncryptText -> returns base64(JSON{iv,ct})
   - aesGcmEncryptBinary -> same for Uint8Array input
========================= */

async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBuffer(hex) {
  if (!hex) return new ArrayBuffer(0);
  if (hex.length % 2 !== 0) throw new Error("Invalid hex");
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) arr[i/2] = parseInt(hex.substr(i,2), 16);
  return arr.buffer;
}

async function timingSafeCompare(aHex, bHex) {
  try {
    if (!aHex || !bHex || aHex.length !== bHex.length) return false;
    const a = hexToBuffer(aHex);
    const b = hexToBuffer(bHex);
    // subtle.timingSafeEqual exists in Worker global crypto
    if (crypto.subtle && crypto.subtle.timingSafeEqual) {
      return await crypto.subtle.timingSafeEqual(a, b);
    }
    // fallback
    return aHex === bHex;
  } catch (e) {
    console.error("timingSafeCompare fail:", e);
    return aHex === bHex;
  }
}

async function aesGcmEncryptText(plaintext, keyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  const payload = { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
  return btoa(JSON.stringify(payload));
}

async function aesGcmEncryptBinary(bin, keyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bin);
  const payload = { iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) };
  return btoa(JSON.stringify(payload));
}

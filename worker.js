// ====== 配置区 ======
const R2_BASE_URL = "https://pub-9f5086173bec4bb0bd47f6680eaa4037.r2.dev/"; 
const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/channel-listott.html";
const ROOT_NOTFOUND_REDIRECT = "https://life4u22.blogspot.com/p/not-found.html";
const SIGN_SECRET = "mySuperSecretKey"; // 建议生产环境放入环境变量
const ADMIN_KEY = "powertech_digital";
const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator", "TiviMate", "Televizo"]; // 增加了一些常见播放器
const MAX_TOKENS_PER_DEVICE = 3;

// 注意：请确保在 Cloudflare 后台绑定了以下 KV Namespace：
// 1. UID_BINDINGS
// 2. DEVICE_MAP
// 3. TOKEN_MAP
// =====================

addEventListener("fetch", event => {
  event.respondWith(handleEventSafe(event));
});

// ===== 统一 CORS =====
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-admin-key, x-device-id, x-app-token, User-Agent"
  };
}

async function handleEventSafe(event) {
  try {
    return await handleRequest(event.request, event);
  } catch (err) {
    console.error("Unhandled error:", err);
    return new Response(`Internal Server Error: ${err.message}`, { status: 500, headers: corsHeaders() });
  }
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;
  const ua = request.headers.get("User-Agent") || "";
  const lowUA = ua.toLowerCase();

  // 检查 KV 是否绑定 (防止未绑定导致代码崩溃)
  if (typeof UID_BINDINGS === 'undefined' || typeof DEVICE_MAP === 'undefined' || typeof TOKEN_MAP === 'undefined') {
    return new Response("Server Config Error: KV Namespaces not bound.", { status: 500 });
  }

  // Root redirect
  if (path === "/") return Response.redirect(ROOT_NOTFOUND_REDIRECT, 302);

  // OPTIONS preflight
  if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders() });

  const adminKeyHeader = request.headers.get("x-admin-key");

  // ==== Admin endpoints ====
  if (path.startsWith("/admin/")) {
    if (!adminKeyHeader || adminKeyHeader !== ADMIN_KEY) return new Response("Forbidden", { status: 403, headers: corsHeaders() });

    if (path === "/admin/add-token" && request.method === "POST") {
      try {
        const body = await request.json();
        const deviceId = body.deviceId;
        const token = body.token;
        const app = body.app || "unknown";
        if (!deviceId || !token) return new Response("Bad Request: Missing fields", { status: 400, headers: corsHeaders() });
        await addTokenToDevice(deviceId, token, app);
        return new Response("OK", { headers: corsHeaders() });
      } catch (e) { 
        return new Response("Bad Request: JSON error", { status: 400, headers: corsHeaders() });
      }
    }

    if (path === "/admin/remove-token" && request.method === "POST") {
      try {
        const body = await request.json();
        const token = body.token;
        if (!token) return new Response("Bad Request", { status: 400, headers: corsHeaders() });
        const ok = await removeToken(token);
        return new Response(ok ? "OK" : "NOT FOUND", { headers: corsHeaders() });
      } catch (e) {
        return new Response("Bad Request", { status: 400, headers: corsHeaders() });
      }
    }

    if (path === "/admin/list-device" && request.method === "GET") {
      const deviceId = params.get("deviceId");
      if (!deviceId) return new Response("Bad Request", { status: 400, headers: corsHeaders() });
      const devRaw = await DEVICE_MAP.get(`device:${deviceId}`);
      return new Response(devRaw || "{}", { headers: { "Content-Type": "application/json", ...corsHeaders() } });
    }

    return new Response("Admin endpoint", { status: 200, headers: corsHeaders() });
  }

  // ==== Create Token API (For Short Link) ====
  if (path === "/api/create-token" && request.method === "POST") {
    try {
      const body = await request.json();
      const uid = body.uid || "";
      const file = body.file || "";
      const exp = Number(body.exp) || 0; 
      const code = gen5DigitsNoZero();

      await UID_BINDINGS.put(`short:${code}`, JSON.stringify({ uid, file, exp }));

      return new Response(JSON.stringify({ code }), { headers: { ...corsHeaders(), "Content-Type": "application/json" } });
    } catch (e) {
      console.error("create-token error:", e);
      return new Response("Bad Request", { status: 400, headers: corsHeaders() });
    }
  }

  // ==== Set Token (Manual Bind) ====
  if (path === "/set-token" && request.method === "POST") {
    try {
      const body = await request.json();
      const code = String(body.code || "").slice(0,5);
      const uid = body.uid || "";
      const file = body.file || "";
      if (!/^\d{3,5}$/.test(code)) return new Response("Invalid code", { status: 400, headers: corsHeaders() });
      await UID_BINDINGS.put(`short:${code}`, JSON.stringify({ uid, file }));
      return new Response("OK", { headers: corsHeaders() });
    } catch (e) {
      return new Response("Bad Request", { status: 400, headers: corsHeaders() });
    }
  }

  // ==== R2 M3U proxy (Direct) ====
  if (path === "/r2/pl.m3u") {
    const r2Url = `${R2_BASE_URL}pl.m3u`;
    const r2resp = await fetch(r2Url);
    // 如果 R2 返回 404，我们也返回 404
    if (!r2resp.ok) return new Response("R2 File Not Found", { status: 404, headers: corsHeaders() });
    return new Response(await r2resp.text(), { status: r2resp.status, headers: { "Content-Type": "audio/x-mpegurl", ...corsHeaders() } });
  }

  // ==== Block Crawlers ====
  // 提示：如果在开发调试，建议暂时注释掉这一段
  if (
    lowUA.includes("curl") ||
    lowUA.includes("wget") ||
    lowUA.includes("python") ||
    lowUA.includes("postman") ||
    lowUA.includes("httpclient") ||
    lowUA.includes("java") ||
    lowUA.includes("insomnia")
  ) return new Response("Crawler Blocked", { status: 403, headers: corsHeaders() });

  // ==== Basic OTT UA check ====
  const isAndroid = ua.includes("Android");
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV|GoogleTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);
  
  // 如果你想允许普通浏览器访问来测试，可以暂时注释下面这行
  if (!isAndroid && !isTV && !appType) return Response.redirect(NON_OTT_REDIRECT_URL, 302);

  // ==== Core param checks ====
  const uid = params.get("uid");
  const exp = Number(params.get("exp") || 0);
  const sig = params.get("sig");
  if (!uid || !exp || !sig) return new Response("🚫 Invalid Link: Missing parameters", { status: 403, headers: corsHeaders() });

  // [修复] 时间校验逻辑
  // 1. Date.now() 是 UTC 时间戳。
  // 2. exp 也应该是 UTC 时间戳。
  // 3. 如果需要马来西亚时间显示，仅在前端转换，后端校验建议统一用 UTC。
  const now = Date.now(); 
  if (now > exp) return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // ==== Signature verify ====
  const text = `${uid}:${exp}`;
  // 校验签名
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);
  if (!sigValid) {
    console.log(`Sig Fail: expected=${expectedSig}, got=${sig}`); // 调试日志
    return new Response("🚫 Invalid Signature", { status: 403, headers: corsHeaders() });
  }

  // ==== Device + Token auth ====
  const deviceId = request.headers.get("x-device-id");
  const appToken = request.headers.get("x-app-token");
  if (!deviceId || !appToken) return new Response("Missing device or token headers", { status: 401, headers: corsHeaders() });

  const ok = await verifyDeviceAndToken(deviceId, appToken);
  if (!ok) return new Response("Unauthorized (device/token mismatch)", { status: 403, headers: corsHeaders() });

  // ==== UID_BINDINGS logic ====
  const key = `uid:${uid}`;
  let stored = null;
  try { 
    stored = await UID_BINDINGS.get(key, { type: "json" }); // 显式声明类型更安全
  } catch (e) { 
    console.error("KV Read Error", e); 
    // [修复] 这里之前缺少括号 ()
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503, headers: corsHeaders() }); 
  }

  const finalAppType = appType || "Generic-OTT";

  if (!stored) {
    const toStore = { device: deviceId, apps: [finalAppType], createdAt: new Date().toISOString() };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} first bind ${deviceId}, app=${finalAppType}`);
  } else if (stored.device === deviceId) {
    if (!stored.apps.includes(finalAppType)) {
      stored.apps.push(finalAppType);
      await UID_BINDINGS.put(key, JSON.stringify(stored));
      console.log(`🟡 UID ${uid} same device new app ${finalAppType}`);
    }
  } else {
    console.log(`🚫 UID ${uid} different device login (stored=${stored.device} now=${deviceId})`);
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // ==== Serve encrypted m3u ====
  if (path === "/secured-m3u" || path.toLowerCase().endsWith(".m3u")) {
    let objectName = "";
    if (path === "/secured-m3u") objectName = params.get("file") || "pl.m3u";
    else objectName = path.startsWith("/") ? path.slice(1) : path;
    
    if (!objectName) return new Response("No playlist specified", { status: 400, headers: corsHeaders() });

    const r2Url = R2_BASE_URL + encodeURIComponent(objectName);
    const r2resp = await fetch(r2Url);
    if (!r2resp.ok) return new Response("Playlist Not Found in R2", { status: 404, headers: corsHeaders() });
    
    const playlistText = await r2resp.text();

    // Encryption Logic
    const oneTimeKey = crypto.getRandomValues(new Uint8Array(32)); // 生成随机密钥
    const encData = await aesGcmEncryptText(playlistText, oneTimeKey); // 用随机密钥加密内容
    
    // Derive Key from Device ID
    const deviceKeyRaw = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(deviceId));
    const deviceKey = new Uint8Array(deviceKeyRaw).slice(0,32);
    
    // Encrypt the Random Key with Device Key
    const encKeyBlob = await aesGcmEncryptBinary(oneTimeKey, deviceKey);

    // Update Metadata (Optional)
    try { await UID_BINDINGS.put(`${key}:meta`, JSON.stringify({ lastAccess: Date.now(), file: objectName }), { expirationTtl: 3600 }); } catch (e) {}

    return new Response(JSON.stringify({ data: encData, k: encKeyBlob }), {
      headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...corsHeaders() }
    });
  }

  return new Response("OK", { headers: corsHeaders() });
}

/* =========================
   Device & Token helpers
========================= */
async function verifyDeviceAndToken(deviceId, token) {
  try {
    const devRaw = await DEVICE_MAP.get(`device:${deviceId}`);
    if (!devRaw) return false;
    const dev = JSON.parse(devRaw);
    if (!Array.isArray(dev.tokens)) return false;
    return dev.tokens.includes(token);
  } catch (e) {
    console.error("verifyDeviceAndToken error:", e);
    return false;
  }
}

async function addTokenToDevice(deviceId, token, appName) {
  await TOKEN_MAP.put(`token:${token}`, JSON.stringify({ device_id: deviceId, app: appName, created: Date.now() }));
  let dev = null;
  try {
    const devRaw = await DEVICE_MAP.get(`device:${deviceId}`);
    dev = devRaw ? JSON.parse(devRaw) : { device_uid: deviceId, tokens: [], last_seen: Date.now() };
  } catch (e) {
    dev = { device_uid: deviceId, tokens: [], last_seen: Date.now() };
  }
  if (!Array.isArray(dev.tokens)) dev.tokens = [];
  if (!dev.tokens.includes(token)) dev.tokens.push(token);
  if (dev.tokens.length > MAX_TOKENS_PER_DEVICE) dev.tokens = dev.tokens.slice(-MAX_TOKENS_PER_DEVICE);
  dev.last_seen = Date.now();
  await DEVICE_MAP.put(`device:${deviceId}`, JSON.stringify(dev));
}

async function removeToken(token) {
  try {
    const tRaw = await TOKEN_MAP.get(`token:${token}`);
    if (!tRaw) return false;
    const tObj = JSON.parse(tRaw);
    const deviceId = tObj.device_id;
    await TOKEN_MAP.delete(`token:${token}`);
    const devRaw = await DEVICE_MAP.get(`device:${deviceId}`);
    if (devRaw) {
      const dev = JSON.parse(devRaw);
      dev.tokens = (dev.tokens || []).filter(t => t !== token);
      await DEVICE_MAP.put(`device:${deviceId}`, JSON.stringify(dev));
    }
    return true;
  } catch (e) {
    console.error("removeToken error:", e);
    return false;
  }
}

/* =========================
   Crypto helpers
========================= */
function gen5DigitsNoZero() {
  let digits = "";
  for (let i = 0; i < 5; i++) digits += Math.floor(Math.random() * 9) + 1;
  return digits;
}

async function sign(text, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2,"0")).join("");
}

function hexToBuffer(hex) {
  if (!hex || typeof hex !== 'string') return new ArrayBuffer(0);
  if (hex.length % 2 !== 0) return new ArrayBuffer(0); // 安全起见，非法hex返回空buffer
  const arr = new Uint8Array(hex.length/2);
  for (let i = 0; i < hex.length; i+=2) arr[i/2] = parseInt(hex.substr(i,2), 16);
  return arr.buffer;
}

async function timingSafeCompare(aHex, bHex) {
  try {
    if (!aHex || !bHex) return false;
    const a = hexToBuffer(aHex);
    const b = hexToBuffer(bHex);
    // Cloudflare Workers 支持 crypto.subtle.timingSafeEqual
    // 只有长度相等时才能比较，否则抛出错误
    if (a.byteLength !== b.byteLength) return false; 
    
    return await crypto.subtle.timingSafeEqual(a, b);
  } catch (e) {
    console.error("timingSafeCompare error:", e);
    // 如果出错，回退到普通比较（虽然不防时序攻击，但保证不崩溃）
    // 或者直接返回 false
    return aHex === bHex;
  }
}

async function aesGcmEncryptText(plaintext, keyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plaintext));
  // 使用 JSON.stringify 保证是字符串
  return btoa(JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) }));
}

async function aesGcmEncryptBinary(bin, keyBytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, bin);
  return btoa(JSON.stringify({ iv: Array.from(iv), ct: Array.from(new Uint8Array(ct)) }));
}

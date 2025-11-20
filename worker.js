// ====== 配置区 ======
const R2_BASE_URL = "https://pub-9f5086173bec4bb0bd47f6680eaa4037.r2.dev/"; 
const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/channel-listott.html";
const ROOT_NOTFOUND_REDIRECT = "https://life4u22.blogspot.com/p/not-found.html";
const SIGN_SECRET = "mySuperSecretKey";
const ADMIN_KEY = "powertech_digital";
const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
const MAX_TOKENS_PER_DEVICE = 3;
// =====================

addEventListener("fetch", event => {
  event.respondWith(handleEventSafe(event));
});

// ===== 统一 CORS =====
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, x-admin-key, x-device-id, x-app-token"
  };
}

async function handleEventSafe(event) {
  try {
    return await handleRequest(event.request, event);
  } catch (err) {
    console.error("Unhandled error:", err);
    return new Response("Internal Server Error", { status: 500, headers: corsHeaders() });
  }
}

async function handleRequest(request, event) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;
  const ua = request.headers.get("User-Agent") || "";
  const lowUA = ua.toLowerCase();

  // Root redirect
  if (path === "/") return Response.redirect(ROOT_NOTFOUND_REDIRECT, 302);

  // OPTIONS preflight
  if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders() });

  // ==== Admin endpoints ====
  if (path.startsWith("/admin/")) {
    const adminKeyHeader = request.headers.get("x-admin-key");
    if (!adminKeyHeader || adminKeyHeader !== ADMIN_KEY) return new Response("Forbidden", { status: 403, headers: corsHeaders() });

    if (path === "/admin/add-token" && request.method === "POST") {
      try {
        const body = await request.json();
        const deviceId = body.deviceId;
        const token = body.token;
        const app = body.app || "unknown";
        if (!deviceId || !token) return new Response("Bad Request", { status: 400, headers: corsHeaders() });
        await addTokenToDevice(deviceId, token, app);
        return new Response("OK", { headers: corsHeaders() });
      } catch (e) { 
        return new Response("Bad Request", { status: 400, headers: corsHeaders() });
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

  if (path === "/api/create-token") {
  const corsHeaders = handleCors(request);
  if (request.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  try {
    const body = await request.json();
    const uid = body.uid || "";
    const file = body.file || "";
    const exp = Number(body.exp) || 0; 
    const code = gen5DigitsNoZero();

    await UID_BINDINGS.put(`short:${code}`, JSON.stringify({ uid, file, exp }));

    return new Response(JSON.stringify({ code }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  } catch (e) {
    console.error("create-token error:", e);
    return new Response("Bad Request", { status: 400, headers: corsHeaders });
  }
}

  // ==== /set-token ====
  if (path === "/set-token") {
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

  // ==== R2 M3U proxy ====
  if (path === "/r2/pl.m3u") {
    const r2Url = `${R2_BASE_URL}pl.m3u`;
    const r2resp = await fetch(r2Url);
    return new Response(await r2resp.text(), { status: r2resp.status, headers: { "Content-Type": "audio/x-mpegurl", ...corsHeaders() } });
  }

  // ... 后面逻辑保持不变，所有 new Response() 都加上 ...corsHeaders()
                        }

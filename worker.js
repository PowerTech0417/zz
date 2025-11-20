addEventListener("fetch", event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const params = url.searchParams;

  // === ⚙️ 配置区 ===
  const GITHUB_PAGES_URL = "https://modskyshop168-sudo.github.io/cc/";
  const EXPIRED_REDIRECT_URL = "https://life4u22.blogspot.com/p/powertech.html";
  const DEVICE_CONFLICT_URL = "https://life4u22.blogspot.com/p/id-ban.html";
  const NON_OTT_REDIRECT_URL = "https://life4u22.blogspot.com/p/channel-listott.html";
  const SIGN_SECRET = "mySuperSecretKey"; 
  const OTT_KEYWORDS = ["OTT Player", "OTT TV", "OTT Navigator"];
  // =================

  const ua = request.headers.get("User-Agent") || "";
  const isAndroid = ua.includes("Android");
  // 匹配 TV 或 TV Box 相关的 User-Agent 关键词
  const isTV = /TV|AFT|MiBOX|SmartTV|BRAVIA|SHIELD|AndroidTV/i.test(ua);
  const appType = OTT_KEYWORDS.find(k => ua.includes(k)) || (isTV ? "OTT-TV-Unknown" : null);

  // ❌ 非 OTT 设备/非 Android 
  if (!isAndroid || !appType) return Response.redirect(NON_OTT_REDIRECT_URL, 302);

  // 参数验证
  const uid = params.get("uid");
  const exp = Number(params.get("exp"));
  const sig = params.get("sig");
  if (!uid || !exp || !sig)
    return new Response("🚫 Invalid Link: Missing parameters", { status: 403 });

  // 检查过期时间（马来西亚时区：UTC+8）
  const malaysiaNow = Date.now() + 8 * 60 * 60 * 1000;
  if (malaysiaNow > exp)
    return Response.redirect(EXPIRED_REDIRECT_URL, 302);

  // 签名验证
  const text = `${uid}:${exp}`;
  const expectedSig = await sign(text, SIGN_SECRET);
  const sigValid = await timingSafeCompare(expectedSig, sig);

  if (!sigValid)
    return new Response("🚫 Invalid Signature", { status: 403 });

  // 📱 设备指纹（不含 IP 和 appType，代表物理设备）
  const deviceFingerprint = await getDeviceFingerprint(ua, uid, SIGN_SECRET);

  // 读取 KV 数据
  const key = `uid:${uid}`;
  let stored = null;
  
  try {
    stored = await UID_BINDINGS.get(key, "json");
  } catch (e) {
    console.error(`KV Read/Parse Error for ${key}:`, e);
    return new Response("Service temporarily unavailable. (K-Err)", { status: 503 });
  }

  // 首次登入
  if (!stored) {
    const toStore = { device: deviceFingerprint, apps: [appType], createdAt: new Date().toISOString() };
    await UID_BINDINGS.put(key, JSON.stringify(toStore));
    console.log(`✅ UID ${uid} 首次绑定 ${deviceFingerprint}, app=${appType}`);
  } 
  // 同物理设备
  else if (stored.device === deviceFingerprint) {
    // 检查当前 appType 是否已记录
    if (!stored.apps.includes(appType)) {
      // 如果是新的 OTT 应用，则添加到列表中并更新 KV
      stored.apps.push(appType);
      await UID_BINDINGS.put(key, JSON.stringify(stored));
      console.log(`🟡 UID ${uid} 同设备使用新应用，新增 ${appType}`);
    } else {
      console.log(`🟩 UID ${uid} 同设备访问 ${appType}`);
    }
  } 
  // 不同设备 → 封锁
  else {
    console.log(`🚫 UID ${uid} 不同设备登入`);
    return Response.redirect(DEVICE_CONFLICT_URL, 302);
  }

  // ✅ 正常访问
  return fetch(`${GITHUB_PAGES_URL}${path}${url.search}`, request);
}

// 辅助函数：将十六进制字符串转换为 ArrayBuffer
function hexToBuffer(hex) {
    if (hex.length % 2 !== 0) {
        throw new Error("Invalid hex string length");
    }
    const arr = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        arr[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return arr.buffer;
}

/** 🔑 使用 timingSafeEqual 进行时间安全比较 */
async function timingSafeCompare(aHex, bHex) {
    try {
        if (aHex.length !== bHex.length) {
            return false;
        }
        const a = hexToBuffer(aHex);
        const b = hexToBuffer(bHex);
        
        return await crypto.subtle.timingSafeEqual(a, b);
    } catch (e) {
        console.error("Timing safe comparison failed, falling back:", e);
        return aHex === bHex;
    }
}

/** 🔐 生成签名 */
async function sign(text, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  
  // 返回十六进制字符串
  return Array.from(new Uint8Array(signature))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

/** 📱 设备指纹（不含 IP 和 appType，代表物理设备）*/
async function getDeviceFingerprint(ua, uid, secret) {
  const cleanUA = ua.replace(/\s+/g, " ").trim().slice(0, 120);
  // 仅依赖 uid 和清理后的 UA
  const base = `${uid}:${cleanUA}`;
  return await sign(base, secret);
}

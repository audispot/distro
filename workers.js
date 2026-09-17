// Base32 / TOTP helpers used by the 2FA endpoints.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(bytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(input) {
  const clean = String(input || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const output = [];
  for (const char of clean) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

function normalizeTotpCode(value) {
  const code = String(value || "").replace(/\s/g, "");
  return /^\d{6}$/.test(code) ? code : null;
}

async function generateTotpCode(secret, counter) {
  const keyBytes = base32Decode(secret);
  const counterBytes = new ArrayBuffer(8);
  const view = new DataView(counterBytes);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, counterBytes));
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, "0");
}

async function verifyTotpCode(secret, suppliedCode, window = 1) {
  if (!secret || !/^\d{6}$/.test(String(suppliedCode || ""))) return false;
  const currentCounter = Math.floor(Date.now() / 1000 / 30);
  for (let offset = -window; offset <= window; offset++) {
    const expected = await generateTotpCode(secret, currentCounter + offset);
    if (expected === String(suppliedCode)) return true;
  }
  return false;
}

function getClientIp(request) {
  return request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown";
}

function getClientDevice(userAgent) {
  const ua = String(userAgent || "");
  if (/iPhone|iPad|Android|Mobile/i.test(ua)) return "Mobile Browser";
  if (/Windows/i.test(ua)) return "Chrome/Windows";
  if (/Macintosh|Mac OS/i.test(ua)) return "Browser/macOS";
  if (/Linux/i.test(ua)) return "Browser/Linux";
  return "Web Browser";
}

function getClientLocation(request) {
  const city = request.cf?.city;
  const country = request.cf?.country;
  if (city && country) return `${city}, ${country}`;
  if (country) return country;
  return "Unknown";
}

async function recordLoginSession(env, userId, request) {
  if (!env.AUDIORY_KV || !userId) return null;
  const key = `SESSIONS_USER_${userId}`;
  const raw = await env.AUDIORY_KV.get(key);
  const sessions = raw ? JSON.parse(raw) : [];
  const now = new Date().toISOString();
  const session = {
    id: `sess_${crypto.randomUUID()}`,
    loginAt: now,
    lastActiveAt: now,
    logoutAt: null,
    lastLoggedInAt: now,
    device: getClientDevice(request.headers.get("user-agent")),
    userAgent: request.headers.get("user-agent") || "Unknown",
    ip: getClientIp(request),
    location: getClientLocation(request),
    isCurrent: true,
    revoked: false
  };
  for (const item of sessions) item.isCurrent = false;
  sessions.unshift(session);
  await env.AUDIORY_KV.put(key, JSON.stringify(sessions.slice(0, 25)));
  return session;
}

// Module-level in-memory cache across Worker isolate invocations
let cachedAccessToken = null;
let tokenExpiresAt = 0;
let activeRefreshToken = null;

// Helper: Simple JWT decoder to extract 'uid' or 'user_id' from Firebase / Auth Bearer token
function parseUserIdFromToken(request) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.split("Bearer ")[1].trim();
  try {
    const payloadBase64 = token.split(".")[1];
    if (!payloadBase64) return null;
    
    // Normalize base64 URL encoding and padding
    let base64 = payloadBase64.replace(/-/g, "+").replace(/_/g, "/");
    while (base64.length % 4) {
      base64 += "=";
    }

    const decodedJson = atob(base64);
    const payload = JSON.parse(decodedJson);
    return payload.user_id || payload.uid || payload.sub || null;
  } catch (e) {
    return null;
  }
}

// ============================================================================
// HELPER: HTML LANDING PAGE GENERATOR
// ============================================================================
function renderArtistLandingPage(data) {
  const title = data.title || 'Listen Now';
  const cover = data.coverUrl || 'https://placehold.co/600x600/1e293b/00f2fe?text=Music';
  const platforms = data.platforms || {};

  const dspConfig = [
    { key: 'spotify', label: 'Spotify', icon: 'fa-brands fa-spotify', color: '#1DB954' },
    { key: 'apple', label: 'Apple Music', icon: 'fa-brands fa-apple', color: '#FA243C' },
    { key: 'youtube', label: 'YouTube Music', icon: 'fa-brands fa-youtube', color: '#FF0000' },
    { key: 'deezer', label: 'Deezer', icon: 'fa-brands fa-deezer', color: '#A238FF' },
    { key: 'tidal', label: 'Tidal', icon: 'fa-solid fa-compact-disc', color: '#00FFFF' },
    { key: 'amazon', label: 'Amazon Music', icon: 'fa-brands fa-amazon', color: '#FF9900' }
  ];

  const buttonsHtml = dspConfig
    .filter(dsp => platforms[dsp.key] && platforms[dsp.key].trim() !== '')
    .map(dsp => `
      <a href="${platforms[dsp.key]}" target="_blank" rel="noopener noreferrer" 
         class="flex items-center justify-between p-3.5 rounded-xl bg-white/10 hover:bg-white/20 backdrop-blur-md border border-white/10 transition group">
        <div class="flex items-center gap-3">
          <i class="${dsp.icon} text-xl" style="color: ${dsp.color}"></i>
          <span class="text-sm font-semibold text-white">${dsp.label}</span>
        </div>
        <span class="px-3 py-1 text-xs font-bold bg-[#00f2fe] text-black rounded-lg group-hover:scale-105 transition">Play</span>
      </a>
    `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} | Audiory</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f17; font-family: system-ui, -apple-system, sans-serif; }
  </style>
</head>
<body class="min-h-screen text-white flex flex-col items-center justify-center p-4 relative overflow-x-hidden">
  <!-- Blurred Background Glow -->
  <div class="absolute inset-0 bg-cover bg-center opacity-20 blur-3xl pointer-events-none" style="background-image: url('${cover}');"></div>

  <main class="w-full max-w-sm mx-auto relative z-10 flex flex-col items-center space-y-6 my-8">
    <!-- Album Cover -->
    <div class="w-64 h-64 sm:w-72 sm:h-72 rounded-2xl overflow-hidden shadow-2xl border border-white/10 bg-black/40">
      <img src="${cover}" alt="${title}" class="w-full h-full object-cover">
    </div>

    <!-- Title Header -->
    <div class="text-center space-y-1">
      <h1 class="text-xl font-bold tracking-tight text-white">${title}</h1>
      <p class="text-xs text-gray-400">Select your preferred streaming platform</p>
    </div>

    <!-- Platform Links -->
    <div class="w-full space-y-2.5">
      ${buttonsHtml || '<p class="text-center text-xs text-gray-500">No active store links available.</p>'}
    </div>

    <!-- Branding -->
    <footer class="pt-4 text-center">
      <p class="text-[10px] text-gray-500 uppercase tracking-widest">Powered by <span class="text-[#00f2fe] font-semibold">Audiory</span></p>
    </footer>
  </main>
</body>
</html>`;
}

async function getAccessToken(env, forceRefresh = false) {
  if (!env) {
    throw new Error("Cloudflare env object was not passed into getAccessToken(env).");
  }

  // 1. Check Cloudflare KV for an active access token
  if (!forceRefresh && env.AUDIORY_KV) {
    const kvAccessToken = await env.AUDIORY_KV.get("TOO_LOST_ACCESS_TOKEN");
    if (kvAccessToken) return kvAccessToken;
  }

  const tokenUrl = env.TOO_LOST_TOKEN_URL || "https://sandbox.toolost.com/oauth/token";
  const clientId = env.TOO_LOST_CLIENT_ID || "a2786dc1-c223-4063-8c65-f50cbc0f8210";
  const clientSecret = env.TOO_LOST_CLIENT_SECRET || "feNwLnJYreL3KhFbusQ0qRM1FqI4YEfMT7xgf4Jb";

  // 2. Read refresh token from KV first, then env
  let refreshToken = null;
  if (env.AUDIORY_KV) {
    refreshToken = await env.AUDIORY_KV.get("TOO_LOST_REFRESH_TOKEN");
  }
  if (!refreshToken) {
    refreshToken = env.TOO_LOST_REFRESH_TOKEN;
  }

  let tokenData = null;

  // 3. ATTEMPT 1: Refresh Token Flow
  if (refreshToken) {
    try {
      const tokenRes = await fetch(tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept": "application/json"
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          client_id: clientId,
          client_secret: clientSecret,
          refresh_token: refreshToken
        })
      });

      const tokenText = await tokenRes.text();
      try { tokenData = JSON.parse(tokenText); } catch { tokenData = { raw: tokenText }; }

      if (!tokenRes.ok || !tokenData.access_token) {
        if (env.AUDIORY_KV) await env.AUDIORY_KV.delete("TOO_LOST_REFRESH_TOKEN");
        tokenData = null;
      }
    } catch (e) {
      tokenData = null;
    }
  }

  // 4. ATTEMPT 2: Client Credentials Fallback
  if (!tokenData || !tokenData.access_token) {
    const fallbackRes = await fetch(tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
      },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret
      })
    });

    const fallbackText = await fallbackRes.text();
    try { tokenData = JSON.parse(fallbackText); } catch { tokenData = { raw: fallbackText }; }

    if (!fallbackRes.ok || !tokenData.access_token) {
      throw new Error(`Too Lost Auth Failed Completely: ${JSON.stringify(tokenData)}`);
    }
  }

  // 5. Store active tokens in KV
  if (env.AUDIORY_KV && tokenData.access_token) {
    const ttl = Math.max((tokenData.expires_in || 3600) - 60, 60);
    await env.AUDIORY_KV.put("TOO_LOST_ACCESS_TOKEN", tokenData.access_token, { expirationTtl: ttl });

    if (tokenData.refresh_token) {
      await env.AUDIORY_KV.put("TOO_LOST_REFRESH_TOKEN", tokenData.refresh_token);
    }
  }

  return tokenData.access_token;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;
    const path = url.pathname;

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Custom-Auth",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const userId = parseUserIdFromToken(request);

      // ------------------------------------------------------------------------
      // 1. PUBLIC LANDING PAGE ROUTER: GET /s/:slug
      // Renders the artist's smart link landing page directly in browser
      // ------------------------------------------------------------------------
      if (method === 'GET' && path.startsWith('/s/')) {
        const slug = path.replace('/s/', '').trim();
        if (!slug) {
          return new Response('Invalid Link', { status: 400 });
        }

        // Fetch stored smart link JSON from AUDIORY_KV
        const rawData = await env.AUDIORY_KV.get(`smartlink:${slug}`);
        if (!rawData) {
          return new Response('Smart Link Not Found', { status: 404 });
        }

        const smartLink = JSON.parse(rawData);

        // Increment click count asynchronously in KV
        if (ctx && typeof ctx.waitUntil === 'function') {
          ctx.waitUntil(
            (async () => {
              smartLink.clicks = (smartLink.clicks || 0) + 1;
              await env.AUDIORY_KV.put(`smartlink:${slug}`, JSON.stringify(smartLink));
              if (smartLink.id) {
                await env.AUDIORY_KV.put(`smartlink_meta:${smartLink.id}`, JSON.stringify(smartLink));
              }
            })()
          );
        } else {
          smartLink.clicks = (smartLink.clicks || 0) + 1;
          await env.AUDIORY_KV.put(`smartlink:${slug}`, JSON.stringify(smartLink));
          if (smartLink.id) {
            await env.AUDIORY_KV.put(`smartlink_meta:${smartLink.id}`, JSON.stringify(smartLink));
          }
        }

        // Return standalone HTML Landing Page
        return new Response(renderArtistLandingPage(smartLink), {
          headers: { 'Content-Type': 'text/html;charset=UTF-8' }
        });
      }

      // ------------------------------------------------------------------------
      // 2. API ENDPOINTS FOR SMART LINKS MANAGEMENT
      // ------------------------------------------------------------------------

      // A. POST /api/smart-links/scan - Auto-Detect Platform Links
      if (method === 'POST' && path === '/api/smart-links/scan') {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        }

        const body = await request.json().catch(() => ({}));
        const { releaseId } = body;

        // Extract release details from KV or database
        const rawRelease = await env.AUDIORY_KV.get(`release:${releaseId}`);
        let platforms = { spotify: '', apple: '', deezer: '', youtube: '', tidal: '', amazon: '' };

        if (rawRelease) {
          const release = JSON.parse(rawRelease);
          // Pre-fill existing DSP URLs or UPC-based lookup
          if (release.spotifyUrl) platforms.spotify = release.spotifyUrl;
          if (release.appleUrl) platforms.apple = release.appleUrl;
        }

        return new Response(JSON.stringify({ success: true, platforms }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // B. POST /api/smart-links - Save/Update Smart Link in AUDIORY_KV
      if (method === 'POST' && path === '/api/smart-links') {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        }

        const body = await request.json().catch(() => ({}));
        const { releaseId, title, slug, coverUrl, platforms } = body;

        if (!slug || !title) {
          return new Response(JSON.stringify({ error: 'Missing title or slug' }), { status: 400, headers: corsHeaders });
        }

        const linkId = body.id || `sl_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
        const shortUrl = `https://links.audiory.site/s/${slug}`;

        // Retrieve existing clicks if updating
        const existingRaw = await env.AUDIORY_KV.get(`smartlink:${slug}`);
        const existing = existingRaw ? JSON.parse(existingRaw) : {};

        const record = {
          id: linkId,
          userId: userId,
          releaseId: releaseId || null,
          title,
          slug,
          coverUrl: coverUrl || '',
          shortUrl,
          platforms: platforms || {},
          clicks: existing.clicks || 0,
          active: true,
          createdAt: existing.createdAt || new Date().toISOString(),
          updatedAt: new Date().toISOString()
        };

        // Store in KV under slug key AND user catalog index
        await env.AUDIORY_KV.put(`smartlink:${slug}`, JSON.stringify(record));
        await env.AUDIORY_KV.put(`smartlink_meta:${linkId}`, JSON.stringify(record));

        // Append to User's list index
        const userIndexKey = `user_smartlinks:${userId}`;
        const userListRaw = await env.AUDIORY_KV.get(userIndexKey);
        let userList = userListRaw ? JSON.parse(userListRaw) : [];

        if (!userList.includes(linkId)) {
          userList.push(linkId);
          await env.AUDIORY_KV.put(userIndexKey, JSON.stringify(userList));
        }

        return new Response(JSON.stringify({ success: true, link: record }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          status: 201
        });
      }

      // C. GET /api/smart-links - Fetch User's Smart Links
      if (method === 'GET' && path === '/api/smart-links') {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        }

        const userIndexKey = `user_smartlinks:${userId}`;
        const userListRaw = await env.AUDIORY_KV.get(userIndexKey);
        const userList = userListRaw ? JSON.parse(userListRaw) : [];

        const results = [];
        for (const id of userList) {
          const itemRaw = await env.AUDIORY_KV.get(`smartlink_meta:${id}`);
          if (itemRaw) {
            results.push(JSON.parse(itemRaw));
          }
        }

        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // D. DELETE /api/smart-links/:id - Delete Smart Link
      if (method === 'DELETE' && path.startsWith('/api/smart-links/')) {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: corsHeaders });
        }

        const linkId = path.replace('/api/smart-links/', '').trim();

        const itemRaw = await env.AUDIORY_KV.get(`smartlink_meta:${linkId}`);
        if (itemRaw) {
          const item = JSON.parse(itemRaw);
          if (item.userId === userId) {
            // Remove main KV keys
            await env.AUDIORY_KV.delete(`smartlink:${item.slug}`);
            await env.AUDIORY_KV.delete(`smartlink_meta:${linkId}`);

            // Remove from user index
            const userIndexKey = `user_smartlinks:${userId}`;
            const userListRaw = await env.AUDIORY_KV.get(userIndexKey);
            let userList = userListRaw ? JSON.parse(userListRaw) : [];
            userList = userList.filter(id => id !== linkId);
            await env.AUDIORY_KV.put(userIndexKey, JSON.stringify(userList));
          }
        }

        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' }
        });
      }

      // =============================================================
      // PILLAR: AUTHENTICATION & SECURITY (Change Password & 2FA)
      // =============================================================

      // NOTE: Firebase remains the source of truth for the user's password.
      // This endpoint verifies the old password through Firebase Identity Toolkit
      // and then changes it. Set FIREBASE_WEB_API_KEY in Worker secrets.
      // Change password endpoint
      if (url.pathname === "/api/auth/change-password" && request.method === "POST") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const body = await request.json().catch(() => ({}));
        const { currentPassword, newPassword } = body;

        if (!currentPassword || !newPassword) {
          return new Response(JSON.stringify({ error: "Current password and new password are required." }), {
            status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (String(newPassword).length < 8) {
          return new Response(JSON.stringify({ error: "New password must be at least 8 characters long." }), {
            status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (!env.FIREBASE_WEB_API_KEY) {
          return new Response(JSON.stringify({ error: "FIREBASE_WEB_API_KEY is not configured on the Worker." }), {
            status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // Extract email from Authorization Bearer token payload
        const authHeader = request.headers.get("Authorization") || "";
        const firebaseToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
        let email = null;

        try {
          const parts = firebaseToken.split(".");
          if (parts.length >= 2) {
            let b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
            while (b64.length % 4) b64 += "=";
            const payload = JSON.parse(atob(b64));
            email = payload.email || null;
          }
        } catch (_) {}

        if (!email) {
          return new Response(JSON.stringify({ error: "The authenticated Firebase token does not contain an email address." }), {
            status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // 1. Verify old password
        const verifyRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password: currentPassword, returnSecureToken: true })
        });

        const verifyData = await verifyRes.json().catch(() => ({}));
        if (!verifyRes.ok || !verifyData.idToken) {
          return new Response(JSON.stringify({ error: "Current password is incorrect." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // 2. Update to new password (returnSecureToken MUST be true)
        const updateRes = await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:update?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ idToken: verifyData.idToken, password: newPassword, returnSecureToken: true })
        });

        const updateData = await updateRes.json().catch(() => ({}));
        if (!updateRes.ok) {
          return new Response(JSON.stringify({ error: updateData?.error?.message || "Unable to update password." }), {
            status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (env.AUDIORY_KV) {
          await env.AUDIORY_KV.put(`PASSWORD_UPDATED_USER_${userId}`, JSON.stringify({ updatedAt: new Date().toISOString() }));
        }

        return new Response(JSON.stringify({ success: true, message: "Password updated successfully." }), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // -------------------------
      // TWO-FACTOR AUTHENTICATION
      // -------------------------
      if (url.pathname.startsWith("/api/auth/2fa")) {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const kv2FAKey = `2FA_USER_${userId}`;

        if (url.pathname === "/api/auth/2fa/status" && request.method === "GET") {
          let state = { is_2fa_enabled: false, method: null, createdAt: null, updatedAt: null };
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kv2FAKey);
            if (raw) {
              const parsed = JSON.parse(raw);
              state = {
                is_2fa_enabled: parsed.is_2fa_enabled === true,
                method: parsed.method || null,
                createdAt: parsed.createdAt || null,
                updatedAt: parsed.updatedAt || null
              };
            }
          }
          return new Response(JSON.stringify(state), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        if (url.pathname === "/api/auth/2fa/setup" && request.method === "POST") {
          // Generate a proper 160-bit Base32 TOTP secret.
          const bytes = new Uint8Array(20);
          crypto.getRandomValues(bytes);
          const secret = base32Encode(bytes);
          const label = encodeURIComponent(`Audiory:${userId}`);
          const issuer = encodeURIComponent("Audiory");
          const qrCodeUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

          const recoveryCodes = Array.from({ length: 8 }, () =>
            crypto.randomUUID().replace(/-/g, "").substring(0, 10).toUpperCase()
          );

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(
              `2FA_TEMP_SECRET_${userId}`,
              JSON.stringify({ secret, recoveryCodes, createdAt: new Date().toISOString() }),
              { expirationTtl: 600 }
            );
          }

          return new Response(JSON.stringify({ success: true, secret, qrCodeUrl, recoveryCodes }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // Verify the code during setup. A six-digit code is NOT accepted merely
        // because it has six digits; it must match the TOTP generated by the authenticator.
        if (url.pathname === "/api/auth/2fa/verify" && request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const code = normalizeTotpCode(body.code);
          if (!code) {
            return new Response(JSON.stringify({ error: "Invalid 6-digit verification code." }), {
              status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          if (!env.AUDIORY_KV) {
            return new Response(JSON.stringify({ error: "AUDIORY_KV is required for 2FA." }), {
              status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const rawTemp = await env.AUDIORY_KV.get(`2FA_TEMP_SECRET_${userId}`);
          if (!rawTemp) {
            return new Response(JSON.stringify({ error: "Setup session expired. Please start 2FA setup again." }), {
              status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const parsedTemp = JSON.parse(rawTemp);
          const valid = await verifyTotpCode(parsedTemp.secret, code);
          if (!valid) {
            return new Response(JSON.stringify({ error: "Incorrect authenticator code." }), {
              status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const record = {
            is_2fa_enabled: true,
            totp_secret: parsedTemp.secret,
            recovery_codes: parsedTemp.recoveryCodes || [],
            method: "authenticator",
            createdAt: parsedTemp.createdAt || new Date().toISOString(),
            updatedAt: new Date().toISOString()
          };

          await env.AUDIORY_KV.put(kv2FAKey, JSON.stringify(record));
          await env.AUDIORY_KV.delete(`2FA_TEMP_SECRET_${userId}`);

          return new Response(JSON.stringify({
            success: true,
            message: "Two-Factor Authentication enabled securely.",
            is_2fa_enabled: true,
            recovery_codes: record.recovery_codes
          }), { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // Verify 2FA after Firebase login. The frontend should call this endpoint
        // immediately after Firebase sign-in when 2FA is enabled.
        if (url.pathname === "/api/auth/2fa/challenge" && request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const code = normalizeTotpCode(body.code);
          const recoveryCode = String(body.recoveryCode || "").trim().toUpperCase();
          const raw = env.AUDIORY_KV ? await env.AUDIORY_KV.get(kv2FAKey) : null;
          const record = raw ? JSON.parse(raw) : null;

          if (!record?.is_2fa_enabled) {
            return new Response(JSON.stringify({ success: true, required: false, verified: true }), {
              status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          let verified = false;
          if (code) verified = await verifyTotpCode(record.totp_secret, code);

          if (!verified && recoveryCode) {
            const codes = Array.isArray(record.recovery_codes) ? record.recovery_codes : [];
            const index = codes.indexOf(recoveryCode);
            if (index !== -1) {
              codes.splice(index, 1); // recovery codes are single-use
              record.recovery_codes = codes;
              record.updatedAt = new Date().toISOString();
              await env.AUDIORY_KV.put(kv2FAKey, JSON.stringify(record));
              verified = true;
            }
          }

          if (!verified) {
            return new Response(JSON.stringify({ success: false, required: true, verified: false, error: "Invalid two-factor authentication code." }), {
              status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          // Short-lived server-side 2FA session. Store only a random opaque token in
          // the browser; the Worker keeps the user binding and expiration in KV.
          const sessionToken = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
          await env.AUDIORY_KV.put(`2FA_SESSION_${sessionToken}`, JSON.stringify({ userId, verifiedAt: new Date().toISOString() }), { expirationTtl: 12 * 60 * 60 });

          return new Response(JSON.stringify({ success: true, required: true, verified: true, sessionToken, expiresIn: 43200 }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (url.pathname === "/api/auth/2fa/disable" && request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const code = normalizeTotpCode(body.code);
          const raw = env.AUDIORY_KV ? await env.AUDIORY_KV.get(kv2FAKey) : null;
          const record = raw ? JSON.parse(raw) : null;

          if (record?.is_2fa_enabled) {
            if (!code || !(await verifyTotpCode(record.totp_secret, code))) {
              return new Response(JSON.stringify({ error: "A valid authenticator code is required to disable 2FA." }), {
                status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
              });
            }
          }

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.delete(kv2FAKey);
            await env.AUDIORY_KV.delete(`2FA_TEMP_SECRET_${userId}`);
          }

          return new Response(JSON.stringify({ success: true, message: "Two-Factor Authentication disabled." }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // =============================================================
      // NEW ROUTE: /api/user/preferences
      // =============================================================
      if (path === "/api/user/preferences") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized access" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // GET Preferences
        if (request.method === "GET") {
          const rawPrefs = env.AUDIORY_KV ? await env.AUDIORY_KV.get(`user_prefs_${userId}`) : null;
          const userPrefs = rawPrefs ? JSON.parse(rawPrefs) : {
            notificationsEmail: true,
            notificationsPush: false,
            defaultCurrency: "USD",
            theme: "dark"
          };

          return new Response(JSON.stringify(userPrefs), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // POST / UPDATE Preferences
        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));

          const updatedPrefs = {
            notificationsEmail: body.notificationsEmail ?? true,
            notificationsPush: body.notificationsPush ?? false,
            defaultCurrency: body.defaultCurrency || "USD",
            theme: body.theme || "dark",
            updatedAt: new Date().toISOString()
          };

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(`user_prefs_${userId}`, JSON.stringify(updatedPrefs));
          }

          return new Response(JSON.stringify({ success: true, preferences: updatedPrefs }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
    

      // =============================================================
      // PILLAR: INTEGRATIONS & OAUTH REDIRECTS
      // =============================================================

      async function createOAuthState(provider, uid) {
        if (!env.AUDIORY_KV) throw new Error("AUDIORY_KV is required for OAuth state.");
        const state = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
        await env.AUDIORY_KV.put(
          `OAUTH_STATE_${provider}_${state}`,
          JSON.stringify({ userId: uid, provider, createdAt: new Date().toISOString() }),
          { expirationTtl: 600 }
        );
        return state;
      }

      async function consumeOAuthState(provider, state) {
        if (!env.AUDIORY_KV || !state) return null;
        const key = `OAUTH_STATE_${provider}_${state}`;
        const raw = await env.AUDIORY_KV.get(key);
        if (!raw) return null;
        await env.AUDIORY_KV.delete(key);
        return JSON.parse(raw);
      }

      const dashboardUrl = env.DASHBOARD_URL || `${url.origin}/dashboard/`;

      // -------------------------
      // SoundCloud connect
      // -------------------------
      if (url.pathname === "/api/integrations/soundcloud/connect" && request.method === "GET") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        if (!env.SOUNDCLOUD_CLIENT_ID || !env.SOUNDCLOUD_CLIENT_SECRET) {
          return new Response(JSON.stringify({ error: "SoundCloud OAuth is not configured. Set SOUNDCLOUD_CLIENT_ID and SOUNDCLOUD_CLIENT_SECRET." }), {
            status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const state = await createOAuthState("soundcloud", userId);
        const redirectUri = `${url.origin}/api/integrations/soundcloud/callback`;
        const authUrl = new URL("https://secure.soundcloud.com/authorize");
        authUrl.searchParams.set("client_id", env.SOUNDCLOUD_CLIENT_ID);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("state", state);
        return Response.redirect(authUrl.toString(), 302);
      }

      // SoundCloud OAuth callback and token exchange.
      if (url.pathname === "/api/integrations/soundcloud/callback" && request.method === "GET") {
        const state = url.searchParams.get("state");
        const code = url.searchParams.get("code");
        const error = url.searchParams.get("error");
        if (error) return Response.redirect(`${dashboardUrl}?integration=soundcloud&status=cancelled`, 302);
        if (!state || !code) return new Response("Missing SoundCloud OAuth state or code.", { status: 400 });

        const stateData = await consumeOAuthState("soundcloud", state);
        if (!stateData?.userId) return new Response("Invalid or expired OAuth state.", { status: 400 });

        const tokenRes = await fetch("https://secure.soundcloud.com/oauth/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: env.SOUNDCLOUD_CLIENT_ID,
            client_secret: env.SOUNDCLOUD_CLIENT_SECRET,
            redirect_uri: `${url.origin}/api/integrations/soundcloud/callback`,
            code
          })
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
          return Response.redirect(`${dashboardUrl}?integration=soundcloud&status=failed`, 302);
        }

        await env.AUDIORY_KV.put(`INTEGRATION_SOUNDCLOUD_USER_${stateData.userId}`, JSON.stringify({
          connected: true,
          provider: "soundcloud",
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token || null,
          expires_in: tokenData.expires_in || null,
          connectedAt: new Date().toISOString()
        }));

        return Response.redirect(`${dashboardUrl}?integration=soundcloud&status=connected`, 302);
      }

      // -------------------------
      // Audiomack connect
      // -------------------------
      if (url.pathname === "/api/integrations/audiomack/connect" && request.method === "GET") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        if (!env.AUDIOMACK_CLIENT_ID) {
          return new Response(JSON.stringify({ error: "Audiomack OAuth is not configured. Set AUDIOMACK_CLIENT_ID." }), {
            status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const state = await createOAuthState("audiomack", userId);
        const redirectUri = `${url.origin}/api/integrations/audiomack/callback`;
        const authUrl = new URL(env.AUDIOMACK_AUTH_URL || "https://audiomack.com/oauth2/authenticate");
        authUrl.searchParams.set("client_id", env.AUDIOMACK_CLIENT_ID);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("state", state);
        return Response.redirect(authUrl.toString(), 302);
      }

      if (url.pathname === "/api/integrations/audiomack/callback" && request.method === "GET") {
        const state = url.searchParams.get("state");
        const code = url.searchParams.get("code");
        if (url.searchParams.get("error")) return Response.redirect(`${dashboardUrl}?integration=audiomack&status=cancelled`, 302);
        if (!state || !code) return new Response("Missing Audiomack OAuth state or code.", { status: 400 });

        const stateData = await consumeOAuthState("audiomack", state);
        if (!stateData?.userId) return new Response("Invalid or expired OAuth state.", { status: 400 });

        // Audiomack's token endpoint can vary by partner/application. Configure it
        // explicitly rather than hard-coding an unverified endpoint.
        if (!env.AUDIOMACK_TOKEN_URL) {
          return new Response("Audiomack OAuth callback received. Set AUDIOMACK_TOKEN_URL to enable token exchange.", { status: 501 });
        }

        const tokenRes = await fetch(env.AUDIOMACK_TOKEN_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            client_id: env.AUDIOMACK_CLIENT_ID,
            client_secret: env.AUDIOMACK_CLIENT_SECRET || "",
            redirect_uri: `${url.origin}/api/integrations/audiomack/callback`,
            code
          })
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
          return Response.redirect(`${dashboardUrl}?integration=audiomack&status=failed`, 302);
        }

        await env.AUDIORY_KV.put(`INTEGRATION_AUDIOMACK_USER_${stateData.userId}`, JSON.stringify({
          connected: true,
          provider: "audiomack",
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token || null,
          expires_in: tokenData.expires_in || null,
          connectedAt: new Date().toISOString()
        }));

        return Response.redirect(`${dashboardUrl}?integration=audiomack&status=connected`, 302);
      }

      // -------------------------
      // Apple ID / Apple Music for Artists connect
      // -------------------------
      if (url.pathname === "/api/integrations/apple-music/connect" && request.method === "GET") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        if (!env.APPLE_MUSIC_CLIENT_ID) {
          return new Response(JSON.stringify({ error: "Apple authentication is not configured. Set APPLE_MUSIC_CLIENT_ID." }), {
            status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const state = await createOAuthState("apple", userId);
        const redirectUri = `${url.origin}/api/integrations/apple-music/callback`;
        const authUrl = new URL("https://appleid.apple.com/auth/authorize");
        authUrl.searchParams.set("client_id", env.APPLE_MUSIC_CLIENT_ID);
        authUrl.searchParams.set("redirect_uri", redirectUri);
        authUrl.searchParams.set("response_type", "code");
        authUrl.searchParams.set("response_mode", "query");
        authUrl.searchParams.set("scope", "name email");
        authUrl.searchParams.set("state", state);
        return Response.redirect(authUrl.toString(), 302);
      }

      if (url.pathname === "/api/integrations/apple-music/callback" && request.method === "GET") {
        const state = url.searchParams.get("state");
        const code = url.searchParams.get("code");
        if (url.searchParams.get("error")) return Response.redirect(`${dashboardUrl}?integration=apple-music&status=cancelled`, 302);
        if (!state || !code) return new Response("Missing Apple OAuth state or code.", { status: 400 });

        const stateData = await consumeOAuthState("apple", state);
        if (!stateData?.userId) return new Response("Invalid or expired OAuth state.", { status: 400 });
        const redirectUri = `${url.origin}/api/integrations/apple-music/callback`;

        // Apple Sign in with Apple requires a valid client_secret JWT generated for
        // the Apple Developer account. Configure APPLE_MUSIC_TOKEN_URL and
        // APPLE_MUSIC_CLIENT_SECRET when your Apple application is configured.
        if (!env.APPLE_MUSIC_TOKEN_URL || !env.APPLE_MUSIC_CLIENT_SECRET) {
          await env.AUDIORY_KV.put(`INTEGRATION_APPLE_MUSIC_USER_${stateData.userId}`, JSON.stringify({
            connected: false,
            provider: "apple-music",
            authorizationReceived: true,
            authorizationCodeReceivedAt: new Date().toISOString(),
            status: "authorization_received_token_exchange_not_configured"
          }));
          return Response.redirect(`${dashboardUrl}?integration=apple-music&status=authorization_received`, 302);
        }

        const tokenRes = await fetch(env.APPLE_MUSIC_TOKEN_URL, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            client_id: env.APPLE_MUSIC_CLIENT_ID,
            client_secret: env.APPLE_MUSIC_CLIENT_SECRET,
            redirect_uri: redirectUri
          })
        });
        const tokenData = await tokenRes.json().catch(() => ({}));
        if (!tokenRes.ok || !tokenData.access_token) {
          return Response.redirect(`${dashboardUrl}?integration=apple-music&status=failed`, 302);
        }

        await env.AUDIORY_KV.put(`INTEGRATION_APPLE_MUSIC_USER_${stateData.userId}`, JSON.stringify({
          connected: true,
          provider: "apple-music",
          access_token: tokenData.access_token,
          refresh_token: tokenData.refresh_token || null,
          expires_in: tokenData.expires_in || null,
          connectedAt: new Date().toISOString()
        }));

        return Response.redirect(`${dashboardUrl}?integration=apple-music&status=connected`, 302);
      }

      // Return integration status to the settings page.
      if (url.pathname === "/api/integrations/status" && request.method === "GET") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        const providers = ["soundcloud", "audiomack", "apple-music"];
        const result = {};
        for (const provider of providers) {
          const raw = env.AUDIORY_KV ? await env.AUDIORY_KV.get(`INTEGRATION_${provider.toUpperCase().replace(/-/g, "_")}_USER_${userId}`) : null;
          const data = raw ? JSON.parse(raw) : null;
          result[provider] = data ? {
            connected: data.connected === true,
            provider,
            connectedAt: data.connectedAt || null,
            status: data.status || (data.connected ? "connected" : "disconnected")
          } : { connected: false, provider, status: "disconnected" };
        }
        return new Response(JSON.stringify(result), {
          status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // =============================================================
      // PILLAR 1: MY PROFILE API (/api/profile)
      // =============================================================
      if (url.pathname === "/api/profile") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const kvKey = `PROFILE_USER_${userId}`;

        if (request.method === "GET") {
          let profile = {};
          if (env.AUDIORY_KV) {
            profile = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "{}");
          }
          return new Response(JSON.stringify(profile), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (request.method === "POST" || request.method === "PUT") {
          const body = await request.json().catch(() => ({}));
          const displayName = String(body.displayName || "").trim();
    
          if (!displayName) {
            return new Response(JSON.stringify({ error: "Profile name is required." }), {
              status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
    
          if (displayName.length > 100) {
            return new Response(JSON.stringify({ error: "Display name must be 100 characters or fewer." }), {
              status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const profileData = {
            displayName,
            updatedAt: new Date().toISOString()
          };

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(profileData));
          }

          // Keep Firebase's displayName in sync (returnSecureToken MUST be true)
          const authHeader = request.headers.get("Authorization") || "";
          const firebaseToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
    
          if (env.FIREBASE_WEB_API_KEY && firebaseToken) {
            await fetch(`https://identitytoolkit.googleapis.com/v1/accounts:update?key=${encodeURIComponent(env.FIREBASE_WEB_API_KEY)}`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ 
                idToken: firebaseToken, 
                displayName: displayName,
                returnSecureToken: true 
              })
            }).catch(() => null);
          }

          return new Response(JSON.stringify({ success: true, profile: profileData }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

// =============================================================
// PILLAR 2: ACCOUNT MEMBERS & ACCESS CONTROL (/api/members)
// =============================================================
if (url.pathname === "/api/members" || url.pathname.startsWith("/api/members/")) {

  // -----------------------------------------------------------
  // PUBLIC ENDPOINT: ACCEPT INVITATION (No userId Auth Required)
  // -----------------------------------------------------------
  if (url.pathname === "/api/members/accept" && request.method === "POST") {
    const { inviteId, ownerId } = await request.json().catch(() => ({}));

    if (!inviteId || !ownerId) {
      return new Response(
        JSON.stringify({ error: "Missing required invitation parameters (inviteId or ownerId)." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const ownerKvKey = `MEMBERS_USER_${ownerId}`;
    let members = [];

    if (env.AUDIORY_KV) {
      members = JSON.parse((await env.AUDIORY_KV.get(ownerKvKey)) || "[]");
    }

    // Locate target pending member record
    const memberIndex = members.findIndex(m => String(m.id) === String(inviteId));

    if (memberIndex === -1) {
      return new Response(
        JSON.stringify({ error: "Invitation record not found or has expired." }),
        { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Update status to Accepted
    members[memberIndex].status = "Accepted";
    members[memberIndex].acceptedAt = new Date().toISOString();

    if (env.AUDIORY_KV) {
      await env.AUDIORY_KV.put(ownerKvKey, JSON.stringify(members));
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "Invitation accepted successfully.",
        member: members[memberIndex]
      }),
      { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  // -----------------------------------------------------------
  // AUTH GUARD: All endpoints below require a valid userId
  // -----------------------------------------------------------
  if (!userId) {
    return new Response(
      JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
      { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }

  const kvKey = `MEMBERS_USER_${userId}`;

  // GET: List Members
  if (url.pathname === "/api/members" && request.method === "GET") {
    let members = [];
    if (env.AUDIORY_KV) {
      members = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
    }
    return new Response(JSON.stringify(members), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  // POST: Invite Member & Send Classic Invitation Email
  if (url.pathname === "/api/members/invite" && request.method === "POST") {
    const { email, roles } = await request.json().catch(() => ({}));
    if (!email || !roles || !Array.isArray(roles) || roles.length === 0) {
      return new Response(
        JSON.stringify({ error: "Member email and at least one role are required." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let members = [];
    if (env.AUDIORY_KV) {
      members = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
    }

    const memberId = `mem_${Date.now()}`;
    const inviteLink = `https://distro.audiory.site/accept-invite?id=${memberId}&owner=${userId}`;

    const newMember = {
      id: memberId,
      email,
      roles,
      status: "Pending",
      invitedAt: new Date().toISOString()
    };

    // Format roles list for display
    const formattedRoles = roles.map(r => `<li style="margin-bottom: 6px;"><strong>${r}</strong></li>`).join("");

    // Classic Invitation Email Template
    const emailHtml = `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <title>Workspace Invitation</title>
      </head>
      <body style="margin: 0; padding: 0; background-color: #f4f5f7; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
        <table width="100%" border="0" cellspacing="0" cellpadding="0" style="background-color: #f4f5f7; padding: 40px 0;">
          <tr>
            <td align="center">
              <table width="560" border="0" cellspacing="0" cellpadding="0" style="background-color: #ffffff; border-radius: 8px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);">
                
                <!-- Header -->
                <tr>
                  <td style="background-color: #0f172a; padding: 30px; text-align: center;">
                    <h1 style="color: #ffffff; margin: 0; font-size: 22px; font-weight: 700; letter-spacing: 0.5px;">AUDIORY</h1>
                  </td>
                </tr>

                <!-- Content -->
                <tr>
                  <td style="padding: 36px 32px; color: #334155;">
                    <h2 style="font-size: 18px; color: #0f172a; margin-top: 0; margin-bottom: 16px;">You've Been Invited!</h2>
                    <p style="font-size: 14px; line-height: 1.6; color: #475569; margin-bottom: 24px;">
                      You have been invited to join an artist/label workspace on <strong>Audiory Distribution</strong>.
                    </p>

                    <!-- Assigned Roles Card -->
                    <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 20px; margin-bottom: 28px;">
                      <p style="font-size: 12px; font-weight: 700; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; margin: 0 0 10px 0;">Your Assigned Roles:</p>
                      <ul style="margin: 0; padding-left: 20px; font-size: 14px; color: #0f172a;">
                        ${formattedRoles}
                      </ul>
                    </div>

                    <!-- Call to Action -->
                    <div style="text-align: center; margin-bottom: 28px;">
                      <a href="${inviteLink}" target="_blank" style="background-color: #6366f1; color: #ffffff; text-decoration: none; font-size: 14px; font-weight: 600; padding: 12px 28px; border-radius: 6px; display: inline-block;">
                        Accept Invitation
                      </a>
                    </div>

                    <p style="font-size: 12px; color: #94a3b8; line-height: 1.5; margin-bottom: 0;">
                      If the button above does not work, copy and paste this link into your browser:<br>
                      <a href="${inviteLink}" style="color: #6366f1; word-break: break-all;">${inviteLink}</a>
                    </p>
                  </td>
                </tr>

                <!-- Footer -->
                <tr>
                  <td style="background-color: #f8fafc; padding: 20px; text-align: center; border-top: 1px solid #e2e8f0;">
                    <p style="font-size: 11px; color: #94a3b8; margin: 0;">
                      &copy; ${new Date().getFullYear()} Audiory. All rights reserved.
                    </p>
                  </td>
                </tr>

              </table>
            </td>
          </tr>
        </table>
      </body>
      </html>
    `;

    // Send invitation email using pre-existing helper
    await sendResendEmail(env, {
      to: email,
      subject: "You've been invited to collaborate on Audiory",
      html: emailHtml
    });

    members.unshift(newMember);

    if (env.AUDIORY_KV) {
      await env.AUDIORY_KV.put(kvKey, JSON.stringify(members));
    }

    return new Response(JSON.stringify({ success: true, member: newMember }), {
      status: 201,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  // DELETE: Remove Member
  if (url.pathname.startsWith("/api/members/") && request.method === "DELETE") {
    const memberId = url.pathname.split("/").pop();
    let members = [];
    if (env.AUDIORY_KV) {
      members = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
      members = members.filter(m => String(m.id) !== String(memberId));
      await env.AUDIORY_KV.put(kvKey, JSON.stringify(members));
    }
    return new Response(JSON.stringify({ success: true, removedId: memberId }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }
}

      // =============================================================
      // PILLAR 3: TAX DETAILS & COMPLIANCE (/api/tax-details)
      // =============================================================
      if (url.pathname === "/api/tax-details") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `TAX_USER_${userId}`;

        if (request.method === "GET") {
          let taxData = {};
          if (env.AUDIORY_KV) {
            taxData = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "{}");
          }
          return new Response(JSON.stringify(taxData), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const w9Details = body.w9Details || {};
          const legalName = String(body.legalName || w9Details.legalName || "").trim();
          const classification = body.classification || w9Details.classification || body.formType || "individual";
          const country = String(body.country || w9Details.country || "").trim();
          const tin = String(body.tin || w9Details.tin || "").trim();
          const address = body.address || w9Details.address || "";
          const formType = body.formType || "W-9";

          if (!legalName || !country || !tin) {
            return new Response(
              JSON.stringify({ error: "Legal name, country, and Tax Identification Number (TIN) are required." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          const taxRecord = {
            formType,
            legalName,
            classification: classification || "individual",
            country,
            tin,
            address: address || "",
            status: "Submitted",
            updatedAt: new Date().toISOString()
          };

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(taxRecord));
          }

          return new Response(JSON.stringify({ success: true, taxRecord }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // =============================================================
      // PILLAR 4: PAYOUT & PAYMENT PREFERENCES ALIAS (/api/payout-preferences)
      // =============================================================
      if (url.pathname === "/api/payout-preferences" || url.pathname === "/api/payout-settings") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `PAYOUT_SETTINGS_USER_${userId}`;

        if (request.method === "GET") {
          let payoutData = { payoutType: "bank", details: {} };
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kvKey);
            payoutData = raw ? JSON.parse(raw) : payoutData;
          }
          return new Response(JSON.stringify(payoutData), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (request.method === "POST" || request.method === "PUT") {
          const body = await request.json().catch(() => ({}));
          const payoutType = body.payoutType || body.method || "bank";
          const details = body.details || {};

          const payoutRecord = {
            payoutType,
            details,
            updatedAt: new Date().toISOString()
          };

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(payoutRecord));
          }

          return new Response(JSON.stringify({ success: true, payoutSettings: payoutRecord }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // =============================================================
      // PILLAR 5: DYNAMIC SUBSCRIPTION & BILLING HISTORY WITH EXPIRY
      // =============================================================

      const PLANS = {
        starter: { name: "Starter Plan", price: "0.00", description: "Starter Plan (Free Tier)", durationDays: 0 },
        pro: { name: "Pro Artist Plan", price: "19.99", description: "Pro Artist Plan (Annual Subscription)", durationDays: 365 },
        label: { name: "Label Partner", price: "49.99", description: "Label Partner Plan (Annual Subscription)", durationDays: 365 }
      };

      // Helper function: Checks subscription expiry and downgrades to starter if expired
      async function checkAndProcessExpiry(userId, env, corsHeaders) {
        if (!env.AUDIORY_KV || !userId) return null;

        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
        const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
        if (!rawSub) return null;

        let currentSub = JSON.parse(rawSub);

        // Free starter plan or non-active subscriptions do not expire automatically
        if (currentSub.planId === "starter" || currentSub.status !== "Active" || !currentSub.expiresAt) {
          return currentSub;
        }

        // Downgrade to starter tier if current date surpasses expiration date
        if (new Date() > new Date(currentSub.expiresAt)) {
          currentSub = {
            planId: "starter",
            planName: PLANS.starter.name,
            amount: PLANS.starter.price,
            status: "Active",
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            downgradedFrom: currentSub.planId,
            downgradedAt: new Date().toISOString()
          };

          await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
        }

        return currentSub;
      }

      if (url.pathname === "/api/billing-history" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
        const billingKvKey = `BILLING_USER_${userId}`;

        // Evaluate expiry before returning subscription state
        let currentSub = await checkAndProcessExpiry(userId, env, corsHeaders);
        let history = [];

        if (env.AUDIORY_KV) {
          const rawHistory = await env.AUDIORY_KV.get(billingKvKey);
          history = rawHistory ? JSON.parse(rawHistory) : [];
        }

        // ACTIVE DARAJA STK QUERY FOR PENDING M-PESA TRANSACTIONS
        if (currentSub && currentSub.status === "Pending" && currentSub.paymentMethod === "mpesa" && currentSub.transactionId) {
          try {
            const darajaAuthUrl = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";
            const authRes = await fetch(darajaAuthUrl, {
              headers: { Authorization: `Basic ${btoa(`${env.DARAJA_CONSUMER_KEY}:${env.DARAJA_CONSUMER_SECRET}`)}` }
            }).then(r => r.json()).catch(() => null);

            if (authRes?.access_token) {
              const timestamp = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
              const password = btoa(`${env.DARAJA_BUSINESS_SHORTCODE}${env.DARAJA_PASSKEY}${timestamp}`);

              const queryRes = await fetch("https://api.safaricom.co.ke/mpesa/stkpushquery/v1/query", {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${authRes.access_token}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify({
                  BusinessShortCode: env.DARAJA_BUSINESS_SHORTCODE,
                  Password: password,
                  Timestamp: timestamp,
                  CheckoutRequestID: currentSub.transactionId
                })
              }).then(r => r.json()).catch(() => null);

              // ResultCode "0" = Success
              // ResultCode "1032" (User cancelled), "1037" (Timeout), "1" (Insufficient funds) = Failed
              if (queryRes && queryRes.ResultCode !== undefined) {
                if (queryRes.ResultCode === "0" || queryRes.ResultCode === 0) {
                  const now = new Date();
                  currentSub.status = "Active";
                  currentSub.updatedAt = now.toISOString();
                  currentSub.expiresAt = new Date(now.getTime() + 365 * 86400000).toISOString();
                  if (history.length > 0) history[0].status = "Paid";
                } else if (queryRes.ResultCode !== "1036") { // 1036 means in-progress/processing; any other code is a definitive failure
                  currentSub.status = "Failed";
                  currentSub.updatedAt = new Date().toISOString();
                  if (history.length > 0) history[0].status = "Failed";
                }

                if (env.AUDIORY_KV) {
                  await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
                  await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(history));
                }
              }
            }
          } catch (e) {
            console.error("Daraja verification query error:", e);
          }
        }

        if (!currentSub) {
          currentSub = {
            planId: "starter",
            planName: PLANS.starter.name,
            amount: PLANS.starter.price,
            status: "Active",
            createdAt: new Date().toISOString()
          };
        }

        return new Response(
          JSON.stringify({ subscription: currentSub, history: history }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (url.pathname === "/api/subscription/status" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        let currentSub = await checkAndProcessExpiry(userId, env, corsHeaders);

        return new Response(
          JSON.stringify({ 
            status: currentSub ? currentSub.status : "Inactive", 
            planId: currentSub ? currentSub.planId : "starter",
            subscription: currentSub 
          }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      if (url.pathname === "/api/subscription/upgrade" && request.method === "POST") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const body = await request.json().catch(() => ({}));
        const { planId, paymentMethod, phone, email, displayName } = body;

        const selectedPlan = PLANS[planId] || PLANS.starter;
        let transactionId = `TXN-${Date.now()}`;
        let redirectUrl = null;
        let requiresManualAction = false;

        if (parseFloat(selectedPlan.price) > 0) {
          // A. M-PESA DARAJA STK PUSH
          if (paymentMethod === "mpesa") {
            if (!phone) {
              return new Response(
                JSON.stringify({ error: "A valid phone number is required for M-Pesa payments." }),
                { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            const darajaAuthUrl = "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials";
      
            const authRes = await fetch(darajaAuthUrl, {
              headers: {
                Authorization: `Basic ${btoa(`${env.DARAJA_CONSUMER_KEY}:${env.DARAJA_CONSUMER_SECRET}`)}`
              }
            }).then(r => r.json()).catch(() => null);

            if (!authRes || !authRes.access_token) {
              return new Response(
                JSON.stringify({ error: "M-Pesa authorization failed. Verify Daraja Consumer Key and Secret." }),
                { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            const timestamp = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
            const password = btoa(`${env.DARAJA_BUSINESS_SHORTCODE}${env.DARAJA_PASSKEY}${timestamp}`);

            const stkRes = await fetch("https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest", {
              method: "POST",
              headers: {
                Authorization: `Bearer ${authRes.access_token}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                BusinessShortCode: env.DARAJA_BUSINESS_SHORTCODE,
                Password: password,
                Timestamp: timestamp,
                TransactionType: "CustomerPayBillOnline",
                Amount: Math.round(parseFloat(selectedPlan.price) * 130),
                PartyA: phone,
                PartyB: env.DARAJA_BUSINESS_SHORTCODE,
                PhoneNumber: phone,
                CallBackURL: "https://distro.audiory.site/api/webhooks/mpesa",
                AccountReference: "AudioryDistro",
                TransactionDesc: `Subscription for ${selectedPlan.name}`
              })
            }).then(r => r.json()).catch(() => null);

            if (!stkRes || !stkRes.CheckoutRequestID) {
              return new Response(
                JSON.stringify({ error: "Failed to initialize M-Pesa STK Push. Check phone format or Daraja credentials." }),
                { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            transactionId = stkRes.CheckoutRequestID;
            requiresManualAction = true;
          }

          // B. PAYPAL CHECKOUT
          else if (paymentMethod === "paypal") {
            const paypalBase = env.PAYPAL_MODE === "sandbox" 
              ? "https://api-m.sandbox.paypal.com" 
              : "https://api-m.paypal.com";

            const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
              method: "POST",
              headers: {
                Authorization: `Basic ${btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`)}`,
                "Content-Type": "application/x-www-form-urlencoded"
              },
              body: "grant_type=client_credentials"
            }).then(r => r.json()).catch(() => null);

            if (!authRes || !authRes.access_token) {
              return new Response(
                JSON.stringify({ error: "PayPal authorization failed. Check PayPal Client ID/Secret." }),
                { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            const orderRes = await fetch(`${paypalBase}/v2/checkout/orders`, {
              method: "POST",
              headers: {
                Authorization: `Bearer ${authRes.access_token}`,
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                intent: "CAPTURE",
                purchase_units: [{
                  reference_id: `SUB-${userId}-${Date.now()}`,
                  description: selectedPlan.description,
                  amount: { currency_code: "USD", value: selectedPlan.price }
                }],
                application_context: {
                  return_url: "https://distro.audiory.site/dashboard/?payment=success",
                  cancel_url: "https://distro.audiory.site/signup/?payment=cancelled",
                  brand_name: "Audiory Distribution",
                  user_action: "PAY_NOW"
                }
              })
            }).then(r => r.json()).catch(() => null);

            const approveLink = orderRes?.links?.find(link => link.rel === "approve");
            if (!orderRes || !orderRes.id || !approveLink) {
              return new Response(
                JSON.stringify({ error: "Failed to generate PayPal payment link." }),
                { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            transactionId = orderRes.id;
            redirectUrl = approveLink.href;
          }

          // C. PESAPAL GATEWAY
          else if (paymentMethod === "pesapal") {
            const pesapalBase = env.PESAPAL_MODE === "sandbox" 
              ? "https://cyb3r.pesapal.com/pesapalv3" 
              : "https://pay.pesapal.com/v3";

            const authRes = await fetch(`${pesapalBase}/api/Auth/RequestToken`, {
              method: "POST",
              headers: { "Content-Type": "application/json", "Accept": "application/json" },
              body: JSON.stringify({
                consumer_key: env.PESAPAL_CONSUMER_KEY,
                consumer_secret: env.PESAPAL_CONSUMER_SECRET
              })
            }).then(r => r.json()).catch(() => null);

            if (!authRes || !authRes.token) {
              return new Response(
                JSON.stringify({ error: "PesaPal authorization failed. Verify Consumer Key and Secret." }),
                { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            let ipnId = env.PESAPAL_IPN_ID;
            if (!ipnId) {
              const ipnRes = await fetch(`${pesapalBase}/api/URLSetup/RegisterIPN`, {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${authRes.token}`,
                  "Content-Type": "application/json",
                  "Accept": "application/json"
                },
                body: JSON.stringify({
                  url: "https://distro.audiory.site/api/webhooks/pesapal",
                  ipn_notification_type: "GET"
                })
              }).then(r => r.json()).catch(() => null);

              if (ipnRes && ipnRes.ipn_id) ipnId = ipnRes.ipn_id;
            }

            const names = (displayName || "Subscriber").trim().split(" ");
            const firstName = names[0] || "Subscriber";
            const lastName = names.slice(1).join(" ") || "Artist";

            const orderRes = await fetch(`${pesapalBase}/api/Transactions/SubmitOrderRequest`, {
              method: "POST",
              headers: {
                Authorization: `Bearer ${authRes.token}`,
                "Content-Type": "application/json",
                "Accept": "application/json"
              },
              body: JSON.stringify({
                id: `PESA-${Date.now()}`,
                currency: "USD",
                amount: Number(parseFloat(selectedPlan.price).toFixed(2)),
                description: selectedPlan.description || "Subscription Upgrade",
                callback_url: "https://distro.audiory.site/dashboard/?payment=success",
                notification_id: ipnId,
                billing_address: {
                  email_address: email || "billing@audiory.site",
                  phone_number: phone || "",
                  first_name: firstName,
                  last_name: lastName
                }
              })
            }).then(r => r.json()).catch(() => null);

            if (!orderRes || !orderRes.redirect_url) {
              return new Response(
                JSON.stringify({ 
                  error: orderRes?.error?.message || "Failed to generate PesaPal payment portal. Verify IPN ID and credentials." 
                }),
                { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
              );
            }

            transactionId = orderRes.order_tracking_id;
            redirectUrl = orderRes.redirect_url;
          }
        }

        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
        const billingKvKey = `BILLING_USER_${userId}`;
        const isFreePlan = parseFloat(selectedPlan.price) === 0;

        // Calculate standard 365-day expiry for paid tiers
        const now = new Date();
        const expiresAt = isFreePlan ? null : new Date(now.getTime() + selectedPlan.durationDays * 24 * 60 * 60 * 1000).toISOString();

        const activeSubData = {
          planId: planId,
          planName: selectedPlan.name,
          amount: selectedPlan.price,
          paymentMethod: paymentMethod || "card",
          transactionId: transactionId,
          status: isFreePlan ? "Active" : "Pending",
          createdAt: now.toISOString(),
          updatedAt: now.toISOString(),
          expiresAt: expiresAt
        };

        if (env.AUDIORY_KV) {
          await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(activeSubData));

          if (paymentMethod === "mpesa" && transactionId) {
            await env.AUDIORY_KV.put(`MPESA_TX_${transactionId}`, userId);
          }

          // FIX: Map transaction ID for PesaPal webhooks
          if (paymentMethod === "pesapal" && transactionId) {
            await env.AUDIORY_KV.put(`PESAPAL_TX_${transactionId}`, userId);
          }

          if (!isFreePlan) {
            const rawHistory = await env.AUDIORY_KV.get(billingKvKey);
            const history = rawHistory ? JSON.parse(rawHistory) : [];

            history.unshift({
              invoiceId: `INV-${Math.floor(10000 + Math.random() * 90000)}`,
              date: now.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
              description: selectedPlan.description,
              amount: selectedPlan.price,
              gateway: paymentMethod,
              status: "Pending"
            });

            await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(history));
          }
        }

        return new Response(JSON.stringify({ 
          success: true, 
          subscription: activeSubData,
          redirectUrl: redirectUrl,
          requiresManualAction: requiresManualAction
        }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // PAYPAL ORDER CAPTURE HANDLER
      if (url.pathname === "/api/subscription/paypal-capture" && request.method === "POST") {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized" }), {
            status: 401,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const { orderId } = await request.json().catch(() => ({}));
        if (!orderId) {
          return new Response(JSON.stringify({ error: "Order ID missing" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const paypalBase = env.PAYPAL_MODE === "sandbox" ? "https://api-m.sandbox.paypal.com" : "https://api-m.paypal.com";

        // Get Auth Token
        const authRes = await fetch(`${paypalBase}/v1/oauth2/token`, {
          method: "POST",
          headers: {
            Authorization: `Basic ${btoa(`${env.PAYPAL_CLIENT_ID}:${env.PAYPAL_CLIENT_SECRET}`)}`,
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: "grant_type=client_credentials"
        }).then(r => r.json()).catch(() => null);

        if (!authRes?.access_token) {
          return new Response(JSON.stringify({ error: "PayPal Auth Failed" }), {
            status: 502,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // Capture Payment
        const captureRes = await fetch(`${paypalBase}/v2/checkout/orders/${orderId}/capture`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${authRes.access_token}`,
            "Content-Type": "application/json"
          }
        }).then(r => r.json()).catch(() => null);

        if (captureRes?.status === "COMPLETED") {
          const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
          const billingKvKey = `BILLING_USER_${userId}`;

          const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
          const rawBilling = await env.AUDIORY_KV.get(billingKvKey);

          let currentSub = rawSub ? JSON.parse(rawSub) : null;
          let history = rawBilling ? JSON.parse(rawBilling) : [];

          if (currentSub) {
            const now = new Date();
            const durationDays = PLANS[currentSub.planId]?.durationDays || 365;
            currentSub.status = "Active";
            currentSub.updatedAt = now.toISOString();
            currentSub.expiresAt = new Date(now.getTime() + durationDays * 86400000).toISOString();
            await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
          }

          if (history.length > 0) {
            history[0].status = "Paid";
            await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(history));
          }

          return new Response(JSON.stringify({ success: true, subscription: currentSub }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        return new Response(JSON.stringify({ error: "Payment capture failed or incomplete" }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // PESAPAL IPN WEBHOOK HANDLER
      if (url.pathname === "/api/webhooks/pesapal" && (request.method === "GET" || request.method === "POST")) {
        const OrderTrackingId = url.searchParams.get("OrderTrackingId");

        if (OrderTrackingId && env.AUDIORY_KV) {
          const targetUserId = await env.AUDIORY_KV.get(`PESAPAL_TX_${OrderTrackingId}`);

          if (targetUserId) {
            const pesapalBase = env.PESAPAL_MODE === "sandbox" ? "https://cyb3r.pesapal.com/pesapalv3" : "https://pay.pesapal.com/v3";

            // 1. Get Token
            const authRes = await fetch(`${pesapalBase}/api/Auth/RequestToken`, {
              method: "POST",
              headers: { "Content-Type": "application/json", Accept: "application/json" },
              body: JSON.stringify({
                consumer_key: env.PESAPAL_CONSUMER_KEY,
                consumer_secret: env.PESAPAL_CONSUMER_SECRET
              })
            }).then(r => r.json()).catch(() => null);

            if (authRes?.token) {
              // 2. Query Status
              const statusRes = await fetch(`${pesapalBase}/api/Transactions/GetTransactionStatus?orderTrackingId=${OrderTrackingId}`, {
                headers: { Authorization: `Bearer ${authRes.token}`, Accept: "application/json" }
              }).then(r => r.json()).catch(() => null);

              const statusCode = statusRes?.payment_status_description;

              const subscriptionKvKey = `SUBSCRIPTION_USER_${targetUserId}`;
              const billingKvKey = `BILLING_USER_${targetUserId}`;

              const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
              const rawBilling = await env.AUDIORY_KV.get(billingKvKey);

              let currentSub = rawSub ? JSON.parse(rawSub) : null;
              let history = rawBilling ? JSON.parse(rawBilling) : [];

              if (statusCode === "Completed") {
                if (currentSub) {
                  const now = new Date();
                  const durationDays = PLANS[currentSub.planId]?.durationDays || 365;
                  currentSub.status = "Active";
                  currentSub.updatedAt = now.toISOString();
                  currentSub.expiresAt = new Date(now.getTime() + durationDays * 86400000).toISOString();
                  await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
                }
                if (history.length > 0) {
                  history[0].status = "Paid";
                  await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(history));
                }
              } else if (statusCode === "Failed" || statusCode === "Reversed") {
                if (currentSub) {
                  currentSub.status = "Failed";
                  currentSub.updatedAt = new Date().toISOString();
                  await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
                }
                if (history.length > 0) {
                  history[0].status = "Failed";
                  await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(history));
                }
              }
            }
          }
        }

        return new Response(JSON.stringify({ orderNotificationType: "IPNCHANGE", orderTrackingId: OrderTrackingId, status: 200 }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      // M-PESA WEBHOOK CALLBACK HANDLER
      if (url.pathname === "/api/webhooks/mpesa" && request.method === "POST") {
        let body = {};
        try {
          body = await request.json();
        } catch (err) {
          body = {};
        }

        const stkCallback = body?.Body?.stkCallback;

        if (stkCallback && env.AUDIORY_KV) {
          const checkoutReqId = stkCallback.CheckoutRequestID;
          const resultCode = stkCallback.ResultCode;

          // Look up user ID using your existing key
          const targetUserId = await env.AUDIORY_KV.get(`MPESA_TX_${checkoutReqId}`);

          if (targetUserId) {
            const subscriptionKvKey = `SUBSCRIPTION_USER_${targetUserId}`;
            const billingKvKey = `BILLING_USER_${targetUserId}`;

            const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
            const rawBilling = await env.AUDIORY_KV.get(billingKvKey);

            let currentSub = rawSub ? JSON.parse(rawSub) : null;
            let billingHistory = rawBilling ? JSON.parse(rawBilling) : [];

            if (resultCode === 0) {
              // --- 1. PAYMENT SUCCESS ---
              if (currentSub) {
                const now = new Date();
                const durationDays = PLANS[currentSub.planId]?.durationDays || 365;

                currentSub.status = "Active";
                currentSub.updatedAt = now.toISOString();
                currentSub.expiresAt = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000).toISOString();

                await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
              }

              if (billingHistory.length > 0) {
                billingHistory[0].status = "Paid";
                await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(billingHistory));
              }
            } else {
              // --- 2. PAYMENT FAILED / CANCELLED BY USER ---
              if (currentSub) {
                currentSub.status = "Failed";
                currentSub.updatedAt = new Date().toISOString();
                // Added: Attach Safaricom's exact result description for UI error display
                currentSub.errorMessage = stkCallback.ResultDesc || "Payment was cancelled or failed.";

                await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
              }

              if (billingHistory.length > 0) {
                billingHistory[0].status = "Failed";
                billingHistory[0].errorMessage = stkCallback.ResultDesc || "Payment failed.";
                await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(billingHistory));
              }
            }

            // Cleanup transaction mapping key
            await env.AUDIORY_KV.delete(`MPESA_TX_${checkoutReqId}`);
          }
        }

        return new Response(JSON.stringify({ ResultCode: 0, ResultDesc: "Accepted" }), {
          status: 200,
          headers: { "Content-Type": "application/json" }
        });
      }

      // =============================================================
      // PILLAR 6: LOGIN HISTORY & SESSION REVOCATION (/api/login-history)
      // =============================================================
      if (
        url.pathname === "/api/login-history" ||
        url.pathname === "/api/login-history/record" ||
        url.pathname === "/api/login-history/revoke-all" ||
        url.pathname.startsWith("/api/login-history/")
      ) {
        if (!userId) {
          return new Response(JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }), {
            status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        const kvKey = `SESSIONS_USER_${userId}`;

        // Called by the frontend immediately after a successful Firebase login.
        if (url.pathname === "/api/login-history/record" && request.method === "POST") {
          const session = await recordLoginSession(env, userId, request);
          return new Response(JSON.stringify({ success: true, session }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (url.pathname === "/api/login-history" && request.method === "GET") {
          let sessions = [];
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kvKey);
            sessions = raw ? JSON.parse(raw) : [];
          }

          // Do not manufacture a fake current login. An empty array means there
          // is genuinely no recorded login history yet.
          return new Response(JSON.stringify(sessions), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (url.pathname === "/api/login-history/revoke-all" && request.method === "POST") {
          let sessions = [];
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kvKey);
            sessions = raw ? JSON.parse(raw) : [];
            const now = new Date().toISOString();
            sessions = sessions.map(s => s.isCurrent ? s : {
              ...s,
              revoked: true,
              isCurrent: false,
              logoutAt: s.logoutAt || now
            });
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(sessions));
          }

          return new Response(JSON.stringify({ success: true, message: "All non-current sessions revoked." }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (url.pathname.startsWith("/api/login-history/") && request.method === "DELETE") {
          const sessionId = decodeURIComponent(url.pathname.split("/").pop());
          if (env.AUDIORY_KV) {
            let sessions = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
            const target = sessions.find(s => String(s.id) === String(sessionId));
            if (target?.isCurrent) {
              return new Response(JSON.stringify({ error: "The current session cannot be revoked from this endpoint." }), {
                status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" }
              });
            }
            sessions = sessions.map(s => String(s.id) === String(sessionId)
              ? { ...s, revoked: true, isCurrent: false, logoutAt: s.logoutAt || new Date().toISOString() }
              : s
            );
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(sessions));
          }

          return new Response(JSON.stringify({ success: true, revokedId: sessionId }), {
            status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

// =============================================================
// ROUTE: SUPPORT TICKETS & RESEND EMAIL AUTOMATION
// =============================================================

// Helper: Send email via Resend API
async function sendResendEmail(env, { to, subject, html }) {
  const resendApiKey = env.RESEND_API_KEY;
  if (!resendApiKey) {
    console.error("Missing RESEND_API_KEY environment variable");
    return false;
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${resendApiKey}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: "Audiory Support <support@distro.audiory.site>",
      to: Array.isArray(to) ? to : [to],
      subject: subject,
      html: html
    })
  });

  return response.ok;
}

// Handler: GET /api/support/tickets
if (url.pathname === "/api/support/tickets" && request.method === "GET") {
  const userKvKey = `TICKETS_USER_${userId || "GUEST"}`;
  const ticketsRaw = await env.AUDIORY_KV.get(userKvKey);
  const tickets = ticketsRaw ? JSON.parse(ticketsRaw) : [];

  return new Response(JSON.stringify({ tickets }), {
    status: 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// Handler: POST /api/support/tickets
if (url.pathname === "/api/support/tickets" && request.method === "POST") {
  const payload = await request.json();
  const { email, subject, priority, message } = payload;

  if (!email || !subject || !message) {
    return new Response(JSON.stringify({ error: "Missing required fields" }), {
      status: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" }
    });
  }

  // 1. Generate unique ticket number (e.g., ADY-849201)
  const ticketNumber = `ADY-${Math.floor(100000 + Math.random() * 900000)}`;

  const newTicket = {
    ticketNumber,
    userEmail: email,
    subject,
    priority: priority || "Normal",
    message,
    status: "new", // Statuses: 'new', 'open', 'solved'
    createdAt: new Date().toISOString()
  };

  // 2. Persist to KV
  const userKvKey = `TICKETS_USER_${userId || "GUEST"}`;
  const existingTickets = JSON.parse((await env.AUDIORY_KV.get(userKvKey)) || "[]");
  existingTickets.unshift(newTicket);
  await env.AUDIORY_KV.put(userKvKey, JSON.stringify(existingTickets));

  // 3. Email 1: Send internal ticket notification to support@audiory.site
  await sendResendEmail(env, {
    to: "support@distro.audiory.site",
    subject: `[New Ticket #${ticketNumber}] ${subject}`,
    html: `
      <h2>New Support Ticket Received</h2>
      <p><strong>Ticket Number:</strong> #${ticketNumber}</p>
      <p><strong>From:</strong> ${email}</p>
      <p><strong>Priority:</strong> ${priority}</p>
      <p><strong>Message:</strong></p>
      <blockquote style="background: #f4f4f4; padding: 10px; border-left: 4px solid #6366f1;">
        ${message.replace(/\n/g, '<br>')}
      </blockquote>
    `
  });

  // 4. Email 2: Send confirmation email to the user
  await sendResendEmail(env, {
    to: email,
    subject: `We received your request [Ticket #${ticketNumber}]`,
    html: `
      <div style="font-family: sans-serif; line-height: 1.5; color: #333;">
        <h2>Hello,</h2>
        <p>Thank you for reaching out to Audiory Support. We have received your message and generated ticket <strong>#${ticketNumber}</strong>.</p>
        <p>Our support team will review your query and reply to you as soon as possible.</p>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="font-size: 12px; color: #777;"><strong>Ticket Summary:</strong><br>${subject}</p>
      </div>
    `
  });

  return new Response(JSON.stringify({ success: true, ticket: newTicket }), {
    status: 201,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

// =============================================================
// FIXED TOO LOST PREFERENCES ROUTES
// =============================================================
//
// This version fixes the structural problem in the previous 2902-line block:
// the route code must run inside an async Worker request handler.
//
// Call from your existing async fetch(request, env, ctx) handler:
//
//   const preferencesResponse = await handlePreferencesRoutes(
//     request, env, url, userId, corsHeaders
//   );
//   if (preferencesResponse) return preferencesResponse;
//
// If the request is not a Preferences route, this function returns null.
// =============================================================

async function handlePreferencesRoutes(
  request,
  env,
  url,
  userId,
  corsHeaders
) {
// =============================================================
// PREFERENCES — ARTIST & LABEL
// =============================================================
//
// IMPORTANT SECURITY REQUIREMENT
//
// getAccessToken(env, userId) MUST return the Too Lost OAuth token
// belonging to THIS authenticated user.
//
// If your existing getAccessToken() currently uses one global
// client-credentials token for every Audiory user, that MUST be
// changed. Otherwise one user's Too Lost preferences can be
// returned to another user.
//
// JavaScript allows the extra userId argument even if your current
// helper only accepts env, but for proper account isolation your
// helper should actually use userId to retrieve that user's
// OAuth access token.
//
// =============================================================


// =============================================================
// COMMON JSON RESPONSE HELPER
// =============================================================

function preferencesJSON(
  data,
  status,
  corsHeaders
) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}


// =============================================================
// COMMON VALUE HELPERS
// =============================================================

function toNullableString(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  const text = String(value).trim();

  return text === ""
    ? null
    : text;
}


function toNullableBoolean(value) {
  if (
    value === true ||
    value === "true"
  ) {
    return true;
  }

  if (
    value === false ||
    value === "false"
  ) {
    return false;
  }

  return null;
}


function normalizePlatform(value) {
  const platform =
    String(value || "")
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, "_");

  if (
    platform === "applemusic" ||
    platform === "apple_music"
  ) {
    return "apple";
  }

  if (
    platform === "yt" ||
    platform === "ytmusic" ||
    platform === "youtube_music"
  ) {
    return "youtube";
  }

  return platform;
}


// =============================================================
// TOO LOST API
// =============================================================

async function fetchTooLostAPI(
  endpoint,
  method = "GET",
  body = null,
  accessToken,
  env
) {
  const baseUrl = (
    env.TOO_LOST_BASE_URL ||
    "https://api-sandbox.toolost.com/v1"
  ).replace(/\/$/, "");

  const options = {
    method,
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json",
      "Content-Type": "application/json"
    }
  };

  if (body !== null) {
    options.body =
      JSON.stringify(body);
  }

  return fetch(
    `${baseUrl}${endpoint}`,
    options
  );
}


// =============================================================
// USER AUTHENTICATION
// =============================================================
//
// Every route below requires the authenticated userId.
//
// The surrounding Worker must already set:
//
//   const userId = ...
//
// from the authenticated Audiory/Firebase user.
//
// =============================================================


// =============================================================
// TOO LOST ACCESS TOKEN
// =============================================================
//
// IMPORTANT:
//
// Use the existing shared OAuth helper.
//
// Pass userId so the helper can return the OAuth token for the
// CURRENT authenticated user.
//
// If your helper currently only accepts env, this call still works
// syntactically because JavaScript ignores extra arguments.
// However, the helper MUST actually use userId if it currently
// returns one shared token for every user.
//
// =============================================================

async function getUserTooLostAccessToken(
  env,
  userId
) {
  if (!userId) {
    throw new Error(
      "Unauthenticated."
    );
  }

  // This helper MUST resolve a Too Lost OAuth token for THIS user.
  // Never silently fall back to a global client-credentials token
  // for user-owned preference reads or writes.
  return getAccessToken(
    env,
    userId
  );
}

// Platform searches do not expose Audiory/Too Lost preference data.
// They can therefore use the existing application-level Too Lost token
// while user-owned preference endpoints remain strictly user-scoped.
async function getTooLostSearchAccessToken(env) {
  return getAccessToken(env);
}

async function proxyTooLostPublicGET(
  request,
  env,
  corsHeaders,
  userId,
  tooLostPath
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthenticated." },
      401,
      corsHeaders
    );
  }

  let accessToken;

  try {
    accessToken = await getTooLostSearchAccessToken(env);
  } catch (authError) {
    console.error(
      "Too Lost public lookup authentication failed:",
      authError
    );

    return preferencesJSON(
      {
        error: "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost."
      },
      401,
      corsHeaders
    );
  }

  try {
    const upstream = await fetchTooLostAPI(
      tooLostPath,
      "GET",
      null,
      accessToken,
      env
    );

    const text = await upstream.text();
    let data = {};

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    return preferencesJSON(
      data,
      upstream.status,
      corsHeaders
    );
  } catch (error) {
    console.error(
      "Too Lost public lookup failed:",
      error
    );

    return preferencesJSON(
      {
        error: "Could not connect to Too Lost.",
        details: error?.message || String(error)
      },
      502,
      corsHeaders
    );
  }
}


async function proxyTooLostPublicPOST(
  request,
  env,
  corsHeaders,
  userId,
  tooLostPath
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthenticated." },
      401,
      corsHeaders
    );
  }

  const body = await request.json().catch(() => ({}));
  let accessToken;

  try {
    accessToken = await getTooLostSearchAccessToken(env);
  } catch (authError) {
    return preferencesJSON(
      {
        error: "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost."
      },
      401,
      corsHeaders
    );
  }

  try {
    const upstream = await fetchTooLostAPI(
      tooLostPath,
      "POST",
      body,
      accessToken,
      env
    );

    const text = await upstream.text();
    let data = {};

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }

    return preferencesJSON(
      data,
      upstream.status,
      corsHeaders
    );
  } catch (error) {
    console.error(
      "Too Lost public POST lookup failed:",
      error
    );

    return preferencesJSON(
      {
        error: "Could not connect to Too Lost.",
        details: error?.message || String(error)
      },
      502,
      corsHeaders
    );
  }
}


// =============================================================
// ADDITIONAL TOO LOST GET HELPER
// =============================================================

async function proxyTooLostPreferencesGET(
  request,
  env,
  corsHeaders,
  userId,
  tooLostPath
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthenticated."
      },
      401,
      corsHeaders
    );
  }

  let accessToken;

  try {
    accessToken =
      await getUserTooLostAccessToken(
        env,
        userId
      );
  } catch (authError) {
    console.error(
      "Too Lost Preferences authentication failed:",
      authError
    );

    return preferencesJSON(
      {
        error:
          "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost."
      },
      401,
      corsHeaders
    );
  }

  try {
    const upstream =
      await fetchTooLostAPI(
        tooLostPath,
        "GET",
        null,
        accessToken,
        env
      );

    const rawText =
      await upstream.text();

    let responseData = {};

    try {
      responseData =
        rawText
          ? JSON.parse(rawText)
          : {};
    } catch {
      responseData = {
        raw: rawText
      };
    }

    return preferencesJSON(
      responseData,
      upstream.status,
      corsHeaders
    );

  } catch (error) {
    console.error(
      "Too Lost Preferences GET request failed:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Could not connect to Too Lost.",
        details:
          error?.message ||
          String(error)
      },
      502,
      corsHeaders
    );
  }
}


// =============================================================
// ADDITIONAL TOO LOST POST HELPER
// =============================================================

async function proxyTooLostPreferencesPOST(
  request,
  env,
  corsHeaders,
  userId,
  tooLostPath
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthenticated."
      },
      401,
      corsHeaders
    );
  }

  const body =
    await request
      .json()
      .catch(() => ({}));

  let accessToken;

  try {
    accessToken =
      await getUserTooLostAccessToken(
        env,
        userId
      );
  } catch (authError) {
    console.error(
      "Too Lost Preferences authentication failed:",
      authError
    );

    return preferencesJSON(
      {
        error:
          "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost."
      },
      401,
      corsHeaders
    );
  }

  try {
    const upstream =
      await fetchTooLostAPI(
        tooLostPath,
        "POST",
        body,
        accessToken,
        env
      );

    const rawText =
      await upstream.text();

    let responseData = {};

    try {
      responseData =
        rawText
          ? JSON.parse(rawText)
          : {};
    } catch {
      responseData = {
        raw: rawText
      };
    }

    return preferencesJSON(
      responseData,
      upstream.status,
      corsHeaders
    );

  } catch (error) {
    console.error(
      "Too Lost Preferences POST request failed:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Could not connect to Too Lost.",
        details:
          error?.message ||
          String(error)
      },
      502,
      corsHeaders
    );
  }
}


// =============================================================
// =============================================================
// GET /api/preferences/artists
// =============================================================
//
// IMPORTANT SECURITY RULE:
// This endpoint MUST NEVER proxy the shared Too Lost account.
// It returns only the artist preference owned by this Audiory user.
// =============================================================

if (
  url.pathname ===
    "/api/preferences/artists" &&
  request.method === "GET"
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthenticated." },
      401,
      corsHeaders
    );
  }

  const artistKey =
    `PREFERENCES_ARTIST_${userId}`;

  let artist = null;

  if (env.AUDIORY_KV) {
    const raw =
      await env.AUDIORY_KV.get(artistKey);

    if (raw) {
      try {
        artist = JSON.parse(raw);
      } catch {
        artist = null;
      }
    }
  }

  const artists = artist ? [artist] : [];

  return preferencesJSON(
    {
      data: artists,
      message: "Preference artists retrieved."
    },
    200,
    corsHeaders
  );
}


// =============================================================
// =============================================================
// GET /api/preferences/label/artist/:id
// =============================================================
// Return only an artist already owned by this Audiory user.
// Never query a shared Too Lost account for an arbitrary ID.
// =============================================================

const labelArtistMatch =
  url.pathname.match(
    /^\/api\/preferences\/label\/artist\/(\d+)$/
  );

if (
  labelArtistMatch &&
  request.method === "GET"
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthenticated." },
      401,
      corsHeaders
    );
  }

  const artistId = Number(labelArtistMatch[1]);
  let foundArtist = null;

  if (env.AUDIORY_KV) {
    const labelRaw = await env.AUDIORY_KV.get(
      `PREFERENCES_LABEL_${userId}`
    );

    if (labelRaw) {
      try {
        const labelData = JSON.parse(labelRaw);
        if (Array.isArray(labelData?.artists)) {
          foundArtist =
            labelData.artists.find(
              artist => Number(artist?.id) === artistId
            ) || null;
        }
      } catch {}
    }

    if (!foundArtist) {
      const artistRaw = await env.AUDIORY_KV.get(
        `PREFERENCES_ARTIST_${userId}`
      );

      if (artistRaw) {
        try {
          const artistData = JSON.parse(artistRaw);
          if (Number(artistData?.id) === artistId) {
            foundArtist = artistData;
          }
        } catch {}
      }
    }
  }

  if (!foundArtist) {
    return preferencesJSON(
      { error: "Artist not found for this user." },
      404,
      corsHeaders
    );
  }

  return preferencesJSON(
    {
      data: foundArtist,
      message: "Artist retrieved."
    },
    200,
    corsHeaders
  );
}


// GET /api/preferences/search-spotify
// =============================================================

if (
  url.pathname ===
    "/api/preferences/search-spotify" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/search-spotify${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/search-yt-channel
// =============================================================

if (
  url.pathname ===
    "/api/preferences/search-yt-channel" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/search-yt-channel${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/search-apple
// =============================================================

if (
  url.pathname ===
    "/api/preferences/search-apple" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/search-apple${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/get-spotify-artist
// =============================================================

if (
  url.pathname ===
    "/api/preferences/get-spotify-artist" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/get-spotify-artist${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/get-yt-channel
// =============================================================

if (
  url.pathname ===
    "/api/preferences/get-yt-channel" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/get-yt-channel${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/get-apple-artist
// =============================================================

if (
  url.pathname ===
    "/api/preferences/get-apple-artist" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/get-apple-artist${url.search || ""}`
  );
}


// =============================================================
// GET /api/preferences/artist-via-link
// =============================================================

if (
  url.pathname ===
    "/api/preferences/artist-via-link" &&
  request.method === "GET"
) {
  return proxyTooLostPublicGET(
    request,
    env,
    corsHeaders,
    userId,
    `/preferences/artist-via-link${url.search || ""}`
  );
}


// =============================================================
// POST /api/preferences/artist/get-artist-via-url
// =============================================================

if (
  url.pathname ===
    "/api/preferences/artist/get-artist-via-url" &&
  request.method === "POST"
) {
  return proxyTooLostPublicPOST(
    request,
    env,
    corsHeaders,
    userId,
    "/preferences/artist/get-artist-via-url"
  );
}


// =============================================================
// ARTIST PLATFORM SEARCH
// =============================================================
//
// POST /api/preferences/search/artist-platform
//
// Primary Too Lost endpoint:
//
// POST /preferences/search/artist-platform
//
// Body:
//
// {
//   platform: "spotify",
//   term: "Official Bigi",
//   limit: 5
// }
//
// If the newer endpoint returns 404 / 405 / 500 / 502 / 503,
// we try the older platform-specific endpoints already present
// in your Worker.
//
// This prevents the Audiory Worker from hiding the actual Too Lost
// response behind its own generic 500.
//
// =============================================================

if (
  url.pathname ===
    "/api/preferences/search/artist-platform" &&
  request.method === "POST"
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthorized"
      },
      401,
      corsHeaders
    );
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return preferencesJSON(
      {
        error:
          "Invalid JSON request body."
      },
      400,
      corsHeaders
    );
  }

  const normalizedPlatform =
    normalizePlatform(
      body?.platform
    );

  const term =
    String(
      body?.term ??
      body?.artist ??
      body?.name ??
      ""
    ).trim();

  let limit =
    Number(body?.limit);

  if (
    !Number.isFinite(limit) ||
    limit < 1
  ) {
    limit = 5;
  }

  limit =
    Math.min(
      Math.floor(limit),
      50
    );

  const allowedPlatforms = [
    "spotify",
    "youtube",
    "apple",
    "audiomack"
  ];

  if (
    !allowedPlatforms.includes(
      normalizedPlatform
    )
  ) {
    return preferencesJSON(
      {
        error:
          "Invalid platform.",
        allowedPlatforms,
        received:
          body?.platform || null
      },
      400,
      corsHeaders
    );
  }

  if (!term) {
    return preferencesJSON(
      {
        error:
          "Search term is required."
      },
      400,
      corsHeaders
    );
  }

  if (term.length > 255) {
    return preferencesJSON(
      {
        error:
          "Search term must be 255 characters or less."
      },
      400,
      corsHeaders
    );
  }

  let accessToken;

  try {
    accessToken =
      await getTooLostSearchAccessToken(env);
  } catch (authError) {
    console.error(
      "Too Lost preference search authentication error:",
      authError
    );

    return preferencesJSON(
      {
        error:
          "Too Lost Authentication Failed",
        details:
          authError?.message ||
          String(authError)
      },
      401,
      corsHeaders
    );
  }

  const tooLostPayload = {
    platform:
      normalizedPlatform,

    term,

    limit
  };

  console.log(
    "TOO LOST ARTIST PLATFORM SEARCH REQUEST:",
    JSON.stringify(
      tooLostPayload,
      null,
      2
    )
  );

  // -----------------------------------------------------------
  // PRIMARY SEARCH
  // -----------------------------------------------------------

  try {
    const upstream =
      await fetchTooLostAPI(
        "/preferences/search/artist-platform",
        "POST",
        tooLostPayload,
        accessToken,
        env
      );

    const upstreamText =
      await upstream.text();

    let upstreamBody = {};

    try {
      upstreamBody =
        upstreamText
          ? JSON.parse(upstreamText)
          : {};
    } catch {
      upstreamBody = {
        raw: upstreamText
      };
    }

    console.log(
      "TOO LOST ARTIST PLATFORM SEARCH RESPONSE:",
      JSON.stringify(
        {
          status:
            upstream.status,
          response:
            upstreamBody
        },
        null,
        2
      )
    );

    // ---------------------------------------------------------
    // SUCCESS
    // ---------------------------------------------------------

    if (upstream.ok) {
      return preferencesJSON(
        upstreamBody,
        200,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // FALLBACK
    //
    // Existing older endpoints:
    //
    // Spotify:
    // GET /preferences/search-spotify?artist=...
    //
    // YouTube:
    // GET /preferences/search-yt-channel?channel=...
    //
    // Apple:
    // GET /preferences/search-apple?artist=...
    // ---------------------------------------------------------

    const shouldFallback =
      [
        404,
        405,
        500,
        502,
        503
      ].includes(
        upstream.status
      );

    if (!shouldFallback) {
      return preferencesJSON(
        {
          error:
            "Too Lost rejected the platform search.",
          tooLostStatus:
            upstream.status,
          tooLostResponse:
            upstreamBody
        },
        upstream.status,
        corsHeaders
      );
    }

    let fallbackPath =
      null;

    if (
      normalizedPlatform ===
      "spotify"
    ) {
      fallbackPath =
        `/preferences/search-spotify?artist=${encodeURIComponent(
          term
        )}&limit=${encodeURIComponent(
          limit
        )}`;
    }

    if (
      normalizedPlatform ===
      "youtube"
    ) {
      fallbackPath =
        `/preferences/search-yt-channel?channel=${encodeURIComponent(
          term
        )}&limit=${encodeURIComponent(
          limit
        )}`;
    }

    if (
      normalizedPlatform ===
      "apple"
    ) {
      fallbackPath =
        `/preferences/search-apple?artist=${encodeURIComponent(
          term
        )}&limit=${encodeURIComponent(
          limit
        )}`;
    }

    // Audiomack does not have an old GET fallback in the
    // supplied Worker, so keep the original upstream response.
    if (!fallbackPath) {
      return preferencesJSON(
        {
          error:
            "Too Lost artist-platform search failed.",
          tooLostStatus:
            upstream.status,
          tooLostResponse:
            upstreamBody
        },
        502,
        corsHeaders
      );
    }

    console.warn(
      "Trying legacy Too Lost artist platform search:",
      fallbackPath
    );

    const fallback =
      await fetchTooLostAPI(
        fallbackPath,
        "GET",
        null,
        accessToken,
        env
      );

    const fallbackText =
      await fallback.text();

    let fallbackBody = {};

    try {
      fallbackBody =
        fallbackText
          ? JSON.parse(
              fallbackText
            )
          : {};
    } catch {
      fallbackBody = {
        raw: fallbackText
      };
    }

    console.log(
      "TOO LOST LEGACY ARTIST SEARCH RESPONSE:",
      JSON.stringify(
        {
          status:
            fallback.status,
          response:
            fallbackBody
        },
        null,
        2
      )
    );

    if (fallback.ok) {
      return preferencesJSON(
        fallbackBody,
        200,
        corsHeaders
      );
    }

    return preferencesJSON(
      {
        error:
          "Artist platform search failed.",
        primarySearch: {
          status:
            upstream.status,
          response:
            upstreamBody
        },
        fallbackSearch: {
          status:
            fallback.status,
          response:
            fallbackBody
        }
      },
      502,
      corsHeaders
    );

  } catch (error) {
    console.error(
      "Preference platform search failed:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Preference platform search failed.",
        details:
          error?.message ||
          String(error)
      },
      502,
      corsHeaders
    );
  }
}


// =============================================================
// =============================================================
// GET ARTIST PREFERENCES
// =============================================================
//
// Audiory is the source of truth for the user's visible preferences.
// We intentionally DO NOT call Too Lost here because a shared
// application token can represent another Audiory user's Too Lost
// account. The saved Too Lost ID remains in this user's KV record.
// =============================================================

if (
  url.pathname ===
    "/api/preferences/artist" &&
  request.method === "GET"
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthenticated." },
      401,
      corsHeaders
    );
  }

  const kvKey =
    `PREFERENCES_ARTIST_${userId}`;

  let artistData = null;

  if (env.AUDIORY_KV) {
    const cached =
      await env.AUDIORY_KV.get(kvKey);

    if (cached) {
      try {
        artistData = JSON.parse(cached);
      } catch {
        artistData = null;
      }
    }
  }

  if (!artistData) {
    artistData = {
      id: null,
      artistName: "",
      about: "",
      primaryGenre: "",
      secondaryGenre: "",
      language: "",
      profileImg: "",
      label: "",
      cLine: "",
      pLine: "",
      releaseTime: "",
      timeZone: "Africa/Nairobi",
      collaborators: [],
      defaultRoles: [],
      territories: [],
      platforms: {
        spotify: "",
        appleMusic: "",
        soundcloud: "",
        vevo: "",
        website: "",
        youtube: ""
      },
      social: {
        facebook: "",
        instagram: "",
        twitter: "",
        youtube: ""
      },
      audiomack: {
        link: "",
        status: ""
      },
      deliveries: {
        beatport: false,
        delivery_beatport_link: "",
        delivery_even: false,
        delivery_facebook: false,
        delivery_hook: false,
        delivery_lyricfind: false,
        delivery_soundcloud: false,
        delivery_soundexchange: false,
        delivery_tracklib: false,
        delivery_youtube: false
      },
      additional: {
        allmusic: "",
        ddex: "",
        isni: "",
        musicbrainz: "",
        wikipedia: ""
      },
      stores: [],
      metadata: {
        artists: [],
        credits: [],
        writers: []
      }
    };
  }

  return preferencesJSON(
    {
      data: { artist: artistData },
      message: "Artist preferences retrieved.",
      syncedWithTooLost: Boolean(artistData?.id)
    },
    200,
    corsHeaders
  );
}


// POST ARTIST PREFERENCES
// =============================================================
//
// POST /api/preferences/artist/submit
//
// CRITICAL CHANGE:
//
// We DO NOT blindly send:
//
//   id: null
//
// anymore.
//
// Before saving, we retrieve the existing artist preference and
// obtain its Too Lost ID.
//
// If the user is editing artist 178145, then the payload becomes:
//
//   id: 178145
//
// This tells Too Lost to update the existing artist instead of
// creating another artist.
//
// =============================================================

if (
  url.pathname ===
    "/api/preferences/artist/submit" &&
  request.method === "POST"
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthenticated."
      },
      401,
      corsHeaders
    );
  }

  const body =
    await request
      .json()
      .catch(() => ({}));

  const artistName =
    String(
      body.artistName || ""
    ).trim();

  if (!artistName) {
    return preferencesJSON(
      {
        error:
          "Artist name is required."
      },
      400,
      corsHeaders
    );
  }

  const platforms =
    body.platforms || {};

  const social =
    body.social || {};

  const metadata =
    body.metadata || {};

  // -----------------------------------------------------------
  // FIND EXISTING ARTIST ID
  // -----------------------------------------------------------

  const artistKVKey =
    `PREFERENCES_ARTIST_${userId}`;

  let existingArtist =
    null;

  let existingArtistId =
    null;

  // First try KV because this is already scoped to userId.
  if (env.AUDIORY_KV) {
    const cachedArtist =
      await env.AUDIORY_KV.get(
        artistKVKey
      );

    if (cachedArtist) {
      try {
        existingArtist =
          JSON.parse(
            cachedArtist
          );
      } catch {
        existingArtist =
          null;
      }
    }
  }

  if (
    existingArtist?.id
  ) {
    existingArtistId =
      Number(
        existingArtist.id
      );
  }

  // -----------------------------------------------------------
  // SECURITY: do NOT look up a missing ID in Too Lost.
  //
  // A shared/global Too Lost token could return another Audiory
  // user's artist. When this user's KV has no ID, this is a NEW
  // artist and Too Lost must create it.
  // -----------------------------------------------------------

  let tooLostAccessToken;

  try {
    tooLostAccessToken =
      await getUserTooLostAccessToken(
        env,
        userId
      );
  } catch (authError) {
    console.error(
      "Too Lost artist preferences authentication failed:",
      authError
    );

    return preferencesJSON(
      {
        error: "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost.",
        syncedWithTooLost: false
      },
      401,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Normalize incoming fields
  // -----------------------------------------------------------

  const tooLostPayload = {
    artistName:
      toNullableString(
        artistName
      ),

    metadata: {
      artists:
        Array.isArray(
          metadata.artists
        ) &&
        metadata.artists.length > 0
          ? metadata.artists
          : [
              {
                name:
                  toNullableString(
                    artistName
                  ) ||
                  "Unknown Artist",

                role:
                  "Main Artist"
              }
            ],

      credits:
        Array.isArray(
          metadata.credits
        )
          ? metadata.credits
          : [],

      writers:
        Array.isArray(
          metadata.writers
        )
          ? metadata.writers
          : []
    },

    about:
      toNullableString(
        body.about
      ),

    additional: {
      allmusic:
        toNullableString(
          body.additional?.allmusic
        ),

      ddex:
        toNullableString(
          body.additional?.ddex
        ),

      isni:
        toNullableString(
          body.additional?.isni
        ),

      musicbrainz:
        toNullableString(
          body.additional?.musicbrainz
        ),

      wikipedia:
        toNullableString(
          body.additional?.wikipedia
        )
    },

    audiomack: {
      link:
        toNullableString(
          body.audiomack?.link
        ),

      status:
        toNullableBoolean(
          body.audiomack?.status
        )
    },

    c_line:
      toNullableString(
        body.c_line ??
        body.cLine
      ),

    collaborators:
      Array.isArray(
        body.collaborators
      )
        ? body.collaborators
        : [],

    deliveries: {
      beatport:
        toNullableBoolean(
          body.deliveries?.beatport
        ),

      delivery_beatport_link:
        toNullableString(
          body.deliveries
            ?.delivery_beatport_link
        ),

      delivery_even:
        toNullableBoolean(
          body.deliveries?.delivery_even
        ),

      delivery_facebook:
        toNullableBoolean(
          body.deliveries
            ?.delivery_facebook
        ),

      delivery_hook:
        toNullableBoolean(
          body.deliveries?.delivery_hook
        ),

      delivery_lyricfind:
        toNullableBoolean(
          body.deliveries
            ?.delivery_lyricfind
        ),

      delivery_soundcloud:
        toNullableBoolean(
          body.deliveries
            ?.delivery_soundcloud
        ),

      delivery_soundexchange:
        toNullableBoolean(
          body.deliveries
            ?.delivery_soundexchange
        ),

      delivery_tracklib:
        toNullableBoolean(
          body.deliveries
            ?.delivery_tracklib
        ),

      delivery_youtube:
        toNullableBoolean(
          body.deliveries
            ?.delivery_youtube
        )
    },

    // ---------------------------------------------------------
    // CRITICAL:
    //
    // Existing artist => existing ID
    // New artist      => null
    // ---------------------------------------------------------

    id:
      existingArtistId ||
      null,

    img:
      toNullableString(
        body.img ??
        body.profileImg
      ),

    label:
      toNullableString(
        body.label
      ),

    language:
      toNullableString(
        body.language
      ),

    p_line:
      toNullableString(
        body.p_line ??
        body.pLine
      ),

    platforms: {
      appleMusic:
        toNullableString(
          body.platforms
            ?.appleMusic ??
          body.platforms
            ?.apple_music
        ),

      soundcloud:
        toNullableString(
          body.platforms
            ?.soundcloud
        ),

      spotify:
        toNullableString(
          body.platforms
            ?.spotify
        ),

      vevo:
        toNullableString(
          body.platforms
            ?.vevo
        ),

      website:
        toNullableString(
          body.platforms
            ?.website
        ),

      youtube:
        toNullableString(
          body.platforms
            ?.youtube
        )
    },

    primaryGenre:
      toNullableString(
        body.primaryGenre
      ),

    releaseTime:
      toNullableString(
        body.releaseTime
      ),

    removeImg:
      body.removeImg === true,

    secondaryGenre:
      toNullableString(
        body.secondaryGenre
      ),

    social: {
      facebook:
        toNullableString(
          body.social?.facebook
        ),

      instagram:
        toNullableString(
          body.social?.instagram
        ),

      twitter:
        toNullableString(
          body.social?.twitter
        ),

      youtube:
        toNullableString(
          body.social?.youtube
        )
    },

    stores:
      Array.isArray(
        body.stores
      )
        ? body.stores
        : [],

    territories:
      Array.isArray(
        body.territories
      )
        ? body.territories
        : [],

    timeZone:
      toNullableString(
        body.timeZone ??
        body.timezone ??
        body.releaseTimezone
      ) ||
      "Africa/Nairobi"
  };

  console.log(
    "EXISTING TOO LOST ARTIST ID:",
    existingArtistId
  );

  console.log(
    "FINAL TOO LOST ARTIST PAYLOAD:",
    JSON.stringify(
      tooLostPayload,
      null,
      2
    )
  );

  // -----------------------------------------------------------
  // Submit
  // -----------------------------------------------------------

  let tooLostResponse;

  let tooLostJson =
    {};

  try {
    tooLostResponse =
      await fetchTooLostAPI(
        "/preferences/artist/submit",
        "POST",
        tooLostPayload,
        tooLostAccessToken,
        env
      );

    const rawTooLostBody =
      await tooLostResponse.text();

    try {
      tooLostJson =
        rawTooLostBody
          ? JSON.parse(
              rawTooLostBody
            )
          : {};
    } catch {
      tooLostJson = {
        raw:
          rawTooLostBody
      };
    }

    console.log(
      "TOO LOST ARTIST SUBMIT:",
      {
        status:
          tooLostResponse.status,
        response:
          tooLostJson
      }
    );

    if (
      !tooLostResponse.ok
    ) {
      return preferencesJSON(
        {
          error:
            "Too Lost rejected the artist preferences.",

          tooLostStatus:
            tooLostResponse.status,

          tooLostResponse:
            tooLostJson,

          artistIdSent:
            tooLostPayload.id
        },
        tooLostResponse.status,
        corsHeaders
      );
    }

  } catch (error) {
    console.error(
      "Too Lost artist preferences request failed:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Could not connect to Too Lost.",

        details:
          error?.message ||
          String(error),

        syncedWithTooLost:
          false
      },
      502,
      corsHeaders
    );
  }

  // -----------------------------------------------------------
  // Determine the ID returned by Too Lost.
  //
  // This is important for a newly-created artist.
  // -----------------------------------------------------------

  const returnedArtist =
    tooLostJson?.data?.artist ||
    tooLostJson?.artist ||
    (
      tooLostJson?.data &&
      typeof tooLostJson.data ===
        "object" &&
      !Array.isArray(
        tooLostJson.data
      )
        ? tooLostJson.data
        : null
    );

  const savedArtistId =
    Number(
      returnedArtist?.id ||
      tooLostJson?.data?.id ||
      existingArtistId ||
      0
    ) || null;

  // -----------------------------------------------------------
  // Save only after Too Lost accepts.
  // -----------------------------------------------------------

  const savedArtist = {
    ...tooLostPayload,

    id:
      savedArtistId,

    cLine:
      tooLostPayload.c_line,

    pLine:
      tooLostPayload.p_line,

    profileImg:
      tooLostPayload.img,

    savedAt:
      new Date().toISOString()
  };

  if (
    env.AUDIORY_KV
  ) {
    await env.AUDIORY_KV.put(
      artistKVKey,
      JSON.stringify(
        savedArtist
      )
    );
  }

  return preferencesJSON(
    {
      success:
        true,

      message:
        "Artist preferences saved and synchronized with Too Lost.",

      data: {
        artist:
          savedArtist
      },

      syncedWithTooLost:
        true
    },
    200,
    corsHeaders
  );
}


// =============================================================
// =============================================================
// GET LABEL PREFERENCES
// =============================================================
//
// User-visible label data is read ONLY from the user's KV namespace
// key. Never proxy a shared Too Lost label response into another user.
// =============================================================

if (
  url.pathname ===
    "/api/preferences/label" &&
  request.method === "GET"
) {
  if (!userId) {
    return preferencesJSON(
      { error: "Unauthorized" },
      401,
      corsHeaders
    );
  }

  const labelKey =
    `PREFERENCES_LABEL_${userId}`;

  let labelData = null;

  if (env.AUDIORY_KV) {
    const rawData =
      await env.AUDIORY_KV.get(labelKey);

    if (rawData) {
      try {
        labelData = JSON.parse(rawData);
      } catch {
        labelData = null;
      }
    }
  }

  if (!labelData) {
    labelData = {
      label: {
        id: null,
        name: "",
        about: "",
        profileImg: null,
        social: {
          facebook: "",
          instagram: "",
          twitter: "",
          youtube: ""
        },
        platforms: { website: "" }
      },
      artists: []
    };
  }

  return preferencesJSON(
    {
      data: labelData,
      message: "Label preferences retrieved.",
      syncedWithTooLost: Boolean(labelData?.label?.id)
    },
    200,
    corsHeaders
  );
}


// POST LABEL PREFERENCES
// =============================================================

if (
  url.pathname ===
    "/api/preferences/label/submit" &&
  request.method === "POST"
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthorized"
      },
      401,
      corsHeaders
    );
  }

  try {
    const requestText =
      await request.text();

    let body =
      {};

    try {
      body =
        JSON.parse(
          requestText ||
          "{}"
        );
    } catch (jsonError) {
      return preferencesJSON(
        {
          error:
            "Invalid JSON request body.",
          details:
            jsonError?.message ||
            String(jsonError)
        },
        400,
        corsHeaders
      );
    }

    const name =
      toNullableString(
        body.name
      );

    if (!name) {
      return preferencesJSON(
        {
          error:
            "Label name is required."
        },
        400,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // FIND EXISTING LABEL ID
    // ---------------------------------------------------------

    const labelKVKey =
      `PREFERENCES_LABEL_${userId}`;

    let existingLabelId =
      null;

    // KV first.
    if (
      env.AUDIORY_KV
    ) {
      const cached =
        await env.AUDIORY_KV.get(
          labelKVKey
        );

      if (cached) {
        try {
          const parsed =
            JSON.parse(
              cached
            );

          existingLabelId =
            Number(
              parsed?.label?.id ||
              parsed?.id ||
              0
            ) || null;

        } catch {
          existingLabelId =
            null;
        }
      }
    }

    let accessToken;

    try {
      accessToken =
        await getUserTooLostAccessToken(
          env,
          userId
        );
    } catch (authError) {
      console.error(
        "TOO LOST LABEL AUTHENTICATION ERROR:",
        authError
      );

      return preferencesJSON(
        {
          error: "Too Lost Authentication Failed",
          details:
            authError?.message ||
            "Unable to authenticate with Too Lost."
        },
        401,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // SECURITY: never discover a missing label ID from the shared
    // Too Lost account. Missing KV ID means this user is creating
    // a new label. Existing IDs are only taken from this user's KV.
    // ---------------------------------------------------------

    // ---------------------------------------------------------
    // CANONICAL LABEL PAYLOAD
    // ---------------------------------------------------------

    const tooLostPayload = {
      name,

      about:
        toNullableString(
          body.about
        )?.slice(
          0,
          500
        ) || null,

      img:
        toNullableString(
          body.img ??
          body.profileImg
        ),

      platforms: {
        website:
          toNullableString(
            body.platforms
              ?.website
          )
      },

      removeImg:
        toNullableBoolean(
          body.removeImg
        ) === true,

      social: {
        facebook:
          toNullableString(
            body.social
              ?.facebook
          ),

        instagram:
          toNullableString(
            body.social
              ?.instagram
          ),

        twitter:
          toNullableString(
            body.social
              ?.twitter
          ),

        youtube:
          toNullableString(
            body.social
              ?.youtube
          )
      }
    };

    // ---------------------------------------------------------
    // IMPORTANT:
    //
    // If Too Lost's label endpoint supports an ID for updating,
    // preserve it rather than creating another label.
    //
    // Do NOT send id:null.
    //
    // Only add it when an existing ID is known.
    // ---------------------------------------------------------

    if (
      existingLabelId
    ) {
      tooLostPayload.id =
        existingLabelId;
    }

    console.log(
      "AUDIORY -> TOO LOST LABEL PAYLOAD:",
      JSON.stringify(
        tooLostPayload,
        null,
        2
      )
    );

    // ---------------------------------------------------------
    // SEND TO TOO LOST
    // ---------------------------------------------------------

    let upstreamRes;

    try {
      upstreamRes =
        await fetchTooLostAPI(
          "/preferences/label/submit",
          "POST",
          tooLostPayload,
          accessToken,
          env
        );

    } catch (networkError) {
      console.error(
        "TOO LOST LABEL NETWORK ERROR:",
        networkError
      );

      return preferencesJSON(
        {
          error:
            "Unable to connect to Too Lost.",
          details:
            networkError?.message ||
            String(networkError)
        },
        502,
        corsHeaders
      );
    }

    const upstreamText =
      await upstreamRes.text();

    let upstreamData =
      {};

    try {
      upstreamData =
        JSON.parse(
          upstreamText ||
          "{}"
        );
    } catch {
      upstreamData = {
        raw:
          upstreamText
      };
    }

    console.log(
      "TOO LOST LABEL RESPONSE:",
      JSON.stringify(
        {
          status:
            upstreamRes.status,
          ok:
            upstreamRes.ok,
          response:
            upstreamData
        },
        null,
        2
      )
    );

    if (
      !upstreamRes.ok
    ) {
      return preferencesJSON(
        {
          error:
            "Too Lost rejected the label preferences.",

          tooLostStatus:
            upstreamRes.status,

          tooLostResponse:
            upstreamData,

          labelIdSent:
            existingLabelId
        },
        upstreamRes.status,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // Determine saved label ID.
    // ---------------------------------------------------------

    const returnedLabel =
      upstreamData?.data?.label ||
      upstreamData?.label ||
      null;

    const savedLabelId =
      Number(
        returnedLabel?.id ||
        upstreamData?.data?.id ||
        existingLabelId ||
        0
      ) || null;

    // ---------------------------------------------------------
    // Preserve existing artists.
    // ---------------------------------------------------------

    let existingArtists =
      [];

    if (
      env.AUDIORY_KV
    ) {
      const cached =
        await env.AUDIORY_KV.get(
          labelKVKey
        );

      if (cached) {
        try {
          const parsed =
            JSON.parse(
              cached
            );

          if (
            Array.isArray(
              parsed?.artists
            )
          ) {
            existingArtists =
              parsed.artists;
          }

        } catch {
          existingArtists =
            [];
        }
      }
    }

    // SECURITY: Too Lost may return every artist attached to the
    // shared label account. Never copy that list into this user's KV.
    // Only retain artists that this Audiory user already owns locally.
    // The user's primary artist ID is the ownership boundary.
    let ownedArtistIds = new Set();

    if (env.AUDIORY_KV) {
      const artistRaw = await env.AUDIORY_KV.get(
        `PREFERENCES_ARTIST_${userId}`
      );

      if (artistRaw) {
        try {
          const artistData = JSON.parse(artistRaw);
          const artistId = Number(artistData?.id || 0);
          if (Number.isInteger(artistId) && artistId > 0) {
            ownedArtistIds.add(artistId);
          }
        } catch {}
      }
    }

    const responseArtists =
      Array.isArray(upstreamData?.data?.artists)
        ? upstreamData.data.artists
        : [];

    const newlyReturnedOwnedArtists =
      responseArtists.filter(
        artist =>
          ownedArtistIds.has(Number(artist?.id))
      );

    const safeArtists =
      [...existingArtists, ...newlyReturnedOwnedArtists]
        .filter(Boolean)
        .filter((artist, index, array) => {
          const id = Number(artist?.id || 0);
          if (!id || !ownedArtistIds.has(id)) return false;
          return array.findIndex(
            item => Number(item?.id || 0) === id
          ) === index;
        });

    const savedData = {
      label: {
        id:
          savedLabelId,

        name,

        about:
          tooLostPayload.about,

        profileImg:
          tooLostPayload.img,

        platforms:
          tooLostPayload.platforms,

        social:
          tooLostPayload.social
      },

      artists:
        safeArtists
    };

    // ---------------------------------------------------------
    // USER-SPECIFIC KV ONLY
    // ---------------------------------------------------------

    if (
      env.AUDIORY_KV
    ) {
      await env.AUDIORY_KV.put(
        labelKVKey,
        JSON.stringify(
          savedData
        )
      );
    }

    return preferencesJSON(
      {
        message:
          upstreamData?.message ||
          "Label preferences updated.",

        data:
          savedData,

        syncedWithTooLost:
          true
      },
      200,
      corsHeaders
    );

  } catch (error) {
    console.error(
      "AUDIORY LABEL SAVE ERROR:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Audiory could not save label preferences.",
        details:
          error?.message ||
          String(error)
      },
      500,
      corsHeaders
    );
  }
}


// =============================================================
// POST /api/preferences/label/artist/remove
// =============================================================
//
// Removes an artist from label management.
//
// =============================================================

if (
  url.pathname ===
    "/api/preferences/label/artist/remove" &&
  request.method === "POST"
) {
  if (!userId) {
    return preferencesJSON(
      {
        error:
          "Unauthorized"
      },
      401,
      corsHeaders
    );
  }

  let body;

  try {
    body =
      await request.json();
  } catch {
    return preferencesJSON(
      {
        error:
          "Invalid JSON request body."
      },
      400,
      corsHeaders
    );
  }

  const artistId =
    Number(
      body?.artistId
    );

  if (
    !Number.isInteger(
      artistId
    ) ||
    artistId <= 0
  ) {
    return preferencesJSON(
      {
        error:
          "A valid artistId is required."
      },
      400,
      corsHeaders
    );
  }

  // SECURITY: never allow a user to remove an artist merely by
  // guessing a Too Lost artist ID. The ID must exist in this user's
  // locally stored label artists or primary artist record.
  let ownsArtist = false;

  if (env.AUDIORY_KV) {
    const labelRaw = await env.AUDIORY_KV.get(
      `PREFERENCES_LABEL_${userId}`
    );

    if (labelRaw) {
      try {
        const labelData = JSON.parse(labelRaw);
        ownsArtist =
          Array.isArray(labelData?.artists) &&
          labelData.artists.some(
            artist => Number(artist?.id) === artistId
          );
      } catch {}
    }

    if (!ownsArtist) {
      const artistRaw = await env.AUDIORY_KV.get(
        `PREFERENCES_ARTIST_${userId}`
      );

      if (artistRaw) {
        try {
          const artistData = JSON.parse(artistRaw);
          ownsArtist = Number(artistData?.id) === artistId;
        } catch {}
      }
    }
  }

  if (!ownsArtist) {
    return preferencesJSON(
      { error: "Artist not found for this user." },
      404,
      corsHeaders
    );
  }

  try {
    const accessToken =
      await getUserTooLostAccessToken(
        env,
        userId
      );

    const upstream =
      await fetchTooLostAPI(
        "/preferences/label/artist/remove",
        "POST",
        {
          artistId
        },
        accessToken,
        env
      );

    const upstreamText =
      await upstream.text();

    let upstreamBody =
      {};

    try {
      upstreamBody =
        upstreamText
          ? JSON.parse(
              upstreamText
            )
          : {};
    } catch {
      upstreamBody = {
        raw:
          upstreamText
      };
    }

    console.log(
      "TOO LOST LABEL ARTIST REMOVE:",
      {
        artistId,
        status:
          upstream.status,
        response:
          upstreamBody
      }
    );

    if (
      !upstream.ok
    ) {
      return preferencesJSON(
        {
          error:
            "Too Lost rejected the artist removal.",

          tooLostStatus:
            upstream.status,

          tooLostResponse:
            upstreamBody
        },
        upstream.status,
        corsHeaders
      );
    }

    // ---------------------------------------------------------
    // Update USER-SPECIFIC KV.
    // ---------------------------------------------------------

    if (
      env.AUDIORY_KV
    ) {
      const labelKey =
        `PREFERENCES_LABEL_${userId}`;

      const cached =
        await env.AUDIORY_KV.get(
          labelKey
        );

      if (cached) {
        try {
          const labelData =
            JSON.parse(
              cached
            );

          if (
            Array.isArray(
              labelData?.artists
            )
          ) {
            labelData.artists =
              labelData.artists.filter(
                (artist) =>
                  Number(
                    artist?.id
                  ) !== artistId
              );

            await env.AUDIORY_KV.put(
              labelKey,
              JSON.stringify(
                labelData
              )
            );
          }

        } catch (kvError) {
          console.error(
            "Could not update label KV after artist removal:",
            kvError
          );
        }
      }
    }

    return preferencesJSON(
      {
        success:
          true,

        message:
          upstreamBody?.message ||
          "Artist removed from label.",

        data:
          upstreamBody?.data ||
          null
      },
      200,
      corsHeaders
    );

  } catch (error) {
    console.error(
      "Remove label artist error:",
      error
    );

    return preferencesJSON(
      {
        error:
          "Failed to remove artist.",
        details:
          error?.message ||
          String(error)
      },
      502,
      corsHeaders
    );
  }
}


  return null;
}

 

const isReleasePath = url.pathname === "/api/releases" ||
                url.pathname.startsWith("/api/releases/");


// =============================================================
// TOO LOST CONNECTION
// =============================================================

const baseUrl = (
  env.TOO_LOST_BASE_URL ||
  "https://api-sandbox.toolost.com/v1"
).replace(/\/$/, "");

let accessToken;

try {
  accessToken = await getAccessToken(env);
} catch (authError) {
  console.error(
    "Too Lost Authentication Error:",
    authError
  );

  return new Response(
    JSON.stringify({
      error: "Too Lost Authentication Failed",
      details:
        authError?.message ||
        "Unable to authenticate with Too Lost."
    }),
    {
      status: 401,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}


// =============================================================
// TOO LOST PLATFORM LOOKUP
// =============================================================

if (
  request.method === "GET" &&
  url.pathname === "/api/toolost/platforms"
) {
  try {

    const response = await fetch(
      `${baseUrl}/lookup/platforms`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );

    const responseText =
      await response.text();

    console.log(
      "TOO LOST PLATFORM RAW RESPONSE:",
      {
        status: response.status,
        body: responseText
      }
    );

    let data;

    try {
      data = JSON.parse(
        responseText || "{}"
      );
    } catch (error) {

      return new Response(
        JSON.stringify({
          success: false,
          message:
            "Too Lost returned an invalid platform response.",
          raw: responseText
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    if (!response.ok) {

      console.error(
        "TOO LOST PLATFORM LOOKUP FAILED:",
        data
      );

      return new Response(
        JSON.stringify({
          success: false,
          message:
            data?.message ||
            data?.error ||
            `Too Lost platform lookup failed (${response.status})`,
          tooLostResponse: data
        }),
        {
          status: response.status,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    let platforms = [];

    if (
      Array.isArray(
        data?.data?.platforms
      )
    ) {
      platforms =
        data.data.platforms;

    } else if (
      Array.isArray(
        data?.platforms
      )
    ) {
      platforms =
        data.platforms;

    } else if (
      Array.isArray(
        data?.data
      )
    ) {
      platforms =
        data.data;

    } else if (
      Array.isArray(data)
    ) {
      platforms = data;
    }

    platforms = [
      ...new Set(
        platforms
          .map(platform =>
            String(
              platform || ""
            ).trim()
          )
          .filter(Boolean)
      )
    ];

    console.log(
      "TOO LOST PLATFORM NORMALIZATION:",
      {
        count:
          platforms.length,
        platforms
      }
    );

    if (!platforms.length) {

      return new Response(
        JSON.stringify({
          success: false,
          message:
            "Too Lost returned no available platforms.",
          tooLostResponse: data
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        data: {
          platforms
        }
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );

  } catch (error) {

    console.error(
      "TOO LOST PLATFORM LOOKUP ERROR:",
      error
    );

    return new Response(
      JSON.stringify({
        success: false,
        message:
          error?.message ||
          "Unable to retrieve Too Lost platforms."
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );
  }
}

// =============================================================
// TOO LOST GENRE LOOKUP
//
// Audiory
//   GET /api/toolost/genres
//
// Too Lost
//   GET /v1/lookup/genres
//
// Too Lost returns:
//
// {
//   "data": [
//     "Alternative",
//     "World/Afro-Beat",
//     ...
//   ]
// }
// =============================================================

if (
  request.method === "GET" &&
  url.pathname === "/api/toolost/genres"
) {
  try {

    const response = await fetch(
      `${baseUrl}/lookup/genres`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );

    const responseText =
      await response.text();

    console.log(
      "TOO LOST GENRE RAW RESPONSE:",
      {
        status: response.status,
        body: responseText
      }
    );

    let data;

    try {
      data = JSON.parse(
        responseText || "{}"
      );
    } catch (error) {

      return new Response(
        JSON.stringify({
          success: false,
          message:
            "Too Lost returned an invalid genre response.",
          raw: responseText
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    if (!response.ok) {

      console.error(
        "TOO LOST GENRE LOOKUP FAILED:",
        data
      );

      return new Response(
        JSON.stringify({
          success: false,
          message:
            data?.message ||
            data?.error ||
            `Too Lost genre lookup failed (${response.status})`,
          tooLostResponse: data
        }),
        {
          status: response.status,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    let genres = [];

    if (Array.isArray(data?.data)) {

      genres =
        data.data;

    } else if (
      Array.isArray(data?.data?.genres)
    ) {

      genres =
        data.data.genres;

    } else if (
      Array.isArray(data?.genres)
    ) {

      genres =
        data.genres;

    } else if (Array.isArray(data)) {

      genres =
        data;
    }

    genres = [
      ...new Set(
        genres
          .map(genre =>
            String(
              genre || ""
            ).trim()
          )
          .filter(Boolean)
      )
    ];

    console.log(
      "TOO LOST GENRE NORMALIZATION:",
      {
        count: genres.length,
        genres
      }
    );

    if (!genres.length) {

      return new Response(
        JSON.stringify({
          success: false,
          message:
            "Too Lost returned no available genres.",
          tooLostResponse: data
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type":
              "application/json"
          }
        }
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        data: {
          genres
        }
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );

  } catch (error) {

    console.error(
      "TOO LOST GENRE LOOKUP ERROR:",
      error
    );

    return new Response(
      JSON.stringify({
        success: false,
        message:
          error?.message ||
          "Unable to retrieve Too Lost genres."
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );
  }
}

if (isReleasePath) {

  if (!userId) {
    return new Response(
      JSON.stringify({
        error: "Unauthorized: Invalid or missing authentication token."
      }),
      {
        status: 401,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  
// =============================================================
// ROUTE 1: CREATE RELEASE DRAFT + UPDATE METADATA
//
// POST /api/releases
//
// Audiory
//   -> POST /v1/releases
//   -> PATCH /v1/releases/:id/metadata
//
// IMPORTANT:
// Too Lost requires release creation and release metadata
// to be handled as TWO separate API operations.
//
// POST /releases only creates the draft.
// PATCH /releases/{releaseId}/metadata saves the metadata.
// =============================================================

if (
  url.pathname === "/api/releases" &&
  request.method === "POST"
) {

  // -------------------------------------------------------------
  // READ AUDIORY REQUEST
  // -------------------------------------------------------------

  const payloadText = await request.text();

  let payloadObj = {};

  try {
    payloadObj = JSON.parse(payloadText || "{}");
  } catch (e) {

    return new Response(
      JSON.stringify({
        error: "Invalid JSON request body."
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  // =============================================================
  // NORMALIZE BASIC RELEASE INFORMATION
  // =============================================================

  const title = String(
    payloadObj.title ||
    payloadObj.releaseTitle ||
    ""
  ).trim();

  const type =
    payloadObj.type ||
    payloadObj.releaseType ||
    "Single";

  const language = String(
    payloadObj.language ||
    payloadObj.primaryLanguage ||
    "en"
  ).trim();

  const label = String(
    payloadObj.label ||
    "Independent"
  ).trim();


  // =============================================================
  // GENRES
  //
  // IMPORTANT:
  // Use canonical camelCase fields FIRST.
  //
  // Do NOT allow `genre` to override `primaryGenre`.
  // Do NOT send snake_case aliases to Too Lost.
  // =============================================================

  const primaryGenre = String(
    payloadObj.primaryGenre ||
    payloadObj.primary_genre ||
    payloadObj.genre ||
    ""
  ).trim();

  const secondaryGenre = String(
    payloadObj.secondaryGenre ||
    payloadObj.secondary_genre ||
    payloadObj.subgenre ||
    ""
  ).trim();


  // =============================================================
  // OTHER METADATA
  // =============================================================

  const releaseDate =
    payloadObj.releaseDate ||
    payloadObj.release_date ||
    null;

  const originalReleaseDate =
    payloadObj.originalReleaseDate ||
    payloadObj.original_release_date ||
    null;

  // =============================================================
// RELEASE TIME
//
// Too Lost expects H:i, e.g. "05:55".
//
// Audiory may send either:
//   "05:55"
// or:
//   { time: "05:55", timeZone: "Africa/Nairobi" }
//
// Convert only valid values.
// =============================================================

let releaseTime = null;

if (typeof payloadObj.releaseTime === "string") {

  const candidate =
    payloadObj.releaseTime.trim();

  if (/^\d{2}:\d{2}$/.test(candidate)) {

    const [hours, minutes] =
      candidate.split(":").map(Number);

    if (
      hours >= 0 &&
      hours <= 23 &&
      minutes >= 0 &&
      minutes <= 59
    ) {
      releaseTime = candidate;
    }
  }

} else if (
  payloadObj.releaseTime &&
  typeof payloadObj.releaseTime === "object"
) {

  const candidate =
    String(
      payloadObj.releaseTime.time ||
      ""
    ).trim();

  if (/^\d{2}:\d{2}$/.test(candidate)) {

    const [hours, minutes] =
      candidate.split(":").map(Number);

    if (
      hours >= 0 &&
      hours <= 23 &&
      minutes >= 0 &&
      minutes <= 59
    ) {
      releaseTime = candidate;
    }
  }
}

  const timeZone =
    payloadObj.timeZone ||
    payloadObj.timezone ||
    payloadObj.releaseTimezone ||
    "Africa/Nairobi";

  const licenseType =
    payloadObj.licenseType ||
    payloadObj.license_type ||
    null;

  const licenseInfo =
    payloadObj.licenseInfo ||
    payloadObj.license_info ||
    null;

  const cYear =
    payloadObj.cYear ||
    payloadObj.c_year ||
    null;

  const cLine =
    payloadObj.cLine ||
    payloadObj.c_line ||
    null;

  const pYear =
    payloadObj.pYear ||
    payloadObj.p_year ||
    null;

  const pLine =
    payloadObj.pLine ||
    payloadObj.p_line ||
    null;

  const upc =
    payloadObj.upc ||
    payloadObj.upc_code ||
    null;

  const coverUrl =
    payloadObj.coverUrl ||
    payloadObj.cover_url ||
    payloadObj.cover_art ||
    payloadObj.artwork ||
    null;

  const compressedArtwork =
    payloadObj.compressedArtwork ||
    payloadObj.compressed_artwork ||
    coverUrl ||
    null;

  const version =
    payloadObj.version ||
    null;

  const remixTitle =
    payloadObj.remixTitle ||
    payloadObj.remix_title ||
    null;

  const applePreorder =
    payloadObj.applePreorder === true;

  const applePreorderDate =
    payloadObj.applePreorderDate ||
    payloadObj.apple_preorder_date ||
    null;

  const isAiGenerated =
    payloadObj.isAiGenerated === true ||
    payloadObj.is_ai_generated === true;

  const participants =
    Array.isArray(payloadObj.participants)
      ? payloadObj.participants
      : (
          Array.isArray(payloadObj.artists)
            ? payloadObj.artists
            : []
        );


  // =============================================================
  // REQUIRED FIELD VALIDATION
  // =============================================================

  if (!title) {

    return new Response(
      JSON.stringify({
        error: "Release title is required.",
        field: "title"
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  if (!language) {

    return new Response(
      JSON.stringify({
        error: "Language is required.",
        field: "language"
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  if (!primaryGenre) {

    return new Response(
      JSON.stringify({
        error: "Primary Genre is required.",
        field: "primaryGenre"
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  // =============================================================
// TOO LOST GENRE RESOLUTION
//
// Audiory has its own display names.
//
// Too Lost exposes the authoritative accepted genre list through:
//
// GET /lookup/genres
//
// We therefore:
//   1. Keep explicit aliases for known Audiory names.
//   2. Match exact Too Lost values.
//   3. Match normalized values.
//   4. Reject anything that cannot be matched.
//
// This prevents invalid genre values from ever being sent
// blindly to Too Lost.
// =============================================================

const TOO_LOST_GENRE_ALIASES = {

  // -----------------------------------------------------------
  // AFRICAN / AFRO MUSIC
  // -----------------------------------------------------------

  "Afrobeats":
    "World/Afro-Beat",

  "Afrobeat":
    "World/Afro-Beat",

  "Afro Pop":
    "World/Afro-Pop",

  "Afropop":
    "World/Afro-Pop",

  "Afro-Pop":
    "World/Afro-Pop",

  "Afro Fusion":
    "World/African",

  "Highlife":
    "World/African",

  "Afro Drill":
    "Hip-Hop/Rap",

  "African":
    "African",

  "Afro House":
    "Afro House",

  "Amapiano":
    "Amapiano",

  "Amapiano (Gqom)":
    "Amapiano (Gqom)",

  "Alternative":
    "Alternative",

  "Alternative Rock":
    "Alternative/Rock",

  "Indie Rock":
    "Indie Rock",

  "Indie Pop":
    "Alternative/Indie Pop",

  "Dance":
    "Dance",

  "Dance Pop":
    "Dance / Pop",

  "Electropop":
    "Dance / Electro Pop",

  "Hip-Hop":
    "Hip-Hop",

  "Hip Hop":
    "Hip-Hop",

  "Hip-Hop/Rap":
    "Hip-Hop/Rap",

  "Trap":
    "Trap / Wave",

  "Boom Bap":
    "Hip-Hop/Rap",

  "Drill":
    "Hip-Hop/Rap",

  "Conscious Hip-Hop":
    "Hip-Hop/Rap",

  "Melodic Rap":
    "Hip-Hop/Rap",

  "Cloud Rap":
    "Hip-Hop/Rap",

  "Christian Hip-Hop":
    "Hip-Hop/Rap",

  "R&B":
    "R&B",

  "R&B/Soul":
    "R&B",

  "Contemporary R&B":
    "R&B",

  "Alternative R&B":
    "R&B",

  "Neo-Soul":
    "Soul",

  "Soul":
    "Soul",

  "Pop":
    "Pop",

  "K-Pop":
    "Pop/K-Pop",

  "Synth-Pop":
    "Pop",

  "House":
    "House",

  "Techno":
    "Techno",

  "Deep House":
    "Deep House",

  "EDM":
    "Electronic/Dance",

  "Dubstep":
    "Dubstep",

  "Trance":
    "Trance Music",

  "Reggae":
    "Reggae",

  "Reggae/Dancehall":
    "Reggae",

  "Dancehall":
    "Reggae/Dancehall/Ska",

  "Roots Reggae":
    "Roots Reggae/Lovers Rock/One Drop",

  "Dub":
    "Dub",

  "Latin":
    "Latin",

  "Reggaeton":
    "Latin/Reggaeton",

  "Bachata":
    "Latin/Bachata",

  "Salsa":
    "Latin/Salsa",

  "Latin Trap":
    "Latin/Latin Rap",

  "Gospel/Christian":
    "Spiritual/Christian",

  "Contemporary Gospel":
    "Spiritual/Gospel",

  "Worship":
    "Spiritual/Gospel"
};


// =============================================================
// NORMALIZE GENRE TEXT FOR COMPARISON
// =============================================================

const normalizeGenreComparison = (value) => {

  return String(value || "")
    .replace(/\u00A0/g, " ")
    .replace(/\u202F/g, " ")
    .trim()
    .toLowerCase()
    .replace(/[–—−]/g, "-")
    .replace(/\s+/g, " ")
    .replace(/\s*\/\s*/g, "/")
    .replace(/\s*-\s*/g, "-");
};


// =============================================================
// RESOLVE GENRE AGAINST LIVE TOO LOST LIST
// =============================================================

const resolveTooLostGenre = (
  value,
  availableGenres
) => {

  const cleaned =
    String(value || "")
      .replace(/\u00A0/g, " ")
      .replace(/\u202F/g, " ")
      .trim();

  if (!cleaned) {
    return null;
  }

  const genres =
    Array.isArray(availableGenres)
      ? availableGenres
      : [];

  // -----------------------------------------------------------
  // 1. EXPLICIT AUDIORY ALIAS
  // -----------------------------------------------------------

  const explicitAlias =
    TOO_LOST_GENRE_ALIASES[cleaned];

  if (explicitAlias) {

    const explicitMatch =
      genres.find(
        genre =>
          String(genre).trim() ===
          explicitAlias
      );

    if (explicitMatch) {
      return explicitMatch;
    }

    // If Too Lost ever returns the alias itself
    // exactly as configured, accept it.
    return explicitAlias;
  }


  // -----------------------------------------------------------
  // 2. EXACT CASE-INSENSITIVE MATCH
  // -----------------------------------------------------------

  const exactMatch =
    genres.find(
      genre =>
        String(genre)
          .trim()
          .toLowerCase() ===
        cleaned.toLowerCase()
    );

  if (exactMatch) {
    return exactMatch;
  }


  // -----------------------------------------------------------
  // 3. NORMALIZED MATCH
  //
  // Handles things such as:
  //
  // Hip Hop
  // Hip-Hop
  //
  // and harmless spacing differences.
  // -----------------------------------------------------------

  const normalizedInput =
    normalizeGenreComparison(cleaned);

  const normalizedMatch =
    genres.find(
      genre =>
        normalizeGenreComparison(
          genre
        ) === normalizedInput
    );

  if (normalizedMatch) {
    return normalizedMatch;
  }


  // -----------------------------------------------------------
  // 4. NO SAFE MATCH
  // -----------------------------------------------------------

  return null;
};


// =============================================================
// FETCH LIVE TOO LOST GENRES
// =============================================================

const getTooLostGenres = async () => {

  const response =
    await fetch(
      `${baseUrl}/lookup/genres`,
      {
        method: "GET",
        headers: {
          "Accept":
            "application/json",
          "Authorization":
            `Bearer ${accessToken}`
        }
      }
    );

  const responseText =
    await response.text();

  let data = {};

  try {
    data =
      JSON.parse(
        responseText || "{}"
      );
  } catch (error) {
    throw new Error(
      "Too Lost returned invalid genre lookup JSON."
    );
  }

  if (!response.ok) {

    throw new Error(
      data?.message ||
      data?.error ||
      `Too Lost genre lookup failed (${response.status})`
    );
  }

  let genres = [];

  if (Array.isArray(data?.data)) {

    genres =
      data.data;

  } else if (
    Array.isArray(data?.data?.genres)
  ) {

    genres =
      data.data.genres;

  } else if (
    Array.isArray(data?.genres)
  ) {

    genres =
      data.genres;

  } else if (Array.isArray(data)) {

    genres =
      data;
  }

  return [
    ...new Set(
      genres
        .map(
          genre =>
            String(
              genre || ""
            ).trim()
        )
        .filter(Boolean)
    )
  ];
};


// =============================================================
// GET AUTHORITATIVE TOO LOST GENRE LIST
// =============================================================

let tooLostGenres = [];

try {

  tooLostGenres =
    await getTooLostGenres();

} catch (genreLookupError) {

  console.error(
    "TOO LOST GENRE LOOKUP FAILED:",
    genreLookupError
  );

  return new Response(
    JSON.stringify({
      error:
        "Unable to retrieve the current Too Lost genre list.",
      details:
        genreLookupError?.message ||
        String(genreLookupError)
    }),
    {
      status: 502,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


// =============================================================
// RESOLVE PRIMARY + SECONDARY GENRES
// =============================================================

const canonicalPrimaryGenre =
  resolveTooLostGenre(
    primaryGenre,
    tooLostGenres
  );

const canonicalSecondaryGenre =
  resolveTooLostGenre(
    secondaryGenre,
    tooLostGenres
  );


// =============================================================
// FAIL EARLY IF AUDIORY SENT AN UNKNOWN GENRE
// =============================================================

if (
  primaryGenre &&
  !canonicalPrimaryGenre
) {

  return new Response(
    JSON.stringify({
      error:
        "Audiory primary genre is not supported by the current Too Lost genre list.",
      primaryGenre,
      availableGenres:
        tooLostGenres
    }),
    {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


if (
  secondaryGenre &&
  !canonicalSecondaryGenre
) {

  return new Response(
    JSON.stringify({
      error:
        "Audiory secondary genre is not supported by the current Too Lost genre list.",
      secondaryGenre,
      availableGenres:
        tooLostGenres
    }),
    {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


  // =============================================================
  // LOG EXACT GENRES BEING SENT
  //
  // This is important for debugging and permanently prevents us
  // from guessing what the frontend actually sent.
  // =============================================================

  console.log(
    "AUDIORY -> TOO LOST GENRE RESOLUTION",
    JSON.stringify({
      primaryGenre: canonicalPrimaryGenre,
      secondaryGenre: canonicalSecondaryGenre
    })
  );


  // =============================================================
  // CREATE RELEASE DRAFT
  //
  // StoreReleaseRequest only requires:
  //
  // participants
  // title
  // type
  // label
  // language
  //
  // Do NOT send release metadata here.
  // =============================================================

  const createPayload = {
    participants,
    title,
    type,
    label,
    language
  };


  console.log(
    "AUDIORY -> TOO LOST CREATE RELEASE",
    JSON.stringify(createPayload)
  );


  let createResponse;

  try {

    createResponse =
      await fetch(
        `${baseUrl}/releases`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`
          },

          body: JSON.stringify(createPayload)
        }
      );

  } catch (e) {

    console.error(
      "Too Lost create release network error:",
      e
    );

    return new Response(
      JSON.stringify({
        error: "Unable to connect to Too Lost while creating release.",
        details: e?.message || String(e)
      }),
      {
        status: 502,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  const createResponseText =
    await createResponse.text();

  let createResponseJson = {};

  try {

    createResponseJson =
      JSON.parse(createResponseText || "{}");

  } catch (e) {

    createResponseJson = {
      raw: createResponseText
    };
  }


  // -------------------------------------------------------------
  // CREATE FAILED
  // -------------------------------------------------------------

  if (!createResponse.ok) {

    console.error(
      "Too Lost CREATE RELEASE ERROR:",
      createResponse.status,
      createResponseText
    );

    return new Response(
      JSON.stringify({
        error: "Too Lost rejected release creation.",
        status: createResponse.status,
        response: createResponseJson
      }),
      {
        status: createResponse.status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  // =============================================================
  // EXTRACT RELEASE ID
  // =============================================================

  const releaseId =
    createResponseJson?.data?.id ||
    createResponseJson?.id ||
    null;


  if (!releaseId) {

    console.error(
      "Too Lost created release but returned no release ID:",
      createResponseJson
    );

    return new Response(
      JSON.stringify({
        error: "Too Lost created the release but did not return a release ID.",
        createResponse: createResponseJson
      }),
      {
        status: 502,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  // =============================================================
  // BUILD CANONICAL TOO LOST METADATA PAYLOAD
  //
  // PATCH:
  // /v1/releases/{releaseId}/metadata
  //
  // Only send fields belonging to UpdateReleaseMetadataRequest.
  // =============================================================

  const metadataPayload = {

    type,
    title,
    version,
    remixTitle,
    label,

    primaryGenre: canonicalPrimaryGenre,

    ...(canonicalSecondaryGenre
      ? {
          secondaryGenre: canonicalSecondaryGenre
        }
      : {}),

    language,

    releaseDate,
    originalReleaseDate,

    applePreorder,

    ...(applePreorderDate
      ? {
          applePreorderDate
        }
      : {}),

    ...(licenseType
      ? {
          licenseType
        }
      : {}),

    ...(licenseInfo
      ? {
          licenseInfo
        }
      : {}),

    ...(cYear
      ? {
          cYear
        }
      : {}),

    ...(cLine
      ? {
          cLine
        }
      : {}),

    ...(pYear
      ? {
          pYear
        }
      : {}),

    ...(pLine
      ? {
          pLine
        }
      : {}),

    ...(upc
      ? {
          upc
        }
      : {}),

    ...(coverUrl
      ? {
          coverUrl
        }
      : {}),

    ...(compressedArtwork
      ? {
          compressedArtwork
        }
      : {}),

    isAiGenerated,

    ...(releaseTime
      ? {
          releaseTime
        }
      : {}),

    ...(timeZone
      ? {
          timeZone
        }
      : {}),

    ...(participants.length
      ? {
          participants
        }
      : {})
  };


  console.log(
    "AUDIORY -> TOO LOST PATCH METADATA",
    JSON.stringify({
      releaseId,
      metadataPayload
    })
  );


  // =============================================================
  // PATCH RELEASE METADATA
  // =============================================================

  let metadataResponse;

  try {

    metadataResponse =
      await fetch(
        `${baseUrl}/releases/${releaseId}/metadata`,
        {
          method: "PATCH",

          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`
          },

          body: JSON.stringify(metadataPayload)
        }
      );

  } catch (e) {

    console.error(
      "Too Lost metadata network error:",
      e
    );

    return new Response(
      JSON.stringify({
        error: "Release was created, but Audiory could not connect to Too Lost to update its metadata.",
        releaseId,
        createResponse: createResponseJson,
        details: e?.message || String(e)
      }),
      {
        status: 502,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  const metadataResponseText =
    await metadataResponse.text();

  let metadataResponseJson = {};

  try {

    metadataResponseJson =
      JSON.parse(metadataResponseText || "{}");

  } catch (e) {

    metadataResponseJson = {
      raw: metadataResponseText
    };
  }


  // =============================================================
  // METADATA FAILED
  // =============================================================

  if (!metadataResponse.ok) {

    console.error(
      "Too Lost METADATA ERROR:",
      metadataResponse.status,
      metadataResponseText
    );

    return new Response(
      JSON.stringify({

        error:
          "Release was created, but Too Lost rejected the release metadata.",

        releaseId,

        metadataSent: {
          primaryGenre: canonicalPrimaryGenre,
          secondaryGenre: canonicalSecondaryGenre,
          language,
          releaseDate,
          coverUrl
        },

        createResponse: createResponseJson,

        metadataStatus:
          metadataResponse.status,

        metadataResponse:
          metadataResponseJson

      }),
      {
        status: metadataResponse.status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }


  // =============================================================
  // METADATA SUCCESS
  // =============================================================

  console.log(
    "Too Lost metadata updated successfully:",
    releaseId
  );


  // =============================================================
  // SYNC RELEASE INTO AUDIORY KV
  // =============================================================

  if (env.AUDIORY_KV) {

    try {

      const userKvKey =
        `RELEASES_USER_${userId}`;

      let existingCached = [];

      try {

        existingCached =
          JSON.parse(
            (await env.AUDIORY_KV.get(userKvKey)) ||
            "[]"
          );

      } catch (e) {

        existingCached = [];

      }


      const metadataResponseData =
        metadataResponseJson?.data ||
        metadataResponseJson ||
        {};


      const localRelease = {

        id: releaseId,

        title,

        type,

        status:
          createResponseJson?.data?.status ||
          "draft",

        label,

        language,

        primaryGenre:
          canonicalPrimaryGenre,

        secondaryGenre:
          canonicalSecondaryGenre,

        releaseDate,

        originalReleaseDate,

        coverUrl,

        compressedArtwork,

        participants,

        submittedBy:
          userId,

        updatedAt:
          new Date().toISOString()

      };


      const withoutDuplicate =
        existingCached.filter(
          item =>
            String(item.id) !==
            String(releaseId)
        );


      withoutDuplicate.unshift(
        localRelease
      );


      await env.AUDIORY_KV.put(
        userKvKey,
        JSON.stringify(withoutDuplicate)
      );

    } catch (kvError) {

      console.error(
        "Audiory KV sync after metadata update failed:",
        kvError
      );

    }
  }


  // =============================================================
  // RETURN SUCCESS
  // =============================================================

  return new Response(
    JSON.stringify({

      success: true,

      message:
        "Release draft and metadata created successfully.",

      releaseId,

      createResponse:
        createResponseJson,

      metadataResponse:
        metadataResponseJson,

      metadataSent: {
        primaryGenre:
          canonicalPrimaryGenre,

        secondaryGenre:
          canonicalSecondaryGenre,

        language,

        timeZone,

        releaseDate,

        coverUrl
      }

    }),
    {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}

// =============================================================
// ROUTE 2A: UPLOAD TRACK FILE TO TOO LOST
//
// POST /api/releases/:id/tracks/upload
//
// Audiory frontend sends the actual FLAC file as multipart/form-data.
//
// Worker:
//   1. Requests a Too Lost upload URL
//   2. Uploads the FLAC to that URL
//   3. Returns the Too Lost fileKey
//
// Supported kinds:
//   audio
//   instrumental
//   dolby
// =============================================================

const trackUploadMatch =
  url.pathname.match(
    /^\/api\/releases\/([^/]+)\/tracks\/upload$/
  );

if (
  trackUploadMatch &&
  request.method === "POST"
) {

  const releaseId =
    trackUploadMatch[1];

  try {

    // -----------------------------------------------------------
    // Read multipart form
    // -----------------------------------------------------------

    const formData =
      await request.formData();

    const file =
      formData.get("file");

    const kind =
      String(
        formData.get("kind") || "audio"
      ).trim();

    // -----------------------------------------------------------
    // Validate file
    // -----------------------------------------------------------

    if (!file || typeof file.arrayBuffer !== "function") {
      return new Response(
        JSON.stringify({
          error: "No audio file was supplied."
        }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    if (
      !["audio", "instrumental", "dolby"].includes(kind)
    ) {
      return new Response(
        JSON.stringify({
          error: "Invalid Too Lost track file kind.",
          allowed: [
            "audio",
            "instrumental",
            "dolby"
          ]
        }),
        {
          status: 400,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    // Too Lost requires FLAC for this upload operation.
    const originalFileName =
      String(
        file.name ||
        `track-${Date.now()}.flac`
      ).trim();

    if (!/\.flac$/i.test(originalFileName)) {
      return new Response(
        JSON.stringify({
          error:
            "Too Lost requires FLAC audio files. Please upload a .flac file."
        }),
        {
          status: 422,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    const fileName =
      originalFileName
        .replace(/[^A-Za-z0-9._-]/g, "_")
        .slice(0, 255);

    // -----------------------------------------------------------
    // 1. REQUEST TOO LOST UPLOAD URL
    // -----------------------------------------------------------

    const uploadUrlResponse =
      await fetch(
        `${baseUrl}/releases/${releaseId}/tracks/upload-url`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`
          },
          body: JSON.stringify({
            contentType: "audio/flac",
            fileName,
            kind
          })
        }
      );

    const uploadUrlText =
      await uploadUrlResponse.text();

    let uploadUrlJson = {};

    try {
      uploadUrlJson =
        JSON.parse(
          uploadUrlText || "{}"
        );
    } catch (e) {
      uploadUrlJson = {
        raw: uploadUrlText
      };
    }

    if (!uploadUrlResponse.ok) {

      console.error(
        "TOO LOST TRACK UPLOAD URL ERROR:",
        uploadUrlResponse.status,
        uploadUrlText
      );

      return new Response(
        JSON.stringify({
          error:
            "Too Lost rejected the track upload URL request.",
          status:
            uploadUrlResponse.status,
          details:
            uploadUrlJson
        }),
        {
          status: uploadUrlResponse.status,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    const uploadData =
      uploadUrlJson?.data ||
      {};

    const uploadUrl =
      uploadData.uploadUrl;

    const fileKey =
      uploadData.fileKey;

    const uploadMethod =
      uploadData.method ||
      "PUT";

    const uploadHeaders =
      uploadData.headers ||
      {};

    if (!uploadUrl || !fileKey) {

      return new Response(
        JSON.stringify({
          error:
            "Too Lost returned an invalid track upload URL response.",
          response:
            uploadUrlJson
        }),
        {
          status: 502,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    // -----------------------------------------------------------
    // 2. UPLOAD ACTUAL FLAC TO TOO LOST
    // -----------------------------------------------------------

    const fileBytes =
      await file.arrayBuffer();

    const tooLostFileResponse =
      await fetch(
        uploadUrl,
        {
          method: uploadMethod,
          headers: uploadHeaders,
          body: fileBytes
        }
      );

    const tooLostFileText =
      await tooLostFileResponse.text();

    if (!tooLostFileResponse.ok) {

      console.error(
        "TOO LOST TRACK FILE UPLOAD ERROR:",
        tooLostFileResponse.status,
        tooLostFileText
      );

      return new Response(
        JSON.stringify({
          error:
            "The audio file could not be uploaded to Too Lost.",
          status:
            tooLostFileResponse.status,
          details:
            tooLostFileText,
          fileKey
        }),
        {
          status: tooLostFileResponse.status,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        }
      );
    }

    // -----------------------------------------------------------
    // SUCCESS
    // -----------------------------------------------------------

    console.log(
      "TOO LOST TRACK FILE UPLOADED",
      {
        releaseId,
        kind,
        fileName,
        fileKey
      }
    );

    return new Response(
      JSON.stringify({
        success: true,
        releaseId,
        kind,
        fileName,
        fileKey,
        expiresIn:
          uploadData.expiresIn ||
          null
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );

  } catch (error) {

    console.error(
      "Audiory Too Lost track upload error:",
      error
    );

    return new Response(
      JSON.stringify({
        error:
          "Audiory could not upload the track to Too Lost.",
        details:
          error?.message ||
          String(error)
      }),
      {
        status: 500,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }
}

// =============================================================
// ROUTE 2B: REPLACE RELEASE TRACKS
//
// PUT /api/releases/:id/tracks
//
// Audiory -> Too Lost
// PUT /releases/{releaseId}/tracks
// =============================================================

const releaseTracksMatch =
  url.pathname.match(
    /^\/api\/releases\/([^/]+)\/tracks$/
  );

if (
  releaseTracksMatch &&
  request.method === "PUT"
) {

  const releaseId =
    releaseTracksMatch[1];

  const payloadText =
    await request.text();

  let payloadObj = {};

  try {
    payloadObj =
      JSON.parse(
        payloadText || "{}"
      );
  } catch (e) {

    return new Response(
      JSON.stringify({
        error:
          "Invalid JSON request body."
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  if (
    !Array.isArray(payloadObj.tracks) ||
    payloadObj.tracks.length === 0
  ) {

    return new Response(
      JSON.stringify({
        error:
          "At least one release track is required."
      }),
      {
        status: 422,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  console.log(
    "AUDIORY -> TOO LOST PUT RELEASE TRACKS",
    JSON.stringify({
      releaseId,
      trackCount:
        payloadObj.tracks.length
    })
  );

  const response =
    await fetch(
      `${baseUrl}/releases/${releaseId}/tracks`,
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          tracks:
            payloadObj.tracks
        })
      }
    );

  const responseText =
    await response.text();

  console.log(
    "TOO LOST RELEASE TRACKS RESPONSE",
    response.status,
    responseText
  );

  return new Response(
    responseText,
    {
      status: response.status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}

// =============================================================
// ROUTE 2: SUBMIT RELEASE
//
// POST /api/releases/:id/submit
//
// IMPORTANT:
// Too Lost validates the SAVED release.
// Therefore we verify the release first.
// =============================================================

const submitMatch =
  url.pathname.match(
    /^\/api\/releases\/([^/]+)\/submit$/
  );

if (
  submitMatch &&
  request.method === "POST"
) {

  const releaseId =
    submitMatch[1];

  const payloadText =
    await request.text();

  let submitPayload = {};

  try {
    submitPayload =
      JSON.parse(payloadText || "{}");
  } catch (e) {
    submitPayload = {};
  }

  // ===========================================================
  // FETCH ACTUAL TOO LOST RELEASE
  // ===========================================================

  const releaseCheckResponse =
    await fetch(
      `${baseUrl}/releases/${releaseId}`,
      {
        method: "GET",
        headers: {
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`
        }
      }
    );

  const releaseCheckText =
    await releaseCheckResponse.text();

  let releaseCheckData = {};

  try {
    releaseCheckData =
      JSON.parse(releaseCheckText);
  } catch (e) {
    releaseCheckData = {};
  }

  if (!releaseCheckResponse.ok) {

    console.error(
      "Too Lost RELEASE CHECK FAILED:",
      releaseCheckResponse.status,
      releaseCheckText
    );

    return new Response(
      releaseCheckText,
      {
        status: releaseCheckResponse.status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  const release =
    releaseCheckData?.data ||
    releaseCheckData ||
    {};

  // ===========================================================
  // CHECK PRIMARY GENRE
  // Fall back to local KV cache if Too Lost GET didn't return it
  // ===========================================================

  let storedPrimaryGenre =
    String(
      release.primaryGenre ||
      release.primary_genre ||
      release.genre ||
      release.metadata?.primaryGenre ||
      release.metadata?.primary_genre ||
      release.metadata?.genre ||
      ""
    ).trim();

  // KV Fallback Check
  if (!storedPrimaryGenre && env.AUDIORY_KV) {
    try {
      const userKvKey = `RELEASES_USER_${userId}`;
      const cached = JSON.parse(await env.AUDIORY_KV.get(userKvKey) || "[]");
      const localRelease = cached.find(item => String(item.id) === String(releaseId));
      if (
        localRelease?.primaryGenre ||
        localRelease?.primary_genre ||
        localRelease?.genre
      ) {
          storedPrimaryGenre = String(
              localRelease.primaryGenre ||
              localRelease.primary_genre ||
              localRelease.genre
          ).trim();
      }
    } catch (e) {
      console.warn("KV fallback read failed during submit check:", e);
    }
  }

  console.log(
    "TOO LOST SUBMIT CHECK",
    {
      releaseId,
      title: release.title,
      primaryGenre: storedPrimaryGenre,
      secondaryGenre: release.secondaryGenre || release.secondary_genre,
      status: release.status
    }
  );

  // ===========================================================
  // DO NOT CALL SUBMIT IF GENRE IS STILL MISSING
  // ===========================================================

  if (!storedPrimaryGenre) {

    return new Response(
      JSON.stringify({
        error: "Too Lost draft is missing Primary Genre.",
        code: "MISSING_PRIMARY_GENRE_ON_DRAFT",
        releaseId: releaseId,
        tooLostRelease: {
          id: release.id,
          title: release.title,
          primaryGenre:
            release.primaryGenre ??
            release.primary_genre ??
            release.genre ??
            release.metadata?.primaryGenre ??
            release.metadata?.primary_genre ??
            release.metadata?.genre ??
            null,

          secondaryGenre:
            release.secondaryGenre ??
            release.secondary_genre ??
            release.subgenre ??
            release.metadata?.secondaryGenre ??
            release.metadata?.secondary_genre ??
            release.metadata?.subgenre ??
            null,
          status: release.status ?? null
        }
      }),
      {
        status: 422,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  // ===========================================================
  // SUBMIT TO TOO LOST
  // Sends both snake_case and camelCase boolean/string flags
  // ===========================================================

  const isTermsAccepted = submitPayload.acceptTerms === true || submitPayload.acceptTerms === "true";
  const isRightsConfirmed = submitPayload.confirmRights === true || submitPayload.confirmRights === "true";

  // ===========================================================
  // RESOLVE CANONICAL TOO LOST GENRE FOR SUBMISSION
  // ===========================================================

  const submitPrimaryGenre = String(
      release.genre ||
      release.primaryGenre ||
      release.primary_genre ||
      release.metadata?.genre ||
      release.metadata?.primaryGenre ||
      release.metadata?.primary_genre ||
      ""
  ).trim();

  const submitSecondaryGenre = String(
      release.subgenre ||
      release.secondaryGenre ||
      release.secondary_genre ||
      release.metadata?.subgenre ||
      release.metadata?.secondaryGenre ||
      release.metadata?.secondary_genre ||
      ""
  ).trim();

  console.log(
      "TOO LOST FINAL SUBMIT GENRE:",
      JSON.stringify({
          releaseId,
          genre: submitPrimaryGenre,
          subgenre: submitSecondaryGenre
      })
  );

  if (!submitPrimaryGenre) {
      return new Response(
          JSON.stringify({
              error: "Too Lost draft is missing Primary Genre.",
              code: "MISSING_PRIMARY_GENRE_ON_DRAFT",
              releaseId,
              tooLostRelease: {
                  id: release.id ?? null,
                  title: release.title ?? null,
                  genre: release.genre ?? null,
                  primaryGenre: release.primaryGenre ?? null,
                  subgenre: release.subgenre ?? null,
                  secondaryGenre: release.secondaryGenre ?? null
              }
          }),
          {
              status: 422,
              headers: {
                  ...corsHeaders,
                  "Content-Type": "application/json"
              }
          }
      );
  }

  // ===========================================================
  // SUBMIT BODY
  // ===========================================================

  const submitBody = {
      // Canonical Too Lost genre fields
      genre: submitPrimaryGenre,
      subgenre: submitSecondaryGenre || null,

      // Compatibility aliases
      primaryGenre: submitPrimaryGenre,
      primary_genre: submitPrimaryGenre,
      secondaryGenre: submitSecondaryGenre || null,
      secondary_genre: submitSecondaryGenre || null,

      acceptTerms: String(isTermsAccepted),
      accept_terms: isTermsAccepted,

      confirmRights: String(isRightsConfirmed),
      confirm_rights: isRightsConfirmed,

      confirmYoutubeRights:
          submitPayload.confirmYoutubeRights ?? null,

      confirm_youtube_rights:
          submitPayload.confirmYoutubeRights ?? null,

      idempotencyKey:
          submitPayload.idempotencyKey || crypto.randomUUID(),

      idempotency_key:
          submitPayload.idempotencyKey || crypto.randomUUID()
  };

  const submitResponse =
    await fetch(
      `${baseUrl}/releases/${releaseId}/submit`,
      {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`
        },

        body: JSON.stringify(submitBody)
      }
    );

  const responseText =
    await submitResponse.text();

  // ===========================================================
  // CACHE STATUS AFTER SUCCESS
  // ===========================================================

  if (
    env.AUDIORY_KV &&
    submitResponse.ok
  ) {

    const serverData =
      (() => {
        try {
          return JSON.parse(responseText);
        } catch (e) {
          return {};
        }
      })();

    const submittedRelease =
      serverData?.data ||
      serverData ||
      {};

    const userKvKey =
      `RELEASES_USER_${userId}`;

    let existingCached = [];

    try {
      existingCached =
        JSON.parse(
          await env.AUDIORY_KV.get(userKvKey) || "[]"
        );
    } catch (e) {
      existingCached = [];
    }

    const idx =
      existingCached.findIndex(
        item =>
          String(item.id) === String(releaseId)
      );

    if (idx !== -1) {

      existingCached[idx] = {
        ...existingCached[idx],

        status:
          submittedRelease.status ||
          "in_review",

        submittedAt:
          submittedRelease.submittedAt ||
          submittedRelease.submitted_at ||
          new Date().toISOString()
      };

      await env.AUDIORY_KV.put(
        userKvKey,
        JSON.stringify(existingCached)
      );
    }
  }

  // ===========================================================
  // RETURN TOO LOST RESPONSE
  // ===========================================================

  return new Response(
    responseText,
    {
      status: submitResponse.status,

      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}

  // =============================================================
  // ROUTE 3: DELETE RELEASE DRAFT
  //
  // DELETE /api/releases/:id
  // =============================================================

  const deleteMatch =
    url.pathname.match(
      /^\/api\/releases\/([^/]+)$/
    );


  if (
    deleteMatch &&
    request.method === "DELETE"
  ) {

    const releaseId =
      deleteMatch[1];


    const response =
      await fetch(
        `${baseUrl}/releases/${releaseId}`,
        {
          method: "DELETE",
          headers: {
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`
          }
        }
      );


    const responseText =
      await response.text();


    // -------------------------------------------------------------
    // Only remove local cache if Too Lost successfully deleted it.
    // -------------------------------------------------------------

    if (
      response.ok &&
      env.AUDIORY_KV
    ) {

      const userKvKey =
        `RELEASES_USER_${userId}`;


      let existingCached = [];

      try {
        existingCached =
          JSON.parse(
            await env.AUDIORY_KV.get(userKvKey) || "[]"
          );
      } catch (e) {
        existingCached = [];
      }


      const filteredKV =
        existingCached.filter(
          item =>
            String(item.id) !== String(releaseId)
        );


      await env.AUDIORY_KV.put(
        userKvKey,
        JSON.stringify(filteredKV)
      );
    }


    return new Response(
      responseText || JSON.stringify({
        message:
          response.ok
            ? "Release deleted successfully"
            : "Unable to delete release"
      }),
      {
        status: response.status,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }



 // =============================================================
// ROUTE 4: RELEASE INFORMATION / UPDATE DRAFT
//
// Audiory:
//   PUT   /api/releases/:id
//   PATCH /api/releases/:id
//
// Too Lost:
//   PATCH /v1/releases/:id/metadata
//
// IMPORTANT:
// Audiory may use PUT/PATCH for its own edit endpoint.
// Too Lost does NOT accept PUT /releases/:id.
// Metadata edits MUST go to:
// PATCH /releases/:id/metadata
// =============================================================

const releaseInfoMatch =
  url.pathname.match(
    /^\/api\/releases\/([^/]+)$/
  );

if (
  releaseInfoMatch &&
  (
    request.method === "PUT" ||
    request.method === "PATCH"
  )
) {

  const releaseId =
    releaseInfoMatch[1];

  // -------------------------------------------------------------
  // READ AUDIORY REQUEST
  // -------------------------------------------------------------

  const payloadText =
    await request.text();

  let payloadObj = {};

  try {

    payloadObj =
      JSON.parse(
        payloadText || "{}"
      );

  } catch (e) {

    return new Response(
      JSON.stringify({
        error:
          "Invalid JSON request body."
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );
  }


  // -------------------------------------------------------------
  // RAW GENRES
  // -------------------------------------------------------------

  const rawPrimaryGenre =
    String(
      payloadObj.primaryGenre ||
      payloadObj.primary_genre ||
      payloadObj.genre ||
      ""
    ).trim();

  const rawSecondaryGenre =
    String(
      payloadObj.secondaryGenre ||
      payloadObj.secondary_genre ||
      payloadObj.subgenre ||
      ""
    ).trim();


  // -------------------------------------------------------------
// LIVE TOO LOST GENRE RESOLUTION FOR EDIT
// -------------------------------------------------------------

let editTooLostGenres = [];

try {

  const genreLookupResponse =
    await fetch(
      `${baseUrl}/lookup/genres`,
      {
        method: "GET",
        headers: {
          "Accept":
            "application/json",
          "Authorization":
            `Bearer ${accessToken}`
        }
      }
    );

  const genreLookupText =
    await genreLookupResponse.text();

  let genreLookupData = {};

  try {

    genreLookupData =
      JSON.parse(
        genreLookupText || "{}"
      );

  } catch (e) {

    throw new Error(
      "Too Lost returned invalid genre lookup JSON."
    );
  }

  if (!genreLookupResponse.ok) {

    throw new Error(
      genreLookupData?.message ||
      genreLookupData?.error ||
      `Too Lost genre lookup failed (${genreLookupResponse.status})`
    );
  }

  if (
    Array.isArray(
      genreLookupData?.data
    )
  ) {

    editTooLostGenres =
      genreLookupData.data;

  } else if (
    Array.isArray(
      genreLookupData?.data?.genres
    )
  ) {

    editTooLostGenres =
      genreLookupData.data.genres;

  } else if (
    Array.isArray(
      genreLookupData?.genres
    )
  ) {

    editTooLostGenres =
      genreLookupData.genres;

  } else if (
    Array.isArray(
      genreLookupData
    )
  ) {

    editTooLostGenres =
      genreLookupData;
  }

  editTooLostGenres =
    [
      ...new Set(
        editTooLostGenres
          .map(
            genre =>
              String(
                genre || ""
              ).trim()
          )
          .filter(Boolean)
      )
    ];

} catch (genreLookupError) {

  console.error(
    "TOO LOST EDIT GENRE LOOKUP FAILED:",
    genreLookupError
  );

  return new Response(
    JSON.stringify({
      error:
        "Unable to retrieve the current Too Lost genre list.",
      details:
        genreLookupError?.message ||
        String(genreLookupError)
    }),
    {
      status: 502,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


// -------------------------------------------------------------
// EDIT GENRE ALIASES
// -------------------------------------------------------------

const editGenreAliases = {

  "Afrobeats":
    "World/Afro-Beat",

  "Afrobeat":
    "World/Afro-Beat",

  "Afro Pop":
    "World/Afro-Pop",

  "Afropop":
    "World/Afro-Pop",

  "Afro-Pop":
    "World/Afro-Pop",

  "Afro Fusion":
    "World/African",

  "Highlife":
    "World/African",

  "Afro Drill":
    "Hip-Hop/Rap",

  "African":
    "African",

  "Afro House":
    "Afro House",

  "Amapiano":
    "Amapiano",

  "Amapiano (Gqom)":
    "Amapiano (Gqom)",

  "Alternative":
    "Alternative",

  "Alternative Rock":
    "Alternative/Rock",

  "Indie Rock":
    "Indie Rock",

  "Indie Pop":
    "Alternative/Indie Pop",

  "Dance":
    "Dance",

  "Dance Pop":
    "Dance / Pop",

  "Electropop":
    "Dance / Electro Pop",

  "Hip-Hop":
    "Hip-Hop",

  "Hip Hop":
    "Hip-Hop",

  "Hip-Hop/Rap":
    "Hip-Hop/Rap",

  "Trap":
    "Trap / Wave",

  "Boom Bap":
    "Hip-Hop/Rap",

  "Drill":
    "Hip-Hop/Rap",

  "Conscious Hip-Hop":
    "Hip-Hop/Rap",

  "Melodic Rap":
    "Hip-Hop/Rap",

  "Cloud Rap":
    "Hip-Hop/Rap",

  "Christian Hip-Hop":
    "Hip-Hop/Rap",

  "R&B":
    "R&B",

  "R&B/Soul":
    "R&B",

  "Contemporary R&B":
    "R&B",

  "Alternative R&B":
    "R&B",

  "Neo-Soul":
    "Soul",

  "Soul":
    "Soul",

  "Pop":
    "Pop",

  "K-Pop":
    "Pop/K-Pop",

  "Synth-Pop":
    "Pop",

  "House":
    "House",

  "Techno":
    "Techno",

  "Deep House":
    "Deep House",

  "EDM":
    "Electronic/Dance",

  "Dubstep":
    "Dubstep",

  "Trance":
    "Trance Music",

  "Reggae":
    "Reggae",

  "Reggae/Dancehall":
    "Reggae",

  "Dancehall":
    "Reggae/Dancehall/Ska",

  "Roots Reggae":
    "Roots Reggae/Lovers Rock/One Drop",

  "Dub":
    "Dub",

  "Latin":
    "Latin",

  "Reggaeton":
    "Latin/Reggaeton",

  "Bachata":
    "Latin/Bachata",

  "Salsa":
    "Latin/Salsa",

  "Latin Trap":
    "Latin/Latin Rap",

  "Gospel/Christian":
    "Spiritual/Christian",

  "Contemporary Gospel":
    "Spiritual/Gospel",

  "Worship":
    "Spiritual/Gospel"
};


// -------------------------------------------------------------
// NORMALIZE GENRE FOR COMPARISON
// -------------------------------------------------------------

const normalizeEditGenre =
  (value) => {

    return String(
      value || ""
    )
      .replace(
        /\u00A0/g,
        " "
      )
      .replace(
        /\u202F/g,
        " "
      )
      .trim()
      .toLowerCase()
      .replace(
        /[–—−]/g,
        "-"
      )
      .replace(
        /\s+/g,
        " "
      )
      .replace(
        /\s*\/\s*/g,
        "/"
      )
      .replace(
        /\s*-\s*/g,
        "-"
      );
  };


// -------------------------------------------------------------
// RESOLVE EDIT GENRE AGAINST LIVE TOO LOST LIST
// -------------------------------------------------------------

const resolveEditGenre =
  (value) => {

    const cleaned =
      String(
        value || ""
      )
        .replace(
          /\u00A0/g,
          " "
        )
        .replace(
          /\u202F/g,
          " "
        )
        .trim();

    if (!cleaned) {
      return null;
    }


    // 1. Audiory alias -> Too Lost value

    const explicitAlias =
      editGenreAliases[
        cleaned
      ];

    if (explicitAlias) {

      const explicitMatch =
        editTooLostGenres.find(
          genre =>
            String(
              genre
            )
              .trim()
              .toLowerCase() ===
            explicitAlias
              .trim()
              .toLowerCase()
        );

      if (explicitMatch) {
        return explicitMatch;
      }
    }


    // 2. Exact case-insensitive match

    const exactMatch =
      editTooLostGenres.find(
        genre =>
          String(
            genre
          )
            .trim()
            .toLowerCase() ===
          cleaned.toLowerCase()
      );

    if (exactMatch) {
      return exactMatch;
    }


    // 3. Normalized match

    const normalizedInput =
      normalizeEditGenre(
        cleaned
      );

    const normalizedMatch =
      editTooLostGenres.find(
        genre =>
          normalizeEditGenre(
            genre
          ) ===
          normalizedInput
      );

    if (normalizedMatch) {
      return normalizedMatch;
    }


    // 4. No supported match

    return null;
  };


const canonicalPrimaryGenre =
  resolveEditGenre(
    rawPrimaryGenre
  );

const canonicalSecondaryGenre =
  rawSecondaryGenre
    ? resolveEditGenre(
        rawSecondaryGenre
      )
    : null;


// -------------------------------------------------------------
// VALIDATE GENRES AGAINST LIVE TOO LOST LIST
// -------------------------------------------------------------

if (!canonicalPrimaryGenre) {

  return new Response(
    JSON.stringify({
      error:
        "Primary Genre is not supported by Too Lost.",
      field:
        "primaryGenre",
      supplied:
        rawPrimaryGenre
    }),
    {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


if (
  rawSecondaryGenre &&
  !canonicalSecondaryGenre
) {

  return new Response(
    JSON.stringify({
      error:
        "Secondary Genre is not supported by Too Lost.",
      field:
        "secondaryGenre",
      supplied:
        rawSecondaryGenre
    }),
    {
      status: 400,
      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}


  // -------------------------------------------------------------
  // BUILD TOO LOST METADATA PAYLOAD
  // -------------------------------------------------------------

  const metadataPayload = {

    type:
      payloadObj.type ||
      payloadObj.releaseType ||
      "Single",

    title:
      payloadObj.title ||
      payloadObj.releaseTitle ||
      "",

    version:
      payloadObj.version ||
      null,

    remixTitle:
      payloadObj.remixTitle ||
      payloadObj.remix_title ||
      null,

    label:
      payloadObj.label ||
      "Independent",

    primaryGenre:
      canonicalPrimaryGenre,

    ...(canonicalSecondaryGenre
      ? {
          secondaryGenre:
            canonicalSecondaryGenre
        }
      : {}),

    language:
      payloadObj.language ||
      payloadObj.primaryLanguage ||
      "en",

    releaseDate:
      payloadObj.releaseDate ||
      payloadObj.release_date ||
      null,

    originalReleaseDate:
      payloadObj.originalReleaseDate ||
      payloadObj.original_release_date ||
      null,

    applePreorder:
      Boolean(
        payloadObj.applePreorder
      ),

    ...(payloadObj.applePreorderDate
      ? {
          applePreorderDate:
            payloadObj.applePreorderDate
        }
      : {}),

    ...(payloadObj.licenseType
      ? {
          licenseType:
            payloadObj.licenseType
        }
      : {}),

    ...(payloadObj.licenseInfo
      ? {
          licenseInfo:
            payloadObj.licenseInfo
        }
      : {}),

    ...(payloadObj.cYear
      ? {
          cYear:
            payloadObj.cYear
        }
      : {}),

    ...(payloadObj.cLine
      ? {
          cLine:
            payloadObj.cLine
        }
      : {}),

    ...(payloadObj.pYear
      ? {
          pYear:
            payloadObj.pYear
        }
      : {}),

    ...(payloadObj.pLine
      ? {
          pLine:
            payloadObj.pLine
        }
      : {}),

    ...(payloadObj.upc
      ? {
          upc:
            payloadObj.upc
        }
      : {}),

    ...(payloadObj.coverUrl
      ? {
          coverUrl:
            payloadObj.coverUrl
        }
      : {}),

    ...(payloadObj.compressedArtwork
      ? {
          compressedArtwork:
            payloadObj.compressedArtwork
        }
      : {}),

    ...(payloadObj.isAiGenerated !== undefined
      ? {
          isAiGenerated:
            Boolean(
              payloadObj.isAiGenerated
            )
        }
      : {}),

    ...(payloadObj.releaseTime
      ? {
          releaseTime:
            payloadObj.releaseTime
        }
      : {}),

    ...(payloadObj.timeZone
      ? {
          timeZone:
            payloadObj.timeZone
        }
      : {}),

    ...(Array.isArray(
      payloadObj.participants
    ) &&
    payloadObj.participants.length
      ? {
          participants:
            payloadObj.participants
        }
      : {})
  };


  // -------------------------------------------------------------
  // DEBUG
  // -------------------------------------------------------------

  console.log(
    "AUDIORY -> TOO LOST EDIT METADATA:",
    JSON.stringify({
      releaseId,
      method:
        request.method,
      primaryGenre:
        canonicalPrimaryGenre,
      secondaryGenre:
        canonicalSecondaryGenre,
      metadataPayload
    })
  );


  // -------------------------------------------------------------
  // IMPORTANT:
  //
  // Audiory PUT/PATCH
  //        ↓
  // Too Lost PATCH /metadata
  // -------------------------------------------------------------

  let response;

  try {

    response =
      await fetch(
        `${baseUrl}/releases/${releaseId}/metadata`,
        {
          method: "PATCH",

          headers: {
            "Content-Type":
              "application/json",

            "Accept":
              "application/json",

            "Authorization":
              `Bearer ${accessToken}`
          },

          body:
            JSON.stringify(
              metadataPayload
            )
        }
      );

  } catch (e) {

    console.error(
      "Too Lost EDIT METADATA NETWORK ERROR:",
      e
    );

    return new Response(
      JSON.stringify({
        error:
          "Unable to connect to Too Lost while updating release metadata.",

        releaseId,

        details:
          e?.message ||
          String(e)
      }),
      {
        status: 502,
        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );
  }


  // -------------------------------------------------------------
  // READ TOO LOST RESPONSE
  // -------------------------------------------------------------

  const responseText =
    await response.text();

  let serverData = {};

  try {

    serverData =
      JSON.parse(
        responseText ||
        "{}"
      );

  } catch (e) {

    serverData = {
      raw:
        responseText
    };
  }


  // -------------------------------------------------------------
  // TOO LOST REJECTED UPDATE
  // -------------------------------------------------------------

  if (!response.ok) {

    console.error(
      "TOO LOST EDIT METADATA ERROR:",
      response.status,
      responseText
    );

    return new Response(
      JSON.stringify({

        error:
          "Too Lost rejected the release metadata update.",

        releaseId,

        status:
          response.status,

        details:
          serverData,

        metadataSent:
          metadataPayload
      }),
      {
        status:
          response.status,

        headers: {
          ...corsHeaders,
          "Content-Type":
            "application/json"
        }
      }
    );
  }


  // -------------------------------------------------------------
  // SYNC UPDATED METADATA TO AUDIORY KV
  // -------------------------------------------------------------

  if (env.AUDIORY_KV) {

    try {

      const userKvKey =
        `RELEASES_USER_${userId}`;

      let existingCached = [];

      try {

        existingCached =
          JSON.parse(
            (await env.AUDIORY_KV.get(
              userKvKey
            )) || "[]"
          );

      } catch (e) {

        existingCached = [];

      }


      const returnedRelease =
        serverData?.data ||
        serverData ||
        {};


      const updatedItem = {

        id:
          releaseId,

        title:
          returnedRelease.title ||
          metadataPayload.title ||
          "Untitled",

        type:
          returnedRelease.type ||
          metadataPayload.type ||
          "Single",

        status:
          returnedRelease.status ||
          "draft",

        label:
          typeof returnedRelease.label ===
          "string"
            ? returnedRelease.label
            : metadataPayload.label,

        primaryGenre:
          canonicalPrimaryGenre,

        secondaryGenre:
          canonicalSecondaryGenre,

        language:
          returnedRelease.language ||
          metadataPayload.language,

        releaseDate:
          returnedRelease.releaseDate ||
          returnedRelease.release_date ||
          metadataPayload.releaseDate,

        originalReleaseDate:
          returnedRelease.originalReleaseDate ||
          returnedRelease.original_release_date ||
          metadataPayload.originalReleaseDate,

        coverUrl:
          returnedRelease.coverUrl ||
          returnedRelease.cover_url ||
          metadataPayload.coverUrl ||
          "",

        compressedArtwork:
          returnedRelease.compressedArtwork ||
          returnedRelease.compressed_artwork ||
          metadataPayload.compressedArtwork ||
          metadataPayload.coverUrl ||
          "",

        participants:
          returnedRelease.participants ||
          returnedRelease.artists ||
          metadataPayload.participants ||
          [],

        upc:
          returnedRelease.upc ||
          returnedRelease.upc_code ||
          metadataPayload.upc ||
          "Pending",

        submittedBy:
          userId,

        updatedAt:
          new Date().toISOString()
      };


      const idx =
        existingCached.findIndex(
          item =>
            String(item.id) ===
            String(releaseId)
        );


      if (idx !== -1) {

        // IMPORTANT:
        // Merge instead of replacing.
        //
        // This preserves existing:
        // tracks
        // delivery
        // territories
        // platforms
        // audio file keys
        // writers
        // credits
        // lyrics
        // artwork
        // and other locally cached data.

        existingCached[idx] = {
          ...existingCached[idx],
          ...updatedItem
        };

      } else {

        existingCached.unshift(
          updatedItem
        );

      }


      await env.AUDIORY_KV.put(
        userKvKey,
        JSON.stringify(
          existingCached
        )
      );

    } catch (kvError) {

      console.error(
        "Audiory KV sync after release edit failed:",
        kvError
      );

    }
  }


  // -------------------------------------------------------------
  // RETURN SUCCESS
  // -------------------------------------------------------------

  return new Response(
    JSON.stringify({

      success:
        true,

      message:
        "Release metadata updated successfully.",

      releaseId,

      metadataResponse:
        serverData,

      metadataSent:
        metadataPayload

    }),
    {
      status:
        200,

      headers: {
        ...corsHeaders,
        "Content-Type":
          "application/json"
      }
    }
  );
}   

// =============================================================
// ROUTE 5: RELEASE DELIVERY & TARGETS
//
// PUT /api/releases/:id/delivery
// PATCH /api/releases/:id/delivery
//
// Audiory -> Too Lost
// PUT /releases/:id/delivery
// PATCH /releases/:id/delivery
// =============================================================

const deliveryMatch =
  url.pathname.match(
    /^\/api\/releases\/([^/]+)\/delivery$/
  );

if (
  deliveryMatch &&
  (
    request.method === "PUT" ||
    request.method === "PATCH"
  )
) {
  const releaseId = deliveryMatch[1];
  const payloadText = await request.text();

  let payloadObj = {};

  try {
    payloadObj = JSON.parse(payloadText || "{}");
  } catch (e) {
    return new Response(
      JSON.stringify({
        error: "Invalid JSON request body."
      }),
      {
        status: 400,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );
  }

  // Extract platforms/DSPs and territories
  const resolvedPlatforms =
    payloadObj.platforms ||
    payloadObj.dsps ||
    payloadObj.delivery?.platforms ||
    payloadObj.delivery?.dsps ||
    [];

  const resolvedTerritories =
    payloadObj.territories ||
    payloadObj.delivery?.territories ||
    [];

  // ===========================================================
  // NORMALIZE DELIVERY PAYLOAD FOR TOO LOST
  // ===========================================================

  const deliveryPayload = {
    delivery: {
      platforms: resolvedPlatforms,
      territories: resolvedTerritories,
      additional: payloadObj.delivery?.additional || {},
      beatPort: Boolean(payloadObj.delivery?.beatPort)
    }
  };

  console.log("Audiory -> Too Lost DELIVERY UPDATE", {
    releaseId,
    method: request.method,
    platformCount: resolvedPlatforms.length,
    territoryCount: resolvedTerritories.length
  });

  // ===========================================================
  // FORWARD TO TOO LOST
  // ===========================================================

  const response = await fetch(
    `${baseUrl}/releases/${releaseId}/delivery`,
    {
      method: request.method,
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": `Bearer ${accessToken}`
      },
      body: JSON.stringify(deliveryPayload)
    }
  );

  const responseText = await response.text();

  // ===========================================================
  // SYNC DELIVERY CONFIG TO LOCAL KV CACHE
  // ===========================================================

  if (response.ok && env.AUDIORY_KV) {
    const userKvKey = `RELEASES_USER_${userId}`;
    let existingCached = [];

    try {
      existingCached = JSON.parse(
        (await env.AUDIORY_KV.get(userKvKey)) || "[]"
      );
    } catch (e) {
      existingCached = [];
    }

    const idx = existingCached.findIndex(
      (item) => String(item.id) === String(releaseId)
    );

    if (idx !== -1) {
      existingCached[idx] = {
        ...existingCached[idx],
        platforms: resolvedPlatforms,
        dsps: resolvedPlatforms,
        territories: resolvedTerritories,
        delivery: deliveryPayload.delivery,
        updatedAt: new Date().toISOString()
      };

      await env.AUDIORY_KV.put(
        userKvKey,
        JSON.stringify(existingCached)
      );
    }
  }

  // ===========================================================
  // RETURN TOO LOST RESPONSE
  // ===========================================================

  return new Response(
    responseText,
    {
      status: response.status,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}



  // =============================================================
// ROUTE 6: FETCH USER CATALOGUE
//
// GET /api/releases
//
// IMPORTANT:
// Audiory KV is the ownership source.
// Too Lost provides the latest release data.
// Only Too Lost releases already owned by this Audiory user
// in KV are allowed into the final catalogue.
// =============================================================

if (
  url.pathname === "/api/releases" &&
  request.method === "GET"
) {

  // -------------------------------------------------------------
  // Get Audiory local cache FIRST
  // -------------------------------------------------------------

  let userCachedReleases = [];

  if (env.AUDIORY_KV) {

    const userKvKey =
      `RELEASES_USER_${userId}`;

    try {

      const cachedValue =
        await env.AUDIORY_KV.get(userKvKey);

      if (cachedValue) {

        const parsed =
          JSON.parse(cachedValue);

        if (Array.isArray(parsed)) {
          userCachedReleases = parsed;
        }

      }

    } catch (e) {

      console.error(
        "Audiory KV Release Cache Error:",
        e
      );

      userCachedReleases = [];
    }
  }


  // -------------------------------------------------------------
  // Build ownership list from Audiory KV
  //
  // This is the security boundary.
  // A Too Lost release is only accepted if its ID is already
  // associated with this Audiory user.
  // -------------------------------------------------------------

  const ownedReleaseIds =
    new Set(
      userCachedReleases
        .filter(item => item?.id)
        .map(item => String(item.id))
    );


  // -------------------------------------------------------------
  // Fetch releases from Too Lost
  // -------------------------------------------------------------

  let apiReleases = [];

  let tooLostError = null;

  try {

    const response =
      await fetch(
        `${baseUrl}/releases${url.search}`,
        {
          method: "GET",

          headers: {
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`
          }
        }
      );


    const responseText =
      await response.text();


    // -----------------------------------------------------------
    // Handle Too Lost errors explicitly
    // -----------------------------------------------------------

    if (!response.ok) {

      console.error(
        "Too Lost Fetch Error:",
        response.status,
        responseText
      );

      tooLostError = {
        status: response.status,
        body: responseText
      };

    } else {

      let resJson = {};

      try {

        resJson =
          JSON.parse(responseText);

      } catch (e) {

        console.error(
          "Too Lost returned invalid JSON:",
          responseText
        );

        tooLostError = {
          status: 502,
          body: "Too Lost returned invalid JSON."
        };
      }


      // ---------------------------------------------------------
      // Normalize Too Lost response
      // ---------------------------------------------------------

      if (!tooLostError) {

        const rawList =
          Array.isArray(resJson)
            ? resJson
            : (
                Array.isArray(resJson?.data)
                  ? resJson.data
                  : (
                      Array.isArray(resJson?.releases)
                        ? resJson.releases
                        : []
                    )
              );


        // -------------------------------------------------------
        // SECURITY FILTER
        //
        // NEVER use:
        //
        // !item.submittedBy
        //
        // because submittedBy is Audiory's local ownership field,
        // not a reliable Too Lost ownership identifier.
        // -------------------------------------------------------

        apiReleases =
          rawList.filter(item => {

            if (!item?.id) {
              return false;
            }

            return ownedReleaseIds.has(
              String(item.id)
            );
          });
      }
    }

  } catch (e) {

    console.error(
      "Too Lost Fetch Error:",
      e
    );

    tooLostError = {
      status: 502,
      body: e?.message ||
        "Unable to contact Too Lost."
    };
  }


  // -------------------------------------------------------------
  // Merge Too Lost data with Audiory's local data
  //
  // Start with the user's KV releases so locally-created drafts
  // remain visible even if Too Lost is temporarily unavailable.
  // -------------------------------------------------------------

  const combinedMap =
    new Map();


  userCachedReleases.forEach(item => {

    if (!item?.id) {
      return;
    }

    combinedMap.set(
      String(item.id),
      {
        ...item
      }
    );

  });


  // -------------------------------------------------------------
  // Overlay the latest Too Lost data
  // -------------------------------------------------------------

  apiReleases.forEach(item => {

    if (!item?.id) {
      return;
    }

    const key =
      String(item.id);

    const existing =
      combinedMap.get(key);


    if (existing) {

      combinedMap.set(
        key,
        {
          ...existing,
          ...item,

          // Too Lost is authoritative for current status.
          status:
            item.status ??
            existing.status,

          // Audiory remains authoritative for ownership.
          submittedBy:
            existing.submittedBy ||
            userId
        }
      );

    }

  });


  // -------------------------------------------------------------
  // Final catalogue
  //
  // Only releases already belonging to this Audiory user
  // are present here.
  // -------------------------------------------------------------

  const finalCatalog =
    Array.from(
      combinedMap.values()
    );


  // -------------------------------------------------------------
  // Return catalogue
  // -------------------------------------------------------------

  return new Response(
    JSON.stringify(
      finalCatalog
    ),
    {
      status: 200,

      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    }
  );
}


// -------------------------------------------------------------
// Unknown release route
// -------------------------------------------------------------

return new Response(
  JSON.stringify({
    error: "Unknown release API route."
  }),
  {
    status: 404,

    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  }
);
}

// -------------------------------------------------------------
// ROUTE 3.5: ANALYTICS CATCH-ALL PROXY
// -------------------------------------------------------------

if (url.pathname.startsWith("/api/analytics")) {

  if (!userId) {

    return new Response(
      JSON.stringify({
        error: "Unauthorized: Missing authentication token."
      }),
      {
        status: 401,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );

  }


  // -------------------------------------------------------------
  // TOO LOST BASE URL
  // -------------------------------------------------------------

  const baseUrl = (
    env.TOO_LOST_BASE_URL ||
    "https://api-sandbox.toolost.com/v1"
  ).replace(/\/$/, "");


  // -------------------------------------------------------------
  // GET TOO LOST ACCESS TOKEN
  // -------------------------------------------------------------

  let tooLostAccessToken;

  try {

    tooLostAccessToken =
      await getAccessToken(env);

  } catch (authError) {

    console.error(
      "Too Lost Analytics Authentication Error:",
      authError
    );

    return new Response(
      JSON.stringify({
        error: "Too Lost Authentication Failed",
        details:
          authError?.message ||
          "Unable to authenticate with Too Lost."
      }),
      {
        status: 401,
        headers: {
          ...corsHeaders,
          "Content-Type": "application/json"
        }
      }
    );

  }


  // -------------------------------------------------------------
  // REMOVE AUDIORY FRONTEND PREFIX
  //
  // Example:
  //
  // /api/analytics/platforms
  //
  // becomes:
  //
  // /analytics/platforms
  // -------------------------------------------------------------

  const subPath =
    url.pathname.replace(
      /^\/api\/analytics/,
      ""
    );


  // -------------------------------------------------------------
  // BUILD TOO LOST URL
  // -------------------------------------------------------------

  const targetUrl =
    `${baseUrl}/analytics${subPath}${url.search || ""}`;


  // -------------------------------------------------------------
  // FETCH OPTIONS
  // -------------------------------------------------------------

  const fetchOptions = {

    method: request.method,

    headers: {

      "Accept":
        "application/json",

      "Authorization":
        `Bearer ${tooLostAccessToken}`

    }

  };


  // -------------------------------------------------------------
  // PASS REQUEST BODY FOR NON-GET REQUESTS
  // -------------------------------------------------------------

  if (
    request.method !== "GET" &&
    request.method !== "HEAD"
  ) {

    fetchOptions.body =
      await request.text();

    const contentType =
      request.headers.get(
        "Content-Type"
      );

    if (contentType) {

      fetchOptions.headers[
        "Content-Type"
      ] = contentType;

    }

  }


  // -------------------------------------------------------------
  // CALL TOO LOST
  // -------------------------------------------------------------

  try {

    console.log(
      "Audiory Analytics -> Too Lost:",
      targetUrl
    );


    const res =
      await fetch(
        targetUrl,
        fetchOptions
      );


    const resText =
      await res.text();


    // -----------------------------------------------------------
    // TRY TO PARSE TOO LOST RESPONSE
    // -----------------------------------------------------------

    let parsed = null;

    try {

      parsed =
        JSON.parse(
          resText || "{}"
        );

    } catch (parseError) {

      parsed = null;

    }


    // -----------------------------------------------------------
    // LOG ALL NON-2XX ANALYTICS RESPONSES
    //
    // This is especially important for:
    //
    // /platforms/total-streams
    //
    // because Too Lost is currently returning HTTP 500
    // for Spotify.
    // -----------------------------------------------------------

    if (!res.ok) {

      console.error(
        "Too Lost Analytics Upstream Error:",
        {
          status: res.status,
          endpoint: subPath,
          query: url.search,
          targetUrl: targetUrl,
          response: parsed !== null
            ? parsed
            : resText
        }
      );

    }


    // -----------------------------------------------------------
    // RELEASE LINKS
    //
    // Too Lost may return a 5xx when release-link analytics
    // are unavailable in the current sandbox/account.
    //
    // Preserve the existing working Release Links behavior.
    // -----------------------------------------------------------

    if (

      res.status >= 500 &&

      subPath.startsWith(
        "/release-links/top-releases"
      )

    ) {

      console.error(
        "Too Lost Release Links upstream error:",
        {
          status: res.status,
          response:
            parsed !== null
              ? parsed
              : resText
        }
      );


      return new Response(

        JSON.stringify({

          data: [],

          currentPage: 1,

          perPage: 10,

          totalItems: 0,

          totalPages: 0,

          available: false,

          message:
            "Release link analytics are not currently available from Too Lost."

        }),

        {

          status: 200,

          headers: {

            ...corsHeaders,

            "Content-Type":
              "application/json"

          }

        }

      );

    }


    // -----------------------------------------------------------
    // PLATFORM TOTAL STREAMS
    //
    // IMPORTANT:
    //
    // Do NOT convert a Too Lost 500 into fake empty analytics.
    //
    // Return a structured error so the frontend can see the
    // actual Too Lost response.
    //
    // This lets us determine whether Spotify itself does not
    // support this endpoint or whether Too Lost has another
    // platform-specific requirement.
    // -----------------------------------------------------------

    if (

      res.status >= 500 &&

      subPath ===
        "/platforms/total-streams"

    ) {

      const upstreamDetails =
        parsed !== null
          ? parsed
          : (
              resText ||
              "Too Lost returned an empty error response."
            );


      return new Response(

        JSON.stringify({

          error:
            "Too Lost platform total-streams analytics failed.",

          endpoint:
            "/analytics/platforms/total-streams",

          status:
            res.status,

          platform:
            url.searchParams.get(
              "platform"
            ),

          period:
            url.searchParams.get(
              "period"
            ),

          release:
            url.searchParams.get(
              "release"
            ),

          tooLostResponse:
            upstreamDetails

        }),

        {

          status:
            res.status,

          headers: {

            ...corsHeaders,

            "Content-Type":
              "application/json"

          }

        }

      );

    }


    // -----------------------------------------------------------
    // PLATFORM OVERVIEW
    //
    // Do not hide platform overview errors either.
    // -----------------------------------------------------------

    if (

      res.status >= 500 &&

      subPath ===
        "/platforms/data"

    ) {

      const upstreamDetails =
        parsed !== null
          ? parsed
          : (
              resText ||
              "Too Lost returned an empty error response."
            );


      return new Response(

        JSON.stringify({

          error:
            "Too Lost platform overview analytics failed.",

          endpoint:
            "/analytics/platforms/data",

          status:
            res.status,

          platform:
            url.searchParams.get(
              "platform"
            ),

          period:
            url.searchParams.get(
              "period"
            ),

          release:
            url.searchParams.get(
              "release"
            ),

          tooLostResponse:
            upstreamDetails

        }),

        {

          status:
            res.status,

          headers: {

            ...corsHeaders,

            "Content-Type":
              "application/json"

          }

        }

      );

    }


    // -----------------------------------------------------------
    // PLATFORM ADDITIONAL ANALYTICS
    // -----------------------------------------------------------

    if (

      res.status >= 500 &&

      (
        subPath ===
          "/platforms/additional" ||

        subPath ===
          "/platforms/additional/info"

      )

    ) {

      const upstreamDetails =
        parsed !== null
          ? parsed
          : (
              resText ||
              "Too Lost returned an empty error response."
            );


      return new Response(

        JSON.stringify({

          error:
            "Too Lost platform additional analytics failed.",

          endpoint:
            `/analytics${subPath}`,

          status:
            res.status,

          platform:
            url.searchParams.get(
              "platform"
            ),

          type:
            url.searchParams.get(
              "type"
            ),

          period:
            url.searchParams.get(
              "period"
            ),

          release:
            url.searchParams.get(
              "release"
            ),

          tooLostResponse:
            upstreamDetails

        }),

        {

          status:
            res.status,

          headers: {

            ...corsHeaders,

            "Content-Type":
              "application/json"

          }

        }

      );

    }


    // -----------------------------------------------------------
    // NORMAL RESPONSE
    //
    // Preserve Too Lost's original HTTP status and JSON body.
    // -----------------------------------------------------------

    return new Response(

      parsed !== null
        ? JSON.stringify(parsed)
        : resText,

      {

        status:
          res.status,

        headers: {

          ...corsHeaders,

          "Content-Type":
            "application/json"

        }

      }

    );


  } catch (fetchErr) {

    // -----------------------------------------------------------
    // NETWORK / CLOUDFLARE FETCH FAILURE
    // -----------------------------------------------------------

    console.error(
      "Too Lost Analytics Proxy Error:",
      fetchErr
    );


    return new Response(

      JSON.stringify({

        error:
          "Upstream Proxy Fetch Failed",

        details:
          fetchErr?.message ||
          "Unable to contact Too Lost."

      }),

      {

        status: 502,

        headers: {

          ...corsHeaders,

          "Content-Type":
            "application/json"

        }

      }

    );

  }

}

      // -------------------------------------------------------------
      // ROUTE 3.6: Too Lost Sales Routes
      // -------------------------------------------------------------
      if (url.pathname.startsWith("/api/toolost/sales/")) {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");

        let tooLostAccessToken;
        try {
          tooLostAccessToken = await getAccessToken(env);
        } catch (authError) {
          return new Response(
            JSON.stringify({ error: "Too Lost Authentication Failed", details: authError.message }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const subPath = url.pathname.replace(/^\/api\/toolost\/sales/, "");
        let salesEndpoint = null;

        if (subPath === "/overview") salesEndpoint = "/sales/overview";
        else if (subPath === "/territories") salesEndpoint = "/sales/territories";
        else if (subPath === "/stream-rates") salesEndpoint = "/sales/stream-rates";
        else if (subPath === "/artists") salesEndpoint = "/sales/artists";
        else if (subPath === "/releases") salesEndpoint = "/sales/releases";
        else if (subPath === "/channels") salesEndpoint = "/sales/channels";
        else if (subPath === "/tracks") salesEndpoint = "/sales/tracks";
        else {
          const trackChannelsMatch = subPath.match(/^\/tracks\/([^\/]+)\/channels$/);
          if (trackChannelsMatch) {
            salesEndpoint = `/sales/tracks/${trackChannelsMatch[1]}/channels`;
          }
        }

        if (!salesEndpoint) {
          return new Response(
            JSON.stringify({ error: "Not Found", message: "Unknown Sales endpoint." }),
            { status: 404, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        try {
          const tooLostUrl = new URL(`${baseUrl}${salesEndpoint}`);
          url.searchParams.forEach((value, key) => tooLostUrl.searchParams.set(key, value));

          const response = await fetch(tooLostUrl.toString(), {
            method: "GET",
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${tooLostAccessToken}`
            }
          });

          // Handle Sandbox 404s gracefully by returning empty arrays
          if (response.status === 404) {
            return new Response(JSON.stringify([]), {
              status: 200,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }

          const responseText = await response.text();
          return new Response(responseText, {
            status: response.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });

        } catch (err) {
          return new Response(
            JSON.stringify({ error: "Too Lost Sales API Request Failed", details: err.message }),
            { status: 502, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
      }

      // -------------------------------------------------------------
      // ROUTE 4: Get & Submit Withdrawals (/api/withdrawals)
      // -------------------------------------------------------------
      if (url.pathname === "/api/withdrawals") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `WITHDRAWALS_USER_${userId}`;

        if (request.method === "GET") {
          let userWithdrawals = [];
          if (env.AUDIORY_KV) {
            userWithdrawals = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
          }
          return new Response(JSON.stringify(userWithdrawals), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const amount = parseFloat(body.amount);

          const currentDay = new Date().getUTCDate();
          if (currentDay < 15 || currentDay > 25) {
            return new Response(
              JSON.stringify({ error: "Withdrawals are allowed exclusively between the 15th and 25th of each month." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          if (isNaN(amount) || amount < 20) {
            return new Response(
              JSON.stringify({ error: "Minimum withdrawal amount is $20.00." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          let existingRequests = [];
          if (env.AUDIORY_KV) {
            existingRequests = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
          }

          const currentMonth = new Date().toISOString().slice(0, 7);
          const hasExisting = existingRequests.some(r => r.date && r.date.startsWith(currentMonth));
          if (hasExisting) {
            return new Response(
              JSON.stringify({ error: "You have already submitted a withdrawal request for this monthly cycle." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          const newRequest = {
            id: `wd_${Date.now()}`,
            amount: amount,
            method: body.method || "mpesa",
            details: body.details || "",
            status: "Pending",
            date: new Date().toISOString()
          };

          existingRequests.unshift(newRequest);

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(existingRequests));
          }

          return new Response(JSON.stringify({ success: true, request: newRequest }), {
            status: 201,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // -------------------------------------------------------------
      // ROUTE 5: Proxy Requests to Too Lost API v1
      // -------------------------------------------------------------
      if (url.pathname.startsWith("/api/toolost") && url.pathname !== "/api/toolost/earnings") {
        let endpoint = url.pathname.replace(/^\/api\/toolost\/?/, "");
        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");
        const targetUrl = `${baseUrl}/${endpoint}${url.search}`;

        let accessToken;
        try {
          accessToken = await getAccessToken(env);
        } catch (authError) {
          return new Response(
            JSON.stringify({ error: "Too Lost Authentication Failed", details: authError.message }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const toolostHeaders = new Headers({
          "Accept": "application/json",
          "Authorization": `Bearer ${accessToken}`,
        });

        const init = {
          method: request.method,
          headers: toolostHeaders,
        };

        if (["POST", "PUT", "PATCH"].includes(request.method)) {
          toolostHeaders.set("Content-Type", "application/json");
          init.body = await request.text();
        }

        const apiResponse = await fetch(targetUrl, init);
        const responseData = await apiResponse.text();

        return new Response(responseData, {
          status: apiResponse.status,
          headers: {
            ...corsHeaders,
            "Content-Type": apiResponse.headers.get("content-type") || "application/json",
          },
        });
      }

      // -------------------------------------------------------------
      // ROUTE 6: Upload Cover & Audio Files to Cloudflare R2
      // -------------------------------------------------------------
      if (url.pathname === "/api/upload" && request.method === "POST") {
        if (!env.MEDIA_BUCKET) {
          return new Response(
            JSON.stringify({ error: "Cloudflare R2 Bucket 'MEDIA_BUCKET' is not bound to this worker." }),
            { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const formData = await request.formData();
        const file = formData.get("file");
        const folder = formData.get("folder") || "general";

        if (!file) {
          return new Response(JSON.stringify({ error: "No file provided" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        const fileKey = `${folder}/${Date.now()}-${file.name.replace(/\s+/g, "_")}`;

        await env.MEDIA_BUCKET.put(fileKey, file.stream(), {
          httpMetadata: { contentType: file.type },
        });

        const fileUrl = `${env.R2_PUBLIC_DOMAIN || 'https://pub-r2.audiory.site'}/${fileKey}`;

        return new Response(
          JSON.stringify({
            success: true,
            key: fileKey,
            url: fileUrl,
            size: file.size,
            type: file.type,
          }),
          {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          }
        );
      }

      // Default Health Check Endpoint
      return new Response(JSON.stringify({ status: "Audiory API Gateway Online" }), {
        status: 200,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });

    } catch (error) {
      return new Response(JSON.stringify({ error: error.message }), {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }
  },
};

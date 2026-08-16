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
    const decodedJson = atob(payloadBase64.replace(/-/g, "+").replace(/_/g, "/"));
    const payload = JSON.parse(decodedJson);
    return payload.user_id || payload.uid || payload.sub || null;
  } catch (e) {
    return null;
  }
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
  async fetch(request, env) {
    const url = new URL(request.url);

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Custom-Auth",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      const userId = parseUserIdFromToken(request);

      // -------------------------------------------------------------
      // ROUTE 1: Release Creation & Editing Route (POST & PUT)
      // -------------------------------------------------------------
      const isReleaseSubmitPath = url.pathname === "/api/releases" || 
                                  url.pathname === "/api/releases/submit" || 
                                  url.pathname.startsWith("/api/releases/");

      if (isReleaseSubmitPath && (request.method === "POST" || request.method === "PUT")) {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const payloadText = await request.text();
        let payloadObj = {};
        try { payloadObj = JSON.parse(payloadText || '{}'); } catch {}

        const pathId = url.pathname.split("/").pop();
        const targetReleaseId = (pathId && pathId !== "releases" && pathId !== "submit") 
          ? pathId 
          : (payloadObj.editingId || payloadObj.id || payloadObj.releaseId || null);

        const isUpdate = Boolean(targetReleaseId) || request.method === "PUT";
        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");
        
        let accessToken;
        try {
          accessToken = await getAccessToken(env);
        } catch (authError) {
          return new Response(
            JSON.stringify({ error: "Too Lost Authentication Failed", details: authError.message }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const tooLostEndpoint = isUpdate && targetReleaseId 
          ? `${baseUrl}/releases/${targetReleaseId}` 
          : `${baseUrl}/releases`;

        const response = await fetch(tooLostEndpoint, {
          method: isUpdate ? "PUT" : "POST",
          headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": `Bearer ${accessToken}`,
          },
          body: payloadText,
        });

        const responseText = await response.text();
        let serverData = {};
        try { serverData = JSON.parse(responseText); } catch {}

        if (env.AUDIORY_KV && (response.ok || response.status === 200 || response.status === 201)) {
          const resolvedCover = payloadObj.coverUrl || 
                                payloadObj.cover_url || 
                                payloadObj.cover_art || 
                                payloadObj.compressedArtwork || 
                                (payloadObj.artwork && payloadObj.artwork.url ? payloadObj.artwork.url : '') ||
                                '';

          const cacheId = targetReleaseId || serverData.id || serverData.data?.id || `local_${Date.now()}`;
          
          const cacheItem = {
            id: cacheId,
            title: payloadObj.title || 'Untitled',
            type: payloadObj.type || 'Single',
            status: 'Submitted',
            label: typeof payloadObj.label === 'string' ? payloadObj.label : 'Audiory',
            coverUrl: resolvedCover,
            compressedArtwork: resolvedCover,
            artworkUrl: resolvedCover,
            participants: payloadObj.participants || payloadObj.artists || [],
            upc: serverData.upc || serverData.data?.upc || payloadObj.upc || 'Pending',
            submittedBy: userId,
            createdAt: payloadObj.createdAt || new Date().toISOString()
          };

          const userKvKey = `RELEASES_USER_${userId}`;
          const existingCached = JSON.parse(await env.AUDIORY_KV.get(userKvKey) || '[]');
          
          const existingIdx = existingCached.findIndex(item => String(item.id) === String(cacheId));
          if (existingIdx !== -1) {
            existingCached[existingIdx] = { ...existingCached[existingIdx], ...cacheItem };
          } else {
            existingCached.unshift(cacheItem);
          }

          await env.AUDIORY_KV.put(userKvKey, JSON.stringify(existingCached));
        }

        return new Response(responseText, {
          status: response.status,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // -------------------------------------------------------------
      // ROUTE 2: Release Deletion Route (DELETE /api/releases/:id)
      // -------------------------------------------------------------
      const deleteMatch = url.pathname.match(/^\/api\/releases\/(.+)$/);
      if (deleteMatch && request.method === "DELETE") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const releaseId = deleteMatch[1];
        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");

        if (env.AUDIORY_KV) {
          const userKvKey = `RELEASES_USER_${userId}`;
          const existingCached = JSON.parse(await env.AUDIORY_KV.get(userKvKey) || '[]');
          const filteredKV = existingCached.filter(item => String(item.id) !== String(releaseId));
          await env.AUDIORY_KV.put(userKvKey, JSON.stringify(filteredKV));
        }

        try {
          const accessToken = await getAccessToken(env);
          await fetch(`${baseUrl}/releases/${releaseId}`, {
            method: "DELETE",
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${accessToken}`,
            },
          });
        } catch (apiErr) {
          console.error("Too Lost API Deletion Error:", apiErr);
        }

        return new Response(JSON.stringify({ success: true, message: "Release deleted successfully" }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // -------------------------------------------------------------
      // ROUTE 3: Catalogue Fetching Route (Strict User Isolation)
      // -------------------------------------------------------------
      if (url.pathname === "/api/releases" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");
        
        let accessToken;
        try {
          accessToken = await getAccessToken(env);
        } catch (authError) {
          return new Response(
            JSON.stringify({ error: "Too Lost Authentication Failed", details: authError.message }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        let apiReleases = [];
        try {
          const response = await fetch(`${baseUrl}/releases${url.search}`, {
            method: "GET",
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${accessToken}`,
            },
          });

          if (response.ok) {
            const resJson = await response.json();
            const rawList = Array.isArray(resJson) ? resJson : (resJson.data || resJson.releases || []);
            apiReleases = rawList.filter(item => item.submittedBy === userId);
          }
        } catch (e) {
          console.error("Too Lost Fetch Error:", e);
        }

        let userCachedReleases = [];
        if (env.AUDIORY_KV) {
          const userKvKey = `RELEASES_USER_${userId}`;
          userCachedReleases = JSON.parse(await env.AUDIORY_KV.get(userKvKey) || '[]');
        }

        const combinedMap = new Map();
        userCachedReleases.forEach(item => combinedMap.set(String(item.id), item));
        
        apiReleases.forEach(item => {
          const existing = combinedMap.get(String(item.id));
          if (existing) {
            combinedMap.set(String(item.id), { ...item, ...existing });
          } else {
            combinedMap.set(String(item.id), item);
          }
        });

        const finalCatalog = Array.from(combinedMap.values());

        return new Response(JSON.stringify(finalCatalog), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        });
      }

      // -------------------------------------------------------------
      // ROUTE 3.5: Analytics Routes (Overview & Tracks)
      // -------------------------------------------------------------
      if (url.pathname.startsWith("/api/analytics/")) {
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

        if (url.pathname === "/api/analytics/overview") {
          const period = url.searchParams.get("period") || "lastThirtyDays";
          const response = await fetch(`${baseUrl}/analytics/overview?period=${period}`, {
            method: "GET",
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${tooLostAccessToken}`,
            },
          });
          const responseText = await response.text();
          return new Response(responseText, {
            status: response.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
        }

        if (url.pathname === "/api/analytics/tracks") {
          const period = url.searchParams.get("period") || "lastThirtyDays";
          const page = url.searchParams.get("page") || "1";
          const perPage = url.searchParams.get("perPage") || "10";
          const response = await fetch(`${baseUrl}/analytics/tracks?period=${period}&page=${page}&perPage=${perPage}`, {
            method: "GET",
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${tooLostAccessToken}`,
            },
          });
          const responseText = await response.text();
          return new Response(responseText, {
            status: response.status,
            headers: { ...corsHeaders, "Content-Type": "application/json" },
          });
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

        // GET: Fetch withdrawal history for the logged-in user
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

        // POST: Request a new withdrawal
        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const amount = parseFloat(body.amount);

          // 1. Date window check (15th - 25th)
          const currentDay = new Date().getUTCDate();
          if (currentDay < 15 || currentDay > 25) {
            return new Response(
              JSON.stringify({ error: "Withdrawals are allowed exclusively between the 15th and 25th of each month." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          // 2. Minimum amount check
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

          // 3. Cycle duplicate check (only 1 request per month)
          const currentMonth = new Date().toISOString().slice(0, 7); // "YYYY-MM"
          const hasExisting = existingRequests.some(r => r.date && r.date.startsWith(currentMonth));
          if (hasExisting) {
            return new Response(
              JSON.stringify({ error: "You have already submitted a withdrawal request for this monthly cycle." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          // Create new record
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
      // ROUTE 5: Get Live TooLost Earnings (/api/toolost/earnings)
      // -------------------------------------------------------------
      if (url.pathname === "/api/toolost/earnings" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const baseUrl = (env.TOO_LOST_BASE_URL || "https://api-sandbox.toolost.com/v1").replace(/\/$/, "");

        try {
          const accessToken = await getAccessToken(env);
          const response = await fetch(`${baseUrl}/analytics/earnings`, {
            headers: {
              "Accept": "application/json",
              "Authorization": `Bearer ${accessToken}`
            }
          });

          if (response.ok) {
            const earningsData = await response.json();
            return new Response(JSON.stringify(earningsData), {
              status: 200,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        } catch (err) {
          console.error("Too Lost Earnings API Error:", err);
        }

        // Return empty payload fallback on API error
        return new Response(JSON.stringify({ totalBalance: 0, platformBreakdown: [] }), {
          status: 200,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }

      // -------------------------------------------------------------
      // ROUTE 6: Proxy Requests to Too Lost API v1
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
      // ROUTE 7: Upload Cover & Audio Files to Cloudflare R2
      // -------------------------------------------------------------
      if (url.pathname === "/api/upload" && request.method === "POST") {
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

        const fileUrl = `${env.R2_PUBLIC_DOMAIN}/${fileKey}`;

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

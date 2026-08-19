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

      // =============================================================
      // PILLAR 1: MY PROFILE API (/api/profile)
      // =============================================================
      if (url.pathname === "/api/profile") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `PROFILE_USER_${userId}`;

        // GET Profile
        if (request.method === "GET") {
          let profile = {};
          if (env.AUDIORY_KV) {
            profile = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "{}");
          }
          return new Response(JSON.stringify(profile), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // POST/PUT Update Profile Name
        if (request.method === "POST" || request.method === "PUT") {
          const body = await request.json().catch(() => ({}));
          const { displayName } = body;

          if (!displayName) {
            return new Response(
              JSON.stringify({ error: "Profile name is required." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          const profileData = {
            displayName,
            updatedAt: new Date().toISOString()
          };

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(profileData));
          }

          return new Response(JSON.stringify({ success: true, profile: profileData }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

      // =============================================================
      // PILLAR 2: ACCOUNT MEMBERS & ACCESS CONTROL (/api/members)
      // =============================================================
      if (url.pathname === "/api/members" || url.pathname === "/api/members/invite" || url.pathname.startsWith("/api/members/")) {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `MEMBERS_USER_${userId}`;

        // GET Members
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

        // POST Invite Member
        if (url.pathname === "/api/members/invite" && request.method === "POST") {
          const { email, roles } = await request.json().catch(() => ({}));
          if (!email || !roles || !Array.isArray(roles) || roles.length === 0) {
            return new Response(
              JSON.stringify({ error: "Member email and at least one role (Content, Royalties, Analytics, SplitShare, Admin) are required." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          let members = [];
          if (env.AUDIORY_KV) {
            members = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
          }

          const newMember = {
            id: `mem_${Date.now()}`,
            email,
            roles,
            status: "Pending",
            invitedAt: new Date().toISOString()
          };

          members.unshift(newMember);

          if (env.AUDIORY_KV) {
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(members));
          }

          return new Response(JSON.stringify({ success: true, member: newMember }), {
            status: 201,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // DELETE Member
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

        // GET Tax Details
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

        // POST Tax Details
        if (request.method === "POST") {
          const body = await request.json().catch(() => ({}));
          const { legalName, classification, country, tin, address } = body;

          if (!legalName || !country || !tin) {
            return new Response(
              JSON.stringify({ error: "Legal name, country, and Tax Identification Number (TIN) are required." }),
              { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
            );
          }

          const taxRecord = {
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
      // PILLAR 5: DYNAMIC SUBSCRIPTION & BILLING HISTORY
      // =============================================================
      
      // Available Audiory Plans Catalog
      const PLANS = {
        starter: { name: "Starter Plan", price: "0.00", description: "Starter Plan (Free Tier)" },
        pro: { name: "Pro Artist Plan", price: "19.99", description: "Pro Artist Plan (Annual Subscription)" },
        label: { name: "Label Partner", price: "49.99", description: "Label Partner Plan (Annual Subscription)" }
      };

      // 1. GET Billing History & Active Subscription
      if (url.pathname === "/api/billing-history" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const billingKvKey = `BILLING_USER_${userId}`;
        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;

        let history = [];
        let currentSub = null;

        if (env.AUDIORY_KV) {
          const rawHistory = await env.AUDIORY_KV.get(billingKvKey);
          const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);

          history = rawHistory ? JSON.parse(rawHistory) : [];
          currentSub = rawSub ? JSON.parse(rawSub) : null;
        }

        // Default to Starter Plan if no record exists
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

      // 2. GET Subscription Status Endpoint (For polling)
      if (url.pathname === "/api/subscription/status" && request.method === "GET") {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
        let currentSub = null;

        if (env.AUDIORY_KV) {
          const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
          currentSub = rawSub ? JSON.parse(rawSub) : null;
        }

        return new Response(
          JSON.stringify({ status: currentSub ? currentSub.status : "Pending", subscription: currentSub }),
          { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }

      // 3. POST Payment & Subscription Upgrade
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

        if (selectedPlan.price !== "0.00") {
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
    // Dynamic URL switching for Sandbox vs Production
    const pesapalBase = env.PESAPAL_MODE === "sandbox" 
      ? "https://cyb3r.pesapal.com/pesapalv3" 
      : "https://pay.pesapal.com/v3";

    // Step 1: Request Access Token
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

    // Step 2: Register IPN URL if not configured in Worker secrets
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

    // Step 3: Format Name Fields (Required by PesaPal v3 schema)
    const names = (displayName || "Subscriber").trim().split(" ");
    const firstName = names[0] || "Subscriber";
    const lastName = names.slice(1).join(" ") || "Artist";

    // Step 4: Submit Order Request
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


        // SAVE PENDING STATE TO CLOUDFLARE KV UNTIL WEBHOOK CONFIRMS
        const subscriptionKvKey = `SUBSCRIPTION_USER_${userId}`;
        const billingKvKey = `BILLING_USER_${userId}`;

        const activeSubData = {
          planId: planId,
          planName: selectedPlan.name,
          amount: selectedPlan.price,
          paymentMethod: paymentMethod || "card",
          transactionId: transactionId,
          // Free plan gets immediate activation; paid plans remain Pending until Webhook confirmation
          status: selectedPlan.price === "0.00" ? "Active" : "Pending",
          updatedAt: new Date().toISOString()
        };

        if (env.AUDIORY_KV) {
          await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(activeSubData));

          // Save transaction lookup mapping so Webhook can find the userId from CheckoutRequestID
          if (paymentMethod === "mpesa" && transactionId) {
            await env.AUDIORY_KV.put(`MPESA_TX_${transactionId}`, userId);
          }

          if (selectedPlan.price !== "0.00") {
            const rawHistory = await env.AUDIORY_KV.get(billingKvKey);
            const history = rawHistory ? JSON.parse(rawHistory) : [];

            history.unshift({
              invoiceId: `INV-${Math.floor(10000 + Math.random() * 90000)}`,
              date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }),
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
    const resultCode = stkCallback.ResultCode; // 0 = Success

    const targetUserId = await env.AUDIORY_KV.get(`MPESA_TX_${checkoutReqId}`);

    if (targetUserId) {
      const subscriptionKvKey = `SUBSCRIPTION_USER_${targetUserId}`;
      const billingKvKey = `BILLING_USER_${targetUserId}`;

      const rawSub = await env.AUDIORY_KV.get(subscriptionKvKey);
      const rawBilling = await env.AUDIORY_KV.get(billingKvKey);

      let currentSub = rawSub ? JSON.parse(rawSub) : null;
      let billingHistory = rawBilling ? JSON.parse(rawBilling) : [];

      if (resultCode === 0) {
        if (currentSub) {
          currentSub.status = "Active";
          currentSub.updatedAt = new Date().toISOString();
          await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
        }

        if (billingHistory.length > 0) {
          billingHistory[0].status = "Paid";
          await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(billingHistory));
        }
      } else {
        if (currentSub) {
          currentSub.status = "Failed";
          currentSub.updatedAt = new Date().toISOString();
          await env.AUDIORY_KV.put(subscriptionKvKey, JSON.stringify(currentSub));
        }

        if (billingHistory.length > 0) {
          billingHistory[0].status = "Failed";
          await env.AUDIORY_KV.put(billingKvKey, JSON.stringify(billingHistory));
        }
      }

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
      if (url.pathname === "/api/login-history" || url.pathname === "/api/login-history/revoke-all" || url.pathname.startsWith("/api/login-history/")) {
        if (!userId) {
          return new Response(
            JSON.stringify({ error: "Unauthorized: Invalid or missing authentication token." }),
            { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }

        const kvKey = `SESSIONS_USER_${userId}`;
        const clientIp = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "197.237.12.89";
        const userAgent = request.headers.get("user-agent") || "Chrome on macOS";

        // GET Sessions
        if (url.pathname === "/api/login-history" && request.method === "GET") {
          let sessions = [];
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kvKey);
            sessions = raw ? JSON.parse(raw) : [];
          }

          if (sessions.length === 0) {
            sessions = [
              {
                id: "sess_current",
                device: userAgent.includes("Mobile") ? "Mobile Web Browser" : "Desktop Browser",
                ip: clientIp,
                location: request.cf ? `${request.cf.city}, ${request.cf.country}` : "Nairobi, Kenya",
                lastActive: "Just now",
                isCurrent: true
              }
            ];
          }

          return new Response(JSON.stringify(sessions), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // POST Terminate All Sessions Except Current
        if (url.pathname === "/api/login-history/revoke-all" && request.method === "POST") {
          let sessions = [];
          if (env.AUDIORY_KV) {
            const raw = await env.AUDIORY_KV.get(kvKey);
            sessions = raw ? JSON.parse(raw) : [];
            sessions = sessions.filter(s => s.isCurrent);
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(sessions));
          }

          return new Response(JSON.stringify({ success: true, message: "All non-current sessions revoked." }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }

        // DELETE Specific Session
        if (url.pathname.startsWith("/api/login-history/") && request.method === "DELETE") {
          const sessionId = url.pathname.split("/").pop();
          if (env.AUDIORY_KV) {
            let sessions = JSON.parse((await env.AUDIORY_KV.get(kvKey)) || "[]");
            sessions = sessions.filter(s => String(s.id) !== String(sessionId));
            await env.AUDIORY_KV.put(kvKey, JSON.stringify(sessions));
          }

          return new Response(JSON.stringify({ success: true, revokedId: sessionId }), {
            status: 200,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }

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

        let salesEndpoint = null;
        if (url.pathname === "/api/toolost/sales/overview") salesEndpoint = "/sales/overview";
        else if (url.pathname === "/api/toolost/sales/channels") salesEndpoint = "/sales/channels";
        else if (url.pathname === "/api/toolost/sales/tracks") salesEndpoint = "/sales/tracks";
        else if (url.pathname === "/api/toolost/sales/releases") salesEndpoint = "/sales/releases";

        if (!salesEndpoint) {
          return new Response(
            JSON.stringify({ error: "Not Found", message: "Unknown Too Lost Sales endpoint." }),
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

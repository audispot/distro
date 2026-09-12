const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization"
};

// -------------------------
// Utility functions
// -------------------------

function json(data, status = 200) {
  return Response.json(data, {
    status,
    headers: corsHeaders
  });
}

function base64url(input) {
  let bytes;

  if (input instanceof ArrayBuffer) {
    bytes = new Uint8Array(input);
  } else if (ArrayBuffer.isView(input)) {
    bytes = new Uint8Array(
      input.buffer,
      input.byteOffset,
      input.byteLength
    );
  } else {
    bytes = new TextEncoder().encode(String(input));
  }

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function generateId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

// -------------------------
// Password hashing
// -------------------------

async function hashPassword(password) {
  const encoder = new TextEncoder();

  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return `${base64url(salt)}.${base64url(derivedBits)}`;
}

// -------------------------
// Password verification
// -------------------------

async function verifyPassword(password, storedHash) {
  const [saltString, hashString] = storedHash.split(".");

  if (!saltString || !hashString) {
    return false;
  }

  const encoder = new TextEncoder();

  function decodeBase64Url(value) {
    value = value
      .replace(/-/g, "+")
      .replace(/_/g, "/");

    while (value.length % 4) {
      value += "=";
    }

    const binary = atob(value);

    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }

  const salt = decodeBase64Url(saltString);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );

  return base64url(derivedBits) === hashString;
}

// -------------------------
// JWT creation
// -------------------------

async function createToken(user, secret) {
  const encoder = new TextEncoder();

  const header = {
    alg: "HS256",
    typ: "JWT"
  };

  const payload = {
    sub: user.id,
    email: user.email,
    role: user.role,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24
  };

  const encodedHeader = base64url(
    JSON.stringify(header)
  );

  const encodedPayload = base64url(
    JSON.stringify(payload)
  );

  const unsignedToken =
    `${encodedHeader}.${encodedPayload}`;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256"
    },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(unsignedToken)
  );

  return `${unsignedToken}.${base64url(signature)}`;
}

// -------------------------
// JWT verification
// -------------------------

async function verifyToken(token, secret) {
  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      return null;
    }

    const [
      encodedHeader,
      encodedPayload,
      encodedSignature
    ] = parts;

    const unsignedToken =
      `${encodedHeader}.${encodedPayload}`;

    const encoder = new TextEncoder();

    function decodeBase64Url(value) {
      value = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

      while (value.length % 4) {
        value += "=";
      }

      const binary = atob(value);

      const bytes = new Uint8Array(binary.length);

      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }

      return bytes;
    }

    const signature =
      decodeBase64Url(encodedSignature);

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      {
        name: "HMAC",
        hash: "SHA-256"
      },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      signature,
      encoder.encode(unsignedToken)
    );

    if (!valid) {
      return null;
    }

    const payloadBytes =
      decodeBase64Url(encodedPayload);

    const payload =
      JSON.parse(
        new TextDecoder().decode(payloadBytes)
      );

    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }

    return payload;

  } catch {
    return null;
  }
}

function getBearerToken(request) {
  const authHeader = request.headers.get("Authorization");

  if (!authHeader) {
    return null;
  }

  const parts = authHeader.trim().split(/\s+/);

  if (parts.length !== 2) {
    return null;
  }

  if (parts[0].toLowerCase() !== "bearer") {
    return null;
  }

  return parts[1];
}

function validateSalesDate(value) {
  if (!value) return true;
  return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

function getSalesDateFilters(url) {
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");

  if (from && !validateSalesDate(from)) {
    throw new Error("Invalid from date. Expected YYYY-MM-DD");
  }

  if (to && !validateSalesDate(to)) {
    throw new Error("Invalid to date. Expected YYYY-MM-DD");
  }

  return { from, to };
}

function addSalesDateConditions(conditions, params, from, to, column = "sd.event_date") {
  if (from) {
    conditions.push(`${column} >= ?`);
    params.push(from);
  }

  if (to) {
    conditions.push(`${column} <= ?`);
    params.push(to);
  }
}

function salesUserId(auth) {
  return auth.sub || auth.user_id || auth.userId || auth.id;
}

function roundSalesMoney(value) {
  return Math.round(Number(value || 0) * 100) / 100;
}

function getSalesPagination(url) {
  let limit = Number(url.searchParams.get("limit") || 50);
  let offset = Number(url.searchParams.get("offset") || 0);

  if (!Number.isFinite(limit) || limit < 1) limit = 50;
  if (limit > 100) limit = 100;

  if (!Number.isFinite(offset) || offset < 0) offset = 0;

  return {
    limit: Math.floor(limit),
    offset: Math.floor(offset)
  };
}

function getSalesDateRange(url) {
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");

  if (from && !validateSalesDate(from)) {
    return {
      error: "Invalid from date. Expected YYYY-MM-DD"
    };
  }

  if (to && !validateSalesDate(to)) {
    return {
      error: "Invalid to date. Expected YYYY-MM-DD"
    };
  }

  if (from && to && from > to) {
    return {
      error: "The from date cannot be after the to date"
    };
  }

  return { from, to };
}

function formatSalesSummary(rows) {
  const currencies = {};

  let streams = 0;
  let downloads = 0;
  let units = 0;

  for (const row of rows || []) {
    const currency = row.currency || "USD";

    if (!currencies[currency]) {
      currencies[currency] = {
        currency,
        streams: 0,
        downloads: 0,
        units: 0,
        gross_revenue: 0,
        net_revenue: 0
      };
    }

    const item = currencies[currency];

    const rowStreams = Number(row.streams || 0);
    const rowDownloads = Number(row.downloads || 0);
    const rowUnits = Number(row.units || 0);
    const rowGross = Number(row.gross_revenue || 0);
    const rowNet = Number(row.net_revenue || 0);

    streams += rowStreams;
    downloads += rowDownloads;
    units += rowUnits;

    item.streams += rowStreams;
    item.downloads += rowDownloads;
    item.units += rowUnits;
    item.gross_revenue += rowGross;
    item.net_revenue += rowNet;
  }

  const byCurrency = Object.values(currencies).map(item => ({
    currency: item.currency,
    streams: item.streams,
    downloads: item.downloads,
    units: item.units,
    gross_revenue: roundSalesMoney(item.gross_revenue),
    net_revenue: roundSalesMoney(item.net_revenue)
  }));

  const currencyList = byCurrency.map(item => item.currency);

  let grossRevenue = null;
  let netRevenue = null;
  let currency = null;

  if (byCurrency.length === 1) {
    currency = byCurrency[0].currency;
    grossRevenue = byCurrency[0].gross_revenue;
    netRevenue = byCurrency[0].net_revenue;
  }

  return {
    streams,
    downloads,
    units,
    gross_revenue: grossRevenue,
    net_revenue: netRevenue,
    currency,
    currencies: currencyList,
    by_currency: byCurrency
  };
}

async function authenticateSalesRequest(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return {
      ok: false,
      response: json({
        success: false,
        error: "Authorization required"
      }, 401)
    };
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return {
      ok: false,
      response: json({
        success: false,
        error: "Invalid or expired token"
      }, 401)
    };
  }

  const userId = salesUserId(auth);

  if (!userId) {
    return {
      ok: false,
      response: json({
        success: false,
        error: "Unable to determine authenticated user"
      }, 401)
    };
  }

  return {
    ok: true,
    auth,
    userId
  };
}

async function resolveSalesTrack(env, userId, isrc) {
  const normalizedIsrc = decodeURIComponent(isrc)
    .replace(/-/g, "")
    .toUpperCase();

  return await env.DB.prepare(`
    SELECT
      t.id,
      t.release_id,
      t.title,
      t.version,
      t.isrc,
      t.track_number,
      t.disc_number,
      t.duration_seconds,
      t.genre,
      t.language,
      t.explicit,
      r.title AS release_title,
      r.release_type,
      r.release_date,
      a.name AS artist_name
    FROM tracks t
    JOIN releases r ON r.id = t.release_id
    LEFT JOIN artists a ON a.id = r.artist_id
    WHERE r.user_id = ?
      AND t.isrc = ?
    LIMIT 1
  `).bind(userId, normalizedIsrc).first();
}

async function resolveSalesRelease(env, userId, releaseId) {
  return await env.DB.prepare(`
    SELECT
      r.id,
      r.title,
      r.release_type,
      r.release_date,
      r.artist_id,
      a.name AS artist_name
    FROM releases r
    LEFT JOIN artists a ON a.id = r.artist_id
    WHERE r.user_id = ?
      AND r.id = ?
    LIMIT 1
  `).bind(userId, releaseId).first();
}

async function resolveSalesArtist(env, userId, artistRef) {
  const decoded = decodeURIComponent(artistRef);

  return await env.DB.prepare(`
    SELECT DISTINCT
      a.id,
      a.name
    FROM artists a
    JOIN releases r ON r.artist_id = a.id
    WHERE r.user_id = ?
      AND (
        a.id = ?
        OR a.name = ?
      )
    LIMIT 1
  `).bind(userId, decoded, decoded).first();
}

// ============================================================
// SALES IMPORT ENGINE
// ============================================================

const SALES_IMPORT_MAX_ROWS = 5000;

function generateSalesImportId() {
  return `import_${crypto.randomUUID()}`;
}

function generateSalesImportErrorId() {
  return `import_error_${crypto.randomUUID()}`;
}

function normalizeImportSource(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function validateImportSource(source) {
  if (!source) {
    return {
      valid: false,
      error: "source is required"
    };
  }

  if (source.length > 100) {
    return {
      valid: false,
      error: "source is too long"
    };
  }

  return {
    valid: true
  };
}

function validateImportReportId(value) {
  if (!value) {
    return {
      valid: false,
      error: "source_report_id is required"
    };
  }

  if (String(value).length > 255) {
    return {
      valid: false,
      error: "source_report_id is too long"
    };
  }

  return {
    valid: true
  };
}

function normalizeImportRows(body) {
  if (Array.isArray(body)) {
    return body;
  }

  if (Array.isArray(body.rows)) {
    return body.rows;
  }

  if (Array.isArray(body.events)) {
    return body.events;
  }

  return [];
}

function normalizeImportedSalesRow(row, rowNumber) {
  const streams = Number(row.streams || 0);
  const downloads = Number(row.downloads || 0);
  const units = Number(
    row.units !== undefined
      ? row.units
      : streams + downloads
  );

  const grossRevenue = Number(
    row.gross_revenue !== undefined
      ? row.gross_revenue
      : row.grossRevenue || 0
  );

  const netRevenue = Number(
    row.net_revenue !== undefined
      ? row.net_revenue
      : row.netRevenue !== undefined
        ? row.netRevenue
        : grossRevenue
  );

  const normalized = {
    release_id: row.release_id || null,
    track_id: row.track_id || null,
    isrc: row.isrc
      ? String(row.isrc)
          .replace(/-/g, "")
          .trim()
          .toUpperCase()
      : null,

    artist_id: row.artist_id || null,

    channel: row.channel
      ? String(row.channel).trim().toLowerCase()
      : null,

    territory: row.territory
      ? String(row.territory).trim().toUpperCase()
      : null,

    sale_type: row.sale_type
      ? String(row.sale_type).trim().toLowerCase()
      : "stream",

    event_date: row.event_date
      ? String(row.event_date).trim()
      : null,

    streams,
    downloads,
    units,

    gross_revenue: grossRevenue,
    net_revenue: netRevenue,

    currency: row.currency
      ? String(row.currency).trim().toUpperCase()
      : "USD",

    stream_rate:
      row.stream_rate !== undefined &&
      row.stream_rate !== null &&
      row.stream_rate !== ""
        ? Number(row.stream_rate)
        : null,

    source_record_id:
      row.source_record_id ||
      row.sourceRecordId ||
      null,

    metadata_json:
      row.metadata_json ||
      row.metadata ||
      null
  };

  return {
    row_number: rowNumber,
    data: normalized
  };
}

function validateImportedSalesRow(row) {
  const errors = [];

  if (!row.source_record_id) {
    errors.push({
      code: "MISSING_SOURCE_RECORD_ID",
      message: "source_record_id is required"
    });
  }

  if (!row.channel) {
    errors.push({
      code: "MISSING_CHANNEL",
      message: "channel is required"
    });
  }

  if (!row.territory) {
    errors.push({
      code: "MISSING_TERRITORY",
      message: "territory is required"
    });
  }

  if (!row.event_date) {
    errors.push({
      code: "MISSING_EVENT_DATE",
      message: "event_date is required"
    });
  } else if (!/^\d{4}-\d{2}-\d{2}$/.test(row.event_date)) {
    errors.push({
      code: "INVALID_DATE",
      message: "event_date must use YYYY-MM-DD format"
    });
  }

  if (
    row.isrc &&
    !/^[A-Z]{2}[A-Z0-9]{3}[0-9]{2}[0-9]{5}$/.test(row.isrc)
  ) {
    errors.push({
      code: "INVALID_ISRC",
      message: "Invalid ISRC format"
    });
  }

  if (!Number.isFinite(row.streams) || row.streams < 0) {
    errors.push({
      code: "INVALID_STREAMS",
      message: "streams must be a non-negative number"
    });
  }

  if (!Number.isFinite(row.downloads) || row.downloads < 0) {
    errors.push({
      code: "INVALID_DOWNLOADS",
      message: "downloads must be a non-negative number"
    });
  }

  if (!Number.isFinite(row.units) || row.units < 0) {
    errors.push({
      code: "INVALID_UNITS",
      message: "units must be a non-negative number"
    });
  }

  if (
    !Number.isFinite(row.gross_revenue) ||
    row.gross_revenue < 0
  ) {
    errors.push({
      code: "INVALID_GROSS_REVENUE",
      message: "gross_revenue must be a non-negative number"
    });
  }

  if (
    !Number.isFinite(row.net_revenue) ||
    row.net_revenue < 0
  ) {
    errors.push({
      code: "INVALID_NET_REVENUE",
      message: "net_revenue must be a non-negative number"
    });
  }

  if (!row.currency || !/^[A-Z]{3}$/.test(row.currency)) {
    errors.push({
      code: "INVALID_CURRENCY",
      message: "currency must be a 3-letter ISO-style code"
    });
  }

  if (
    row.stream_rate !== null &&
    (!Number.isFinite(row.stream_rate) ||
      row.stream_rate < 0)
  ) {
    errors.push({
      code: "INVALID_STREAM_RATE",
      message: "stream_rate must be a non-negative number"
    });
  }

  return errors;
}

async function findExistingSalesEvent(
  env,
  userId,
  source,
  sourceRecordId
) {
  if (!sourceRecordId) {
    return null;
  }

  return await env.DB.prepare(`
    SELECT
      id,
      aggregation_status,
      event_date,
      streams,
      gross_revenue,
      net_revenue
    FROM sales_events
    WHERE user_id = ?
      AND source = ?
      AND source_record_id = ?
    LIMIT 1
  `)
    .bind(
      userId,
      source,
      sourceRecordId
    )
    .first();
}

async function createSalesImportError(
  env,
  {
    importId,
    rowNumber,
    sourceRecordId,
    errorCode,
    errorMessage,
    rawData,
    retryCount = 0
  }
) {
  const id = generateSalesImportErrorId();

  await env.DB.prepare(`
    INSERT INTO sales_import_errors (
      id,
      import_id,
      row_number,
      source_record_id,
      status,
      error_code,
      error_message,
      raw_data_json,
      retry_count
    )
    VALUES (?, ?, ?, ?, 'failed', ?, ?, ?, ?)
  `)
    .bind(
      id,
      importId,
      rowNumber,
      sourceRecordId || null,
      errorCode,
      errorMessage,
      rawData
        ? JSON.stringify(rawData)
        : null,
      retryCount
    )
    .run();

  return id;
}

async function updateSalesImportStats(
  env,
  importId
) {
  const result = await env.DB.prepare(`
    SELECT
      COUNT(*) AS records,
      COALESCE(SUM(gross_revenue), 0) AS gross_revenue,
      COALESCE(SUM(net_revenue), 0) AS net_revenue,
      MIN(event_date) AS period_start,
      MAX(event_date) AS period_end,
      currency
    FROM sales_events
    WHERE user_id = (
      SELECT user_id
      FROM sales_imports
      WHERE id = ?
    )
      AND source = (
        SELECT source
        FROM sales_imports
        WHERE id = ?
      )
      AND source_report_id = (
        SELECT source_report_id
        FROM sales_imports
        WHERE id = ?
      )
  `)
    .bind(
      importId,
      importId,
      importId
    )
    .first();

  return result;
}

async function aggregateAnalyticsEvent(env, eventId) {
  const event = await env.DB.prepare(`
    SELECT *
    FROM analytics_events
    WHERE id = ?
    LIMIT 1
  `).bind(eventId).first();

  if (!event) {
    throw new Error("Analytics event not found");
  }

  // Check if event was already processed
  if (event.aggregation_status === "aggregated") {
    return {
      success: true,
      event_id: event.id,
      already_aggregated: true,
      message: "Analytics event was already aggregated"
    };
  }

  const streams = Number(event.streams || 0);
  const downloads = Number(event.downloads || 0);
  const revenue = Number(event.revenue_amount || 0);

  /*
   * ---------------------------------------------------------
   * 1. analytics_daily
   * ---------------------------------------------------------
   */
  const existingDaily = await env.DB.prepare(`
    SELECT id
    FROM analytics_daily
    WHERE user_id = ?
      AND event_date = ?
      AND platform = ?
      AND COALESCE(territory, '') = COALESCE(?, '')
      AND COALESCE(release_id, '') = COALESCE(?, '')
      AND COALESCE(track_id, '') = COALESCE(?, '')
    LIMIT 1
  `).bind(
    event.user_id,
    event.event_date,
    event.platform,
    event.territory || null,
    event.release_id || null,
    event.track_id || null
  ).first();

  if (existingDaily) {
    await env.DB.prepare(`
      UPDATE analytics_daily
      SET
        streams = streams + ?,
        downloads = downloads + ?,
        revenue_amount = revenue_amount + ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      streams,
      downloads,
      revenue,
      existingDaily.id
    ).run();
  } else {
    const dailyId = `daily_${crypto.randomUUID()}`;
    await env.DB.prepare(`
      INSERT INTO analytics_daily (
        id,
        user_id,
        release_id,
        track_id,
        platform,
        territory,
        event_date,
        streams,
        downloads,
        revenue_amount,
        currency
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      dailyId,
      event.user_id,
      event.release_id || null,
      event.track_id || null,
      event.platform,
      event.territory || null,
      event.event_date,
      streams,
      downloads,
      revenue,
      event.currency || "USD"
    ).run();
  }

  /*
   * ---------------------------------------------------------
   * 2. analytics_tracks
   * ---------------------------------------------------------
   */
  if (event.track_id) {
    const existingTrack = await env.DB.prepare(`
      SELECT id
      FROM analytics_tracks
      WHERE user_id = ?
        AND track_id = ?
      LIMIT 1
    `).bind(
      event.user_id,
      event.track_id
    ).first();

    if (existingTrack) {
      await env.DB.prepare(`
        UPDATE analytics_tracks
        SET
          total_streams = total_streams + ?,
          total_downloads = total_downloads + ?,
          total_revenue = total_revenue + ?,
          last_stream_date = CASE
            WHEN last_stream_date IS NULL
              OR last_stream_date < ?
            THEN ?
            ELSE last_stream_date
          END,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        streams,
        downloads,
        revenue,
        event.event_date,
        event.event_date,
        existingTrack.id
      ).run();
    } else {
      const trackId = `analytics_track_${crypto.randomUUID()}`;
      const track = await env.DB.prepare(`
        SELECT id, release_id, isrc
        FROM tracks
        WHERE id = ?
        LIMIT 1
      `).bind(event.track_id).first();

      await env.DB.prepare(`
        INSERT INTO analytics_tracks (
          id,
          user_id,
          track_id,
          release_id,
          isrc,
          total_streams,
          total_downloads,
          total_revenue,
          currency,
          last_stream_date
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        trackId,
        event.user_id,
        event.track_id,
        event.release_id || track?.release_id || null,
        track?.isrc || null,
        streams,
        downloads,
        revenue,
        event.currency || "USD",
        event.event_date
      ).run();
    }
  }

  /*
   * ---------------------------------------------------------
   * 3. analytics_platforms
   * ---------------------------------------------------------
   */
  const existingPlatform = await env.DB.prepare(`
    SELECT id
    FROM analytics_platforms
    WHERE user_id = ?
      AND platform = ?
    LIMIT 1
  `).bind(
    event.user_id,
    event.platform
  ).first();

  if (existingPlatform) {
    await env.DB.prepare(`
      UPDATE analytics_platforms
      SET
        total_streams = total_streams + ?,
        total_downloads = total_downloads + ?,
        total_revenue = total_revenue + ?,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      streams,
      downloads,
      revenue,
      existingPlatform.id
    ).run();
  } else {
    const platformId = `analytics_platform_${crypto.randomUUID()}`;
    await env.DB.prepare(`
      INSERT INTO analytics_platforms (
        id,
        user_id,
        platform,
        total_streams,
        total_downloads,
        total_revenue,
        currency
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      platformId,
      event.user_id,
      event.platform,
      streams,
      downloads,
      revenue,
      event.currency || "USD"
    ).run();
  }

  /*
   * ---------------------------------------------------------
   * 4. analytics_territories
   * ---------------------------------------------------------
   */
  if (event.territory) {
    const existingTerritory = await env.DB.prepare(`
      SELECT id
      FROM analytics_territories
      WHERE user_id = ?
        AND territory = ?
      LIMIT 1
    `).bind(
      event.user_id,
      event.territory
    ).first();

    if (existingTerritory) {
      await env.DB.prepare(`
        UPDATE analytics_territories
        SET
          total_streams = total_streams + ?,
          total_downloads = total_downloads + ?,
          total_revenue = total_revenue + ?,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        streams,
        downloads,
        revenue,
        existingTerritory.id
      ).run();
    } else {
      const territoryId = `analytics_territory_${crypto.randomUUID()}`;
      await env.DB.prepare(`
        INSERT INTO analytics_territories (
          id,
          user_id,
          territory,
          total_streams,
          total_downloads,
          total_revenue,
          currency
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        territoryId,
        event.user_id,
        event.territory,
        streams,
        downloads,
        revenue,
        event.currency || "USD"
      ).run();
    }
  }

  // Update status to aggregated after successful execution
  await env.DB.prepare(`
    UPDATE analytics_events
    SET
      aggregation_status = 'aggregated',
      aggregated_at = CURRENT_TIMESTAMP
    WHERE id = ?
      AND aggregation_status = 'pending'
  `).bind(event.id).run();

  return {
    success: true,
    event_id: event.id,
    aggregated: {
      daily: true,
      track: Boolean(event.track_id),
      platform: true,
      territory: Boolean(event.territory)
    }
  };
}

async function updateDeliveryParentStatus(env, submissionId, releaseId) {
  const jobsResult = await env.DB.prepare(`
    SELECT status, COUNT(*) AS count
    FROM delivery_jobs
    WHERE submission_id = ?
    GROUP BY status
  `)
    .bind(submissionId)
    .all();

  const counts = {
    pending: 0,
    delivering: 0,
    delivered: 0,
    failed: 0
  };

  for (const row of jobsResult.results || []) {
    if (counts[row.status] !== undefined) {
      counts[row.status] = Number(row.count);
    }
  }

  const total =
    counts.pending +
    counts.delivering +
    counts.delivered +
    counts.failed;

  let parentStatus = "delivering";

  // Any failed delivery means the overall delivery has failed
  if (total > 0 && counts.failed > 0) {
    parentStatus = "failed";
  }

  // Only when ALL delivery jobs are delivered
  else if (total > 0 && counts.delivered === total) {
    parentStatus = "delivered";
  }

  await env.DB.prepare(`
    UPDATE release_submissions
    SET
      status = ?,
      updated_at = CURRENT_TIMESTAMP,
      completed_at = CASE
        WHEN ? IN ('delivered', 'failed')
        THEN CURRENT_TIMESTAMP
        ELSE completed_at
      END
    WHERE id = ?
  `)
    .bind(
      parentStatus,
      parentStatus,
      submissionId
    )
    .run();

  await env.DB.prepare(`
    UPDATE releases
    SET
      status = ?,
      updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `)
    .bind(
      parentStatus,
      releaseId
    )
    .run();

  return {
    status: parentStatus,
    counts,
    total
  };
}

async function sandboxDeliveryAdapter({ job, package: distributionPackage, metadata, env }) {
  // Sandbox-only delivery simulation.
  // This does NOT contact Spotify, Apple Music, YouTube, or any other DSP.

  const externalId =
    `sandbox_${job.platform}_${crypto.randomUUID()}`;

  return {
    success: true,
    external_id: externalId,
    platform: job.platform,
    mode: "sandbox",
    message: "Sandbox delivery simulated successfully"
  };
}


function getDeliveryAdapter(platform, mode) {
  // Sandbox adapters
  if (mode === "sandbox") {
    const sandboxAdapters = {
      spotify: sandboxDeliveryAdapter,
      apple_music: sandboxDeliveryAdapter,
      youtube_music: sandboxDeliveryAdapter,
      amazon_music: sandboxDeliveryAdapter,
      deezer: sandboxDeliveryAdapter,
      tiktok_music: sandboxDeliveryAdapter
    };

    return sandboxAdapters[platform] || null;
  }

  // Production adapters will be added here later.
  const productionAdapters = {
    spotify: null,
    apple_music: null,
    youtube_music: null,
    amazon_music: null,
    deezer: null,
    tiktok_music: null
  };

  return productionAdapters[platform] || null;
}

function isValidPlatform(platform) {
  return [
    "spotify",
    "apple_music",
    "youtube_music",
    "amazon_music",
    "deezer",
    "tiktok_music"
  ].includes(platform);
}

function isValidIntegrationMode(mode) {
  return ["sandbox", "production"].includes(mode);
}

async function getPlatformIntegration(env, platform) {
  const integration = await env.DB.prepare(`
    SELECT
      id,
      platform,
      enabled,
      mode,
      adapter_version,
      created_at,
      updated_at
    FROM platform_integrations
    WHERE platform = ?
    LIMIT 1
  `)
    .bind(platform)
    .first();

  return integration || null;
}

// -------------------------
// Main Worker
// -------------------------

export default {
  async fetch(request, env) {

    const url = new URL(request.url);

    // OPTIONS
    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: corsHeaders
      });
    }

    // -------------------------
    // HOME
    // -------------------------

    if (
      url.pathname === "/" &&
      request.method === "GET"
    ) {
      return json({
        name: "Audiory API",
        version: "1.0.0",
        status: "online"
      });
    }

    // -------------------------
    // HEALTH
    // -------------------------

    if (
      url.pathname === "/v1/health" &&
      request.method === "GET"
    ) {
      return json({
        status: "ok",
        service: "Audiory API",
        version: "1.0.0"
      });
    }

    // -------------------------
    // DATABASE TEST
    // -------------------------

    if (
      url.pathname === "/v1/database" &&
      request.method === "GET"
    ) {
      const result = await env.DB
        .prepare("SELECT 1 AS connected")
        .first();

      return json({
        database: "Audiory D1",
        status: "connected",
        result
      });
    }

    // -------------------------
    // REGISTER
    // -------------------------

    if (
      url.pathname === "/v1/auth/register" &&
      request.method === "POST"
    ) {

      try {

        const body = await request.json();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");

        const role =
          body.role === "label"
            ? "label"
            : "artist";

        if (!email || !password) {
          return json({
            success: false,
            error: "Email and password are required"
          }, 400);
        }

        if (password.length < 8) {
          return json({
            success: false,
            error: "Password must be at least 8 characters"
          }, 400);
        }

        // Check existing account

        const existing = await env.DB
          .prepare(
            "SELECT id FROM users WHERE email = ?"
          )
          .bind(email)
          .first();

        if (existing) {
          return json({
            success: false,
            error: "An account with this email already exists"
          }, 409);
        }

        const userId =
          generateId("user");

        const passwordHash =
          await hashPassword(password);

        await env.DB
          .prepare(`
            INSERT INTO users (
              id,
              email,
              password_hash,
              role
            )
            VALUES (?, ?, ?, ?)
          `)
          .bind(
            userId,
            email,
            passwordHash,
            role
          )
          .run();

        return json({
          success: true,
          message: "Account created successfully",
          user: {
            id: userId,
            email,
            role
          }
        }, 201);

      } catch (error) {

        return json({
          success: false,
          error: "Unable to create account"
        }, 500);
      }
    }

    // -------------------------
    // LOGIN
    // -------------------------

    if (
      url.pathname === "/v1/auth/login" &&
      request.method === "POST"
    ) {

      try {

        const body = await request.json();

        const email =
          String(body.email || "")
            .trim()
            .toLowerCase();

        const password =
          String(body.password || "");

        if (!email || !password) {
          return json({
            success: false,
            error: "Email and password are required"
          }, 400);
        }

        const user = await env.DB
          .prepare(`
            SELECT
              id,
              email,
              password_hash,
              role
            FROM users
            WHERE email = ?
          `)
          .bind(email)
          .first();

        if (!user) {
          return json({
            success: false,
            error: "Invalid email or password"
          }, 401);
        }

        const valid =
          await verifyPassword(
            password,
            user.password_hash
          );

        if (!valid) {
          return json({
            success: false,
            error: "Invalid email or password"
          }, 401);
        }

        const token =
          await createToken(
            user,
            env.JWT_SECRET
          );

        return json({
          success: true,
          token,
          token_type: "Bearer",
          expires_in: 86400,
          user: {
            id: user.id,
            email: user.email,
            role: user.role
          }
        });

      } catch (error) {

        return json({
          success: false,
          error: "Unable to login"
        }, 500);
      }
    }

    // -------------------------
    // GET CURRENT USER
    // -------------------------

    if (
      url.pathname === "/v1/auth/me" &&
      request.method === "GET"
    ) {

      const authorization =
        request.headers.get("Authorization");

      if (!authorization) {
        return json({
          success: false,
          error: "Authorization required"
        }, 401);
      }

      const token =
        authorization.replace(
          "Bearer ",
          ""
        );

      const payload =
        await verifyToken(
          token,
          env.JWT_SECRET
        );

      if (!payload) {
        return json({
          success: false,
          error: "Invalid or expired token"
        }, 401);
      }

      return json({
        success: true,
        user: {
          id: payload.sub,
          email: payload.email,
          role: payload.role
        }
      });
    }

    // -------------------------
    // GET ARTISTS
    // -------------------------

    if (
      url.pathname === "/v1/artists" &&
      request.method === "GET"
    ) {

      const { results } =
        await env.DB
          .prepare(`
            SELECT
              id,
              user_id,
              name,
              bio,
              country,
              created_at
            FROM artists
            ORDER BY created_at DESC
          `)
          .all();

      return json({
        success: true,
        artists: results
      });
    }

    // -------------------------
    // CREATE ARTIST
    // -------------------------

    if (
      url.pathname === "/v1/artists" &&
      request.method === "POST"
    ) {
      try {
        // Get Authorization header
        const authorization =
          request.headers.get("Authorization");

        if (!authorization) {
          return json({
            success: false,
            error: "Authorization required"
          }, 401);
        }

        // Make sure it's a Bearer token
        if (!authorization.startsWith("Bearer ")) {
          return json({
            success: false,
            error: "Invalid authorization format"
          }, 401);
        }

        const token =
          authorization.substring(7);

        // Verify JWT
        const user =
          await verifyToken(
            token,
            env.JWT_SECRET
          );

        if (!user) {
          return json({
            success: false,
            error: "Invalid or expired token"
          }, 401);
        }

        // Read request body
        const body =
          await request.json();

        const name =
          String(body.name || "").trim();

        const bio =
          body.bio
            ? String(body.bio).trim()
            : null;

        const country =
          body.country
            ? String(body.country).trim()
            : null;

        // Validate artist name
        if (!name) {
          return json({
            success: false,
            error: "Artist name is required"
          }, 400);
        }

        // Generate artist ID
        const artistId =
          generateId("artist");

        // Create artist using
        // authenticated user's ID
        await env.DB
          .prepare(`
            INSERT INTO artists (
              id,
              user_id,
              name,
              bio,
              country
            )
            VALUES (?, ?, ?, ?, ?)
          `)
          .bind(
            artistId,
            user.sub,
            name,
            bio,
            country
          )
          .run();

        return json({
          success: true,
          message: "Artist created successfully",
          artist: {
            id: artistId,
            user_id: user.sub,
            name,
            bio,
            country
          }
        }, 201);

      } catch (error) {

        return json({
          success: false,
          error: "Unable to create artist"
        }, 500);

      }
    }

    // -------------------------
    // CREATE RELEASE
    // -------------------------

    if (
      url.pathname === "/v1/releases" &&
      request.method === "POST"
    ) {
      try {
        // -------------------------
        // Authentication
        // -------------------------

        const authorization =
          request.headers.get("Authorization");

        if (!authorization) {
          return json({
            success: false,
            error: "Authorization required"
          }, 401);
        }

        if (!authorization.startsWith("Bearer ")) {
          return json({
            success: false,
            error: "Invalid authorization format"
          }, 401);
        }

        const token =
          authorization.substring(7);

        const user =
          await verifyToken(
            token,
            env.JWT_SECRET
          );

        if (!user) {
          return json({
            success: false,
            error: "Invalid or expired token"
          }, 401);
        }

        // -------------------------
        // Read request body
        // -------------------------

        const body =
          await request.json();

        const artistId =
          String(body.artist_id || "").trim();

        const title =
          String(body.title || "").trim();

        const releaseType =
          String(body.release_type || "single")
            .trim()
            .toLowerCase();

        const version =
          body.version
            ? String(body.version).trim()
            : null;

        const genre =
          body.genre
            ? String(body.genre).trim()
            : null;

        const subgenre =
          body.subgenre
            ? String(body.subgenre).trim()
            : null;

        const language =
          body.language
            ? String(body.language).trim()
            : null;

        const releaseDate =
          body.release_date
            ? String(body.release_date).trim()
            : null;

        const originalReleaseDate =
          body.original_release_date
            ? String(body.original_release_date).trim()
            : null;

        const upc =
          body.upc
            ? String(body.upc).trim()
            : null;

        const copyrightLine =
          body.copyright_line
            ? String(body.copyright_line).trim()
            : null;

        const phonographicCopyrightLine =
          body.phonographic_copyright_line
            ? String(body.phonographic_copyright_line).trim()
            : null;

        const labelName =
          body.label_name
            ? String(body.label_name).trim()
            : null;

        const explicit =
          body.explicit === true ? 1 : 0;

        // -------------------------
        // Validation
        // -------------------------

        if (!artistId) {
          return json({
            success: false,
            error: "artist_id is required"
          }, 400);
        }

        if (!title) {
          return json({
            success: false,
            error: "Release title is required"
          }, 400);
        }

        const allowedReleaseTypes = [
          "single",
          "ep",
          "album"
        ];

        if (!allowedReleaseTypes.includes(releaseType)) {
          return json({
            success: false,
            error: "release_type must be single, ep, or album"
          }, 400);
        }

        // -------------------------
        // Verify artist ownership
        // -------------------------

        const artist =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id,
                name
              FROM artists
              WHERE id = ?
            `)
            .bind(artistId)
            .first();

        if (!artist) {
          return json({
            success: false,
            error: "Artist not found"
          }, 404);
        }

        if (artist.user_id !== user.sub) {
          return json({
            success: false,
            error: "You do not have permission to create a release for this artist"
          }, 403);
        }

        // -------------------------
        // Generate release ID
        // -------------------------

        const releaseId =
          generateId("release");

        // -------------------------
        // Create release
        // -------------------------

        await env.DB
          .prepare(`
            INSERT INTO releases (
              id,
              user_id,
              artist_id,
              title,
              release_type,
              version,
              genre,
              subgenre,
              language,
              release_date,
              original_release_date,
              upc,
              copyright_line,
              phonographic_copyright_line,
              label_name,
              explicit,
              status
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            releaseId,
            user.sub,
            artistId,
            title,
            releaseType,
            version,
            genre,
            subgenre,
            language,
            releaseDate,
            originalReleaseDate,
            upc,
            copyrightLine,
            phonographicCopyrightLine,
            labelName,
            explicit,
            "draft"
          )
          .run();

        // -------------------------
        // Response
        // -------------------------

        return json({
          success: true,
          message: "Release created successfully",
          release: {
            id: releaseId,
            user_id: user.sub,
            artist_id: artistId,
            artist_name: artist.name,
            title,
            release_type: releaseType,
            version,
            genre,
            subgenre,
            language,
            release_date: releaseDate,
            original_release_date: originalReleaseDate,
            upc,
            copyright_line: copyrightLine,
            phonographic_copyright_line:
              phonographicCopyrightLine,
            label_name: labelName,
            explicit: Boolean(explicit),
            status: "draft"
          }
        }, 201);

      } catch (error) {

        return json({
          success: false,
          error: "Unable to create release"
        }, 500);
      }
    }

    // -------------------------
    // CREATE TRACK
    // POST /v1/releases/:release_id/tracks
    // -------------------------

    if (
      request.method === "POST" &&
      url.pathname.match(/^\/v1\/releases\/[^/]+\/tracks$/)
    ) {
      try {
        // -------------------------
        // Authentication
        // -------------------------

        const authorization =
          request.headers.get("Authorization");

        if (!authorization) {
          return json({
            success: false,
            error: "Authorization required"
          }, 401);
        }

        if (!authorization.startsWith("Bearer ")) {
          return json({
            success: false,
            error: "Invalid authorization format"
          }, 401);
        }

        const token =
          authorization.substring(7);

        const user =
          await verifyToken(
            token,
            env.JWT_SECRET
          );

        if (!user) {
          return json({
            success: false,
            error: "Invalid or expired token"
          }, 401);
        }

        // -------------------------
        // Get release ID
        // -------------------------

        const releaseId =
          url.pathname.split("/")[3];

        if (!releaseId) {
          return json({
            success: false,
            error: "Release ID is required"
          }, 400);
        }

        // -------------------------
        // Find release
        // -------------------------

        const release =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id,
                artist_id,
                title,
                release_type,
                status
              FROM releases
              WHERE id = ?
            `)
            .bind(releaseId)
            .first();

        if (!release) {
          return json({
            success: false,
            error: "Release not found"
          }, 404);
        }

        // -------------------------
        // Verify ownership
        // -------------------------

        if (release.user_id !== user.sub) {
          return json({
            success: false,
            error: "You do not have permission to modify this release"
          }, 403);
        }

        // -------------------------
        // Read request body
        // -------------------------

        const body =
          await request.json();

        const title =
          String(body.title || "").trim();

        const version =
          body.version
            ? String(body.version).trim()
            : null;

        const isrc =
          body.isrc
            ? String(body.isrc).trim().toUpperCase()
            : null;

        const trackNumber =
          Number(body.track_number);

        const discNumber =
          body.disc_number !== undefined
            ? Number(body.disc_number)
            : 1;

        const durationSeconds =
          body.duration_seconds !== undefined
            ? Number(body.duration_seconds)
            : null;

        const genre =
          body.genre
            ? String(body.genre).trim()
            : null;

        const language =
          body.language
            ? String(body.language).trim()
            : null;

        const explicit =
          body.explicit === true ? 1 : 0;

        const lyrics =
          body.lyrics
            ? String(body.lyrics)
            : null;

        // -------------------------
        // Validate title
        // -------------------------

        if (!title) {
          return json({
            success: false,
            error: "Track title is required"
          }, 400);
        }

        // -------------------------
        // Validate track number
        // -------------------------

        if (
          !Number.isInteger(trackNumber) ||
          trackNumber < 1
        ) {
          return json({
            success: false,
            error: "track_number must be a positive integer"
          }, 400);
        }

        // -------------------------
        // Validate disc number
        // -------------------------

        if (
          !Number.isInteger(discNumber) ||
          discNumber < 1
        ) {
          return json({
            success: false,
            error: "disc_number must be a positive integer"
          }, 400);
        }

        // -------------------------
        // Validate duration
        // -------------------------

        if (
          durationSeconds !== null &&
          (
            !Number.isInteger(durationSeconds) ||
            durationSeconds < 0
          )
        ) {
          return json({
            success: false,
            error: "duration_seconds must be a non-negative integer"
          }, 400);
        }

        // -------------------------
        // Check duplicate track
        // -------------------------

        const existingTrack =
          await env.DB
            .prepare(`
              SELECT id
              FROM tracks
              WHERE release_id = ?
                AND track_number = ?
                AND disc_number = ?
            `)
            .bind(
              releaseId,
              trackNumber,
              discNumber
            )
            .first();

        if (existingTrack) {
          return json({
            success: false,
            error: "A track with this track number already exists on this release"
          }, 409);
        }

        // -------------------------
        // Validate ISRC format
        // -------------------------

        if (isrc) {
          const isrcPattern =
            /^[A-Z]{2}[A-Z0-9]{3}\d{7}$/;

          if (!isrcPattern.test(isrc)) {
            return json({
              success: false,
              error: "Invalid ISRC format"
            }, 400);
          }
        }

        // -------------------------
        // Generate track ID
        // -------------------------

        const trackId =
          generateId("track");

        // -------------------------
        // Create track
        // -------------------------

        await env.DB
          .prepare(`
            INSERT INTO tracks (
              id,
              release_id,
              title,
              version,
              isrc,
              track_number,
              disc_number,
              duration_seconds,
              genre,
              language,
              explicit,
              lyrics
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
          .bind(
            trackId,
            releaseId,
            title,
            version,
            isrc,
            trackNumber,
            discNumber,
            durationSeconds,
            genre,
            language,
            explicit,
            lyrics
          )
          .run();

        // -------------------------
        // Return created track
        // -------------------------

        return json({
          success: true,
          message: "Track created successfully",
          track: {
            id: trackId,
            release_id: releaseId,
            title,
            version,
            isrc,
            track_number: trackNumber,
            disc_number: discNumber,
            duration_seconds: durationSeconds,
            genre,
            language,
            explicit: Boolean(explicit),
            lyrics,
            audio_asset_id: null
          }
        }, 201);

      } catch (error) {

        console.error(error);

        return json({
          success: false,
          error: "Unable to create track"
        }, 500);
      }
    }

    // -------------------------
// UPLOAD AUDIO
// POST /v1/uploads/audio
// -------------------------

if (
  request.method === "POST" &&
  url.pathname === "/v1/uploads/audio"
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token =
      authorization.substring(7);

    const user =
      await verifyToken(
        token,
        env.JWT_SECRET
      );

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get track ID
    // -------------------------

    const trackId =
      url.searchParams.get("track_id");

    if (!trackId) {
      return json({
        success: false,
        error: "track_id is required"
      }, 400);
    }

    // -------------------------
    // Find track + release
    // -------------------------

    const track =
      await env.DB
        .prepare(`
          SELECT
            tracks.id,
            tracks.release_id,
            tracks.title,
            releases.user_id,
            releases.title AS release_title
          FROM tracks
          INNER JOIN releases
            ON tracks.release_id = releases.id
          WHERE tracks.id = ?
        `)
        .bind(trackId)
        .first();

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    // -------------------------
    // Verify ownership
    // -------------------------

    if (track.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to upload audio for this track"
      }, 403);
    }

    // -------------------------
    // Validate content type
    // -------------------------

    const contentType =
      request.headers.get("Content-Type") || "";

    const allowedTypes = [
      "audio/wav",
      "audio/x-wav",
      "audio/wave",
      "audio/flac",
      "audio/mpeg",
      "audio/mp4",
      "audio/aac",
      "audio/x-m4a"
    ];

    if (!allowedTypes.includes(contentType)) {
      return json({
        success: false,
        error: "Unsupported audio format",
        allowed_formats: [
          "WAV",
          "FLAC",
          "MP3",
          "M4A",
          "AAC"
        ]
      }, 400);
    }

    // -------------------------
    // Validate file size
    // -------------------------

    const contentLength =
      request.headers.get("Content-Length");

    const sizeBytes =
      Number(contentLength);

    if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
      return json({
        success: false,
        error: "Content-Length header is required"
      }, 400);
    }

    // 500 MB maximum for now
    const maxSize =
      500 * 1024 * 1024;

    if (sizeBytes > maxSize) {
      return json({
        success: false,
        error: "Audio file is too large. Maximum size is 500 MB"
      }, 413);
    }

    // -------------------------
    // Generate asset ID
    // -------------------------

    const assetId =
      generateId("asset");

    // -------------------------
    // Determine extension
    // -------------------------

    let extension = "audio";

    if (
      contentType === "audio/wav" ||
      contentType === "audio/x-wav" ||
      contentType === "audio/wave"
    ) {
      extension = "wav";
    } else if (contentType === "audio/flac") {
      extension = "flac";
    } else if (contentType === "audio/mpeg") {
      extension = "mp3";
    } else if (
      contentType === "audio/mp4" ||
      contentType === "audio/x-m4a"
    ) {
      extension = "m4a";
    } else if (contentType === "audio/aac") {
      extension = "aac";
    }

    // -------------------------
    // Generate R2 key
    // -------------------------

    const r2Key =
      `audio/${user.sub}/${track.release_id}/${trackId}/${assetId}.${extension}`;

    // -------------------------
    // Upload to R2
    // -------------------------

    await env.MEDIA.put(
      r2Key,
      request.body,
      {
        httpMetadata: {
          contentType
        },

        customMetadata: {
          asset_id: assetId,
          user_id: user.sub,
          release_id: track.release_id,
          track_id: trackId
        }
      }
    );

    // -------------------------
    // Create D1 asset record
    // -------------------------

    await env.DB
      .prepare(`
        INSERT INTO assets (
          id,
          user_id,
          release_id,
          track_id,
          type,
          filename,
          content_type,
          size_bytes,
          r2_key,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        assetId,
        user.sub,
        track.release_id,
        trackId,
        "audio",
        track.title,
        contentType,
        sizeBytes,
        r2Key,
        "uploaded"
      )
      .run();

    // -------------------------
    // Connect asset to track
    // -------------------------

    await env.DB
      .prepare(`
        UPDATE tracks
        SET audio_asset_id = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        assetId,
        trackId
      )
      .run();

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,
      message: "Audio uploaded successfully",

      asset: {
        id: assetId,
        type: "audio",
        track_id: trackId,
        release_id: track.release_id,
        filename: track.title,
        content_type: contentType,
        size_bytes: sizeBytes,
        r2_key: r2Key,
        status: "uploaded"
      }
    }, 201);

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to upload audio"
    }, 500);
  }
}

// -------------------------
// UPLOAD ARTWORK
// POST /v1/uploads/artwork?release_id=...
// -------------------------

if (
  request.method === "POST" &&
  url.pathname === "/v1/uploads/artwork"
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token =
      authorization.substring(7);

    const user =
      await verifyToken(
        token,
        env.JWT_SECRET
      );

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get release ID
    // -------------------------

    const releaseId =
      url.searchParams.get("release_id");

    if (!releaseId) {
      return json({
        success: false,
        error: "release_id is required"
      }, 400);
    }

    // -------------------------
    // Find release
    // -------------------------

    const release =
      await env.DB
        .prepare(`
          SELECT
            id,
            user_id,
            title,
            artwork_asset_id
          FROM releases
          WHERE id = ?
        `)
        .bind(releaseId)
        .first();

    if (!release) {
      return json({
        success: false,
        error: "Release not found"
      }, 404);
    }

    // -------------------------
    // Verify ownership
    // -------------------------

    if (release.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to upload artwork for this release"
      }, 403);
    }

    // -------------------------
    // Validate content type
    // -------------------------

    const contentType =
      request.headers.get("Content-Type") || "";

    const allowedTypes = [
      "image/jpeg",
      "image/png",
      "image/webp"
    ];

    if (!allowedTypes.includes(contentType)) {
      return json({
        success: false,
        error: "Unsupported artwork format",
        allowed_formats: [
          "JPEG",
          "PNG",
          "WebP"
        ]
      }, 400);
    }

    // -------------------------
    // Validate file size
    // -------------------------

    const contentLength =
      request.headers.get("Content-Length");

    const sizeBytes =
      Number(contentLength);

    if (!Number.isFinite(sizeBytes) || sizeBytes <= 0) {
      return json({
        success: false,
        error: "Content-Length header is required"
      }, 400);
    }

    // 20 MB maximum
    const maxSize =
      20 * 1024 * 1024;

    if (sizeBytes > maxSize) {
      return json({
        success: false,
        error: "Artwork file is too large. Maximum size is 20 MB"
      }, 413);
    }

    // -------------------------
    // Generate asset ID
    // -------------------------

    const assetId =
      generateId("asset");

    // -------------------------
    // Determine extension
    // -------------------------

    let extension = "jpg";

    if (contentType === "image/png") {
      extension = "png";
    }

    if (contentType === "image/webp") {
      extension = "webp";
    }

    // -------------------------
    // Generate R2 key
    // -------------------------

    const r2Key =
      `artwork/${user.sub}/${releaseId}/${assetId}.${extension}`;

    // -------------------------
    // Upload to R2
    // -------------------------

    await env.MEDIA.put(
      r2Key,
      request.body,
      {
        httpMetadata: {
          contentType
        },

        customMetadata: {
          asset_id: assetId,
          user_id: user.sub,
          release_id: releaseId,
          type: "artwork"
        }
      }
    );

    // -------------------------
    // Create asset record
    // -------------------------

    await env.DB
      .prepare(`
        INSERT INTO assets (
          id,
          user_id,
          release_id,
          track_id,
          type,
          filename,
          content_type,
          size_bytes,
          r2_key,
          status
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `)
      .bind(
        assetId,
        user.sub,
        releaseId,
        null,
        "artwork",
        `${release.title} artwork`,
        contentType,
        sizeBytes,
        r2Key,
        "uploaded"
      )
      .run();

    // -------------------------
    // Connect artwork to release
    // -------------------------

    await env.DB
      .prepare(`
        UPDATE releases
        SET artwork_asset_id = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        assetId,
        releaseId
      )
      .run();

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,
      message: "Artwork uploaded successfully",

      asset: {
        id: assetId,
        type: "artwork",
        release_id: releaseId,
        filename: `${release.title} artwork`,
        content_type: contentType,
        size_bytes: sizeBytes,
        r2_key: r2Key,
        status: "uploaded"
      }
    }, 201);

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to upload artwork"
    }, 500);
  }
}

// -------------------------
// GET RELEASE
// GET /v1/releases/:release_id
// -------------------------

if (
  request.method === "GET" &&
  url.pathname.match(/^\/v1\/releases\/[^/]+$/)
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token =
      authorization.substring(7);

    const user =
      await verifyToken(
        token,
        env.JWT_SECRET
      );

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get release ID
    // -------------------------

    const releaseId =
      url.pathname.split("/")[3];

    if (!releaseId) {
      return json({
        success: false,
        error: "Release ID is required"
      }, 400);
    }

    // -------------------------
    // Get release
    // -------------------------

    const release =
      await env.DB
        .prepare(`
          SELECT
            releases.id,
            releases.user_id,
            releases.artist_id,
            releases.title,
            releases.release_type,
            releases.version,
            releases.genre,
            releases.subgenre,
            releases.language,
            releases.release_date,
            releases.original_release_date,
            releases.upc,
            releases.copyright_line,
            releases.phonographic_copyright_line,
            releases.label_name,
            releases.artwork_asset_id,
            releases.explicit,
            releases.status,
            releases.created_at,
            releases.updated_at,

            artists.name AS artist_name,
            artists.bio AS artist_bio,
            artists.country AS artist_country

          FROM releases

          INNER JOIN artists
            ON releases.artist_id = artists.id

          WHERE releases.id = ?
        `)
        .bind(releaseId)
        .first();

    if (!release) {
      return json({
        success: false,
        error: "Release not found"
      }, 404);
    }

    // -------------------------
    // Verify ownership
    // -------------------------

    if (release.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to view this release"
      }, 403);
    }

    // -------------------------
    // Get tracks
    // -------------------------

    const tracksResult =
      await env.DB
        .prepare(`
          SELECT
            id,
            release_id,
            title,
            version,
            isrc,
            track_number,
            disc_number,
            duration_seconds,
            genre,
            language,
            explicit,
            lyrics,
            audio_asset_id,
            created_at,
            updated_at

          FROM tracks

          WHERE release_id = ?

          ORDER BY
            disc_number ASC,
            track_number ASC
        `)
        .bind(releaseId)
        .all();

    // -------------------------
    // Get artwork asset
    // -------------------------

    let artwork = null;

    if (release.artwork_asset_id) {

      artwork =
        await env.DB
          .prepare(`
            SELECT
              id,
              type,
              filename,
              content_type,
              size_bytes,
              r2_key,
              status,
              created_at

            FROM assets

            WHERE id = ?
              AND user_id = ?
          `)
          .bind(
            release.artwork_asset_id,
            user.sub
          )
          .first();
    }

    // -------------------------
    // Get audio assets
    // -------------------------

    const tracks =
      await Promise.all(
        (tracksResult.results || []).map(
          async (track) => {

            let audio = null;

            if (track.audio_asset_id) {

              audio =
                await env.DB
                  .prepare(`
                    SELECT
                      id,
                      type,
                      filename,
                      content_type,
                      size_bytes,
                      r2_key,
                      status,
                      created_at

                    FROM assets

                    WHERE id = ?
                      AND user_id = ?
                  `)
                  .bind(
                    track.audio_asset_id,
                    user.sub
                  )
                  .first();
            }

            return {
              ...track,
              explicit: Boolean(track.explicit),
              audio_asset: audio
            };
          }
        )
      );

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,

      release: {
        id: release.id,
        user_id: release.user_id,
        artist_id: release.artist_id,

        artist: {
          id: release.artist_id,
          name: release.artist_name,
          bio: release.artist_bio,
          country: release.artist_country
        },

        title: release.title,
        release_type: release.release_type,
        version: release.version,

        genre: release.genre,
        subgenre: release.subgenre,
        language: release.language,

        release_date: release.release_date,
        original_release_date:
          release.original_release_date,

        upc: release.upc,

        copyright_line:
          release.copyright_line,

        phonographic_copyright_line:
          release.phonographic_copyright_line,

        label_name:
          release.label_name,

        explicit:
          Boolean(release.explicit),

        status:
          release.status,

        artwork_asset:
          artwork,

        tracks,

        created_at:
          release.created_at,

        updated_at:
          release.updated_at
      }
    });

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to retrieve release"
    }, 500);
  }
}

// -------------------------
// GET RELEASE TRACKS
// GET /v1/releases/:release_id/tracks
// -------------------------

if (
  request.method === "GET" &&
  url.pathname.match(/^\/v1\/releases\/[^/]+\/tracks$/)
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token =
      authorization.substring(7);

    const user =
      await verifyToken(
        token,
        env.JWT_SECRET
      );

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get release ID
    // -------------------------

    const releaseId =
      url.pathname.split("/")[3];

    if (!releaseId) {
      return json({
        success: false,
        error: "Release ID is required"
      }, 400);
    }

    // -------------------------
    // Verify release ownership
    // -------------------------

    const release =
      await env.DB
        .prepare(`
          SELECT
            id,
            user_id,
            title
          FROM releases
          WHERE id = ?
        `)
        .bind(releaseId)
        .first();

    if (!release) {
      return json({
        success: false,
        error: "Release not found"
      }, 404);
    }

    if (release.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to view this release"
      }, 403);
    }

    // -------------------------
    // Get tracks
    // -------------------------

    const result =
      await env.DB
        .prepare(`
          SELECT
            id,
            release_id,
            title,
            version,
            isrc,
            track_number,
            disc_number,
            duration_seconds,
            genre,
            language,
            explicit,
            lyrics,
            audio_asset_id,
            created_at,
            updated_at

          FROM tracks

          WHERE release_id = ?

          ORDER BY
            disc_number ASC,
            track_number ASC
        `)
        .bind(releaseId)
        .all();

    // -------------------------
    // Attach audio assets
    // -------------------------

    const tracks =
      await Promise.all(
        (result.results || []).map(
          async (track) => {

            let audioAsset = null;

            if (track.audio_asset_id) {

              audioAsset =
                await env.DB
                  .prepare(`
                    SELECT
                      id,
                      type,
                      filename,
                      content_type,
                      size_bytes,
                      r2_key,
                      status,
                      created_at

                    FROM assets

                    WHERE id = ?
                      AND user_id = ?
                  `)
                  .bind(
                    track.audio_asset_id,
                    user.sub
                  )
                  .first();
            }

            return {
              ...track,

              explicit:
                Boolean(track.explicit),

              audio_asset:
                audioAsset
            };
          }
        )
      );

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,

      release: {
        id: release.id,
        title: release.title
      },

      tracks
    });

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to retrieve tracks"
    }, 500);
  }
}

// -------------------------
// VALIDATE RELEASE
// POST /v1/releases/:release_id/validate
// -------------------------

if (
  request.method === "POST" &&
  url.pathname.match(/^\/v1\/releases\/[^/]+\/validate$/)
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token =
      authorization.substring(7);

    const user =
      await verifyToken(
        token,
        env.JWT_SECRET
      );

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get release ID
    // -------------------------

    const releaseId =
      url.pathname.split("/")[3];

    if (!releaseId) {
      return json({
        success: false,
        error: "Release ID is required"
      }, 400);
    }

    // -------------------------
    // Get release
    // -------------------------

    const release =
      await env.DB
        .prepare(`
          SELECT
            id,
            user_id,
            artist_id,
            title,
            release_type,
            version,
            genre,
            subgenre,
            language,
            release_date,
            original_release_date,
            upc,
            copyright_line,
            phonographic_copyright_line,
            label_name,
            artwork_asset_id,
            explicit,
            status
          FROM releases
          WHERE id = ?
        `)
        .bind(releaseId)
        .first();

    if (!release) {
      return json({
        success: false,
        error: "Release not found"
      }, 404);
    }

    // -------------------------
    // Ownership
    // -------------------------

    if (release.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to validate this release"
      }, 403);
    }

    // -------------------------
    // Validation containers
    // -------------------------

    const errors = [];
    const warnings = [];

    // -------------------------
    // RELEASE METADATA
    // -------------------------

    if (!release.title || !release.title.trim()) {
      errors.push({
        code: "MISSING_RELEASE_TITLE",
        field: "title",
        message: "Release title is required"
      });
    }

    if (!release.artist_id) {
      errors.push({
        code: "MISSING_ARTIST",
        field: "artist_id",
        message: "An artist is required"
      });
    }

    const validReleaseTypes = [
      "single",
      "album",
      "ep",
      "compilation"
    ];

    if (
      !release.release_type ||
      !validReleaseTypes.includes(
        String(release.release_type).toLowerCase()
      )
    ) {
      errors.push({
        code: "INVALID_RELEASE_TYPE",
        field: "release_type",
        message: "Release type must be single, album, ep, or compilation"
      });
    }

    if (!release.genre || !release.genre.trim()) {
      errors.push({
        code: "MISSING_GENRE",
        field: "genre",
        message: "Genre is required"
      });
    }

    if (!release.language || !release.language.trim()) {
      errors.push({
        code: "MISSING_LANGUAGE",
        field: "language",
        message: "Language is required"
      });
    }

    if (!release.release_date) {
      errors.push({
        code: "MISSING_RELEASE_DATE",
        field: "release_date",
        message: "Release date is required"
      });
    }

    if (
      !release.copyright_line ||
      !release.copyright_line.trim()
    ) {
      errors.push({
        code: "MISSING_COPYRIGHT",
        field: "copyright_line",
        message: "Copyright line is required"
      });
    }

    if (
      !release.phonographic_copyright_line ||
      !release.phonographic_copyright_line.trim()
    ) {
      errors.push({
        code: "MISSING_PHONOGRAPHIC_COPYRIGHT",
        field: "phonographic_copyright_line",
        message: "Phonographic copyright line is required"
      });
    }

    // -------------------------
    // ARTIST
    // -------------------------

    const artist =
      await env.DB
        .prepare(`
          SELECT
            id,
            user_id,
            name
          FROM artists
          WHERE id = ?
        `)
        .bind(release.artist_id)
        .first();

    if (!artist) {
      errors.push({
        code: "ARTIST_NOT_FOUND",
        field: "artist_id",
        message: "The selected artist does not exist"
      });
    } else if (artist.user_id !== user.sub) {
      errors.push({
        code: "INVALID_ARTIST_OWNER",
        field: "artist_id",
        message: "The selected artist does not belong to this account"
      });
    } else if (!artist.name || !artist.name.trim()) {
      errors.push({
        code: "MISSING_ARTIST_NAME",
        field: "artist_id",
        message: "Artist name is required"
      });
    }

    // -------------------------
    // ARTWORK
    // -------------------------

    if (!release.artwork_asset_id) {

      errors.push({
        code: "MISSING_ARTWORK",
        field: "artwork_asset_id",
        message: "Release artwork is required"
      });

    } else {

      const artwork =
        await env.DB
          .prepare(`
            SELECT
              id,
              type,
              content_type,
              size_bytes,
              r2_key,
              status
            FROM assets
            WHERE id = ?
              AND user_id = ?
              AND release_id = ?
          `)
          .bind(
            release.artwork_asset_id,
            user.sub,
            releaseId
          )
          .first();

      if (!artwork) {

        errors.push({
          code: "ARTWORK_ASSET_NOT_FOUND",
          field: "artwork_asset_id",
          message: "Artwork asset could not be found"
        });

      } else {

        if (artwork.type !== "artwork") {
          errors.push({
            code: "INVALID_ARTWORK_ASSET",
            field: "artwork_asset_id",
            message: "The selected asset is not artwork"
          });
        }

        const allowedArtworkTypes = [
          "image/jpeg",
          "image/png",
          "image/webp"
        ];

        if (
          !allowedArtworkTypes.includes(
            artwork.content_type
          )
        ) {
          errors.push({
            code: "INVALID_ARTWORK_FORMAT",
            field: "artwork",
            message: "Artwork must be JPEG, PNG, or WebP"
          });
        }

        if (artwork.status !== "uploaded") {
          errors.push({
            code: "ARTWORK_NOT_UPLOADED",
            field: "artwork",
            message: "Artwork has not been successfully uploaded"
          });
        }
      }
    }

    // -------------------------
    // GET TRACKS
    // -------------------------

    const tracksResult =
      await env.DB
        .prepare(`
          SELECT
            id,
            title,
            version,
            isrc,
            track_number,
            disc_number,
            duration_seconds,
            genre,
            language,
            explicit,
            audio_asset_id
          FROM tracks
          WHERE release_id = ?
          ORDER BY
            disc_number ASC,
            track_number ASC
        `)
        .bind(releaseId)
        .all();

    const tracks =
      tracksResult.results || [];

    // -------------------------
    // TRACK COUNT
    // -------------------------

    if (tracks.length === 0) {

      errors.push({
        code: "NO_TRACKS",
        field: "tracks",
        message: "At least one track is required"
      });
    }

    // -------------------------
    // RELEASE TYPE / TRACK COUNT
    // -------------------------

    if (
      release.release_type === "single" &&
      tracks.length > 1
    ) {
      warnings.push({
        code: "SINGLE_HAS_MULTIPLE_TRACKS",
        field: "tracks",
        message: "A single normally contains one main track"
      });
    }

    if (
      release.release_type === "album" &&
      tracks.length < 2
    ) {
      warnings.push({
        code: "ALBUM_HAS_ONE_TRACK",
        field: "tracks",
        message: "An album normally contains multiple tracks"
      });
    }

    // -------------------------
    // TRACK VALIDATION
    // -------------------------

    const trackNumbers = new Set();

    for (const track of tracks) {

      // Track title
      if (
        !track.title ||
        !track.title.trim()
      ) {
        errors.push({
          code: "MISSING_TRACK_TITLE",
          track_id: track.id,
          field: "title",
          message: "Track title is required"
        });
      }

      // Track number
      if (
        !Number.isInteger(
          Number(track.track_number)
        ) ||
        Number(track.track_number) < 1
      ) {
        errors.push({
          code: "INVALID_TRACK_NUMBER",
          track_id: track.id,
          field: "track_number",
          message: "Track number must be a positive integer"
        });
      }

      // Duplicate track numbers
      const trackKey =
        `${track.disc_number}:${track.track_number}`;

      if (trackNumbers.has(trackKey)) {

        errors.push({
          code: "DUPLICATE_TRACK_NUMBER",
          track_id: track.id,
          field: "track_number",
          message: "Duplicate track number detected"
        });

      } else {

        trackNumbers.add(trackKey);
      }

      // Audio
      if (!track.audio_asset_id) {

        errors.push({
          code: "MISSING_AUDIO",
          track_id: track.id,
          field: "audio_asset_id",
          message: "Track audio is required"
        });

      } else {

        const audio =
          await env.DB
            .prepare(`
              SELECT
                id,
                type,
                content_type,
                size_bytes,
                r2_key,
                status
              FROM assets
              WHERE id = ?
                AND user_id = ?
                AND track_id = ?
            `)
            .bind(
              track.audio_asset_id,
              user.sub,
              track.id
            )
            .first();

        if (!audio) {

          errors.push({
            code: "AUDIO_ASSET_NOT_FOUND",
            track_id: track.id,
            field: "audio_asset_id",
            message: "Audio asset could not be found"
          });

        } else {

          if (audio.type !== "audio") {

            errors.push({
              code: "INVALID_AUDIO_ASSET",
              track_id: track.id,
              field: "audio_asset_id",
              message: "Selected asset is not an audio asset"
            });
          }

          const allowedAudioTypes = [
            "audio/wav",
            "audio/x-wav",
            "audio/wave",
            "audio/flac",
            "audio/mpeg",
            "audio/mp4",
            "audio/aac",
            "audio/x-m4a"
          ];

          if (
            !allowedAudioTypes.includes(
              audio.content_type
            )
          ) {
            errors.push({
              code: "INVALID_AUDIO_FORMAT",
              track_id: track.id,
              field: "audio",
              message: "Unsupported audio format"
            });
          }

          if (audio.status !== "uploaded") {

            errors.push({
              code: "AUDIO_NOT_UPLOADED",
              track_id: track.id,
              field: "audio",
              message: "Audio has not been successfully uploaded"
            });
          }
        }
      }

      // ISRC
      if (!track.isrc) {

        warnings.push({
          code: "MISSING_ISRC",
          track_id: track.id,
          field: "isrc",
          message: "Track ISRC is missing"
        });
      } else {

        const isrcPattern =
          /^[A-Z]{2}[A-Z0-9]{3}\d{7}$/;

        if (!isrcPattern.test(track.isrc)) {

          errors.push({
            code: "INVALID_ISRC",
            track_id: track.id,
            field: "isrc",
            message: "Invalid ISRC format"
          });
        }
      }

      // Duration
      if (
        track.duration_seconds === null ||
        track.duration_seconds === undefined
      ) {

        warnings.push({
          code: "MISSING_DURATION",
          track_id: track.id,
          field: "duration_seconds",
          message: "Track duration has not been provided"
        });
      }

      // Track genre
      if (
        !track.genre ||
        !track.genre.trim()
      ) {

        warnings.push({
          code: "MISSING_TRACK_GENRE",
          track_id: track.id,
          field: "genre",
          message: "Track genre is not specified"
        });
      }

      // Track language
      if (
        !track.language ||
        !track.language.trim()
      ) {

        warnings.push({
          code: "MISSING_TRACK_LANGUAGE",
          track_id: track.id,
          field: "language",
          message: "Track language is not specified"
        });
      }
    }

    // -------------------------
// CONTRIBUTOR VALIDATION
// -------------------------

for (const track of tracks) {

  const contributorsResult =
    await env.DB
      .prepare(`
        SELECT
          id,
          name,
          role,
          artist_id
        FROM track_contributors
        WHERE track_id = ?
      `)
      .bind(track.id)
      .all();

  const contributors =
    contributorsResult.results || [];

  // -------------------------
  // Basic contributor check
  // -------------------------

  if (contributors.length === 0) {

    errors.push({
      code: "MISSING_CONTRIBUTORS",
      track_id: track.id,
      message: "At least one contributor is required"
    });

    continue;
  }

  // -------------------------
  // Primary artist
  // -------------------------

  const primaryArtists =
    contributors.filter(
      contributor =>
        contributor.role === "primary_artist"
    );

  if (primaryArtists.length === 0) {

    errors.push({
      code: "MISSING_PRIMARY_ARTIST",
      track_id: track.id,
      field: "contributors",
      message: "At least one primary artist is required"
    });

  } else {

    // Check linked artist ownership
    for (const contributor of primaryArtists) {

      if (contributor.artist_id) {

        const artist =
          await env.DB
            .prepare(`
              SELECT
                id,
                user_id,
                name
              FROM artists
              WHERE id = ?
            `)
            .bind(contributor.artist_id)
            .first();

        if (!artist) {

          errors.push({
            code: "PRIMARY_ARTIST_NOT_FOUND",
            track_id: track.id,
            contributor_id: contributor.id,
            message: "Linked primary artist does not exist"
          });

        } else if (artist.user_id !== user.sub) {

          errors.push({
            code: "INVALID_PRIMARY_ARTIST_OWNER",
            track_id: track.id,
            contributor_id: contributor.id,
            message: "Primary artist does not belong to this account"
          });
        }
      }
    }
  }

  // -------------------------
  // Songwriter / Composer
  // -------------------------

  const writers =
    contributors.filter(
      contributor =>
        contributor.role === "songwriter" ||
        contributor.role === "composer"
    );

  if (writers.length === 0) {

    errors.push({
      code: "MISSING_SONGWRITER",
      track_id: track.id,
      field: "contributors",
      message: "At least one songwriter or composer is required"
    });
  }

  // -------------------------
  // Producer
  // -------------------------

  const producers =
    contributors.filter(
      contributor =>
        contributor.role === "producer"
    );

  if (producers.length === 0) {

    warnings.push({
      code: "MISSING_PRODUCER",
      track_id: track.id,
      field: "contributors",
      message: "No producer has been added to this track"
    });
  }

  // -------------------------
  // Contributor names
  // -------------------------

  for (const contributor of contributors) {

    if (
      !contributor.name ||
      !contributor.name.trim()
    ) {

      errors.push({
        code: "INVALID_CONTRIBUTOR_NAME",
        track_id: track.id,
        contributor_id: contributor.id,
        message: "Contributor name cannot be empty"
      });
    }
  }
}

    // -------------------------
    // FINAL STATUS
    // -------------------------

    const valid =
      errors.length === 0;

    const status =
      valid
        ? "ready"
        : "incomplete";

    // -------------------------
    // Update release status
    // -------------------------

    await env.DB
      .prepare(`
        UPDATE releases
        SET status = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        status,
        releaseId
      )
      .run();

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,

      release_id: releaseId,

      valid,

      status,

      summary: {
        errors: errors.length,
        warnings: warnings.length,
        tracks: tracks.length
      },

      errors,

      warnings
    });

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to validate release"
    }, 500);
  }
}

// -------------------------
// ADD TRACK CONTRIBUTOR
// POST /v1/tracks/:track_id/contributors
// -------------------------

if (
  request.method === "POST" &&
  url.pathname.match(/^\/v1\/tracks\/[^/]+\/contributors$/)
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token = authorization.substring(7);

    const user =
      await verifyToken(token, env.JWT_SECRET);

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Get track ID
    // -------------------------

    const trackId =
      url.pathname.split("/")[3];

    if (!trackId) {
      return json({
        success: false,
        error: "Track ID is required"
      }, 400);
    }

    // -------------------------
    // Get track + verify ownership
    // -------------------------

    const track =
      await env.DB
        .prepare(`
          SELECT
            tracks.id,
            tracks.release_id,
            releases.user_id
          FROM tracks
          INNER JOIN releases
            ON tracks.release_id = releases.id
          WHERE tracks.id = ?
        `)
        .bind(trackId)
        .first();

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    if (track.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to modify this track"
      }, 403);
    }

    // -------------------------
    // Parse request body
    // -------------------------

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        error: "Invalid JSON body"
      }, 400);
    }

    const name =
      typeof body.name === "string"
        ? body.name.trim()
        : "";

    const role =
      typeof body.role === "string"
        ? body.role.trim().toLowerCase()
        : "";

    const artistId =
      typeof body.artist_id === "string" &&
      body.artist_id.trim()
        ? body.artist_id.trim()
        : null;

    // -------------------------
    // Validate name
    // -------------------------

    if (!name) {
      return json({
        success: false,
        error: "Contributor name is required"
      }, 400);
    }

    if (name.length > 200) {
      return json({
        success: false,
        error: "Contributor name is too long"
      }, 400);
    }

    // -------------------------
    // Validate role
    // -------------------------

    const allowedRoles = [
      "primary_artist",
      "featured_artist",
      "remixer",
      "producer",
      "songwriter",
      "composer",
      "lyricist",
      "arranger",
      "engineer",
      "vocalist"
    ];

    if (!allowedRoles.includes(role)) {
      return json({
        success: false,
        error: "Invalid contributor role",
        allowed_roles: allowedRoles
      }, 400);
    }

    // -------------------------
    // Validate artist_id
    // -------------------------

    if (artistId) {

      const artist =
        await env.DB
          .prepare(`
            SELECT
              id,
              user_id,
              name
            FROM artists
            WHERE id = ?
          `)
          .bind(artistId)
          .first();

      if (!artist) {
        return json({
          success: false,
          error: "Artist not found"
        }, 404);
      }

      if (artist.user_id !== user.sub) {
        return json({
          success: false,
          error: "You do not have permission to use this artist"
        }, 403);
      }
    }

    // -------------------------
    // Prevent exact duplicate
    // -------------------------

    const existing =
      await env.DB
        .prepare(`
          SELECT
            id
          FROM track_contributors
          WHERE track_id = ?
            AND name = ?
            AND role = ?
        `)
        .bind(
          trackId,
          name,
          role
        )
        .first();

    if (existing) {
      return json({
        success: false,
        error: "This contributor already exists on this track"
      }, 409);
    }

    // -------------------------
    // Create contributor
    // -------------------------

    const contributorId =
      `contributor_${crypto.randomUUID()}`;

    await env.DB
      .prepare(`
        INSERT INTO track_contributors (
          id,
          track_id,
          name,
          role,
          artist_id
        )
        VALUES (?, ?, ?, ?, ?)
      `)
      .bind(
        contributorId,
        trackId,
        name,
        role,
        artistId
      )
      .run();

    // -------------------------
    // Get created contributor
    // -------------------------

    const contributor =
      await env.DB
        .prepare(`
          SELECT
            id,
            track_id,
            name,
            role,
            artist_id,
            created_at
          FROM track_contributors
          WHERE id = ?
        `)
        .bind(contributorId)
        .first();

    // -------------------------
    // Response
    // -------------------------

    return json({
      success: true,
      message: "Contributor added successfully",
      contributor
    }, 201);

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to add contributor"
    }, 500);
  }
}

// -------------------------
// GET TRACK CONTRIBUTORS
// GET /v1/tracks/:track_id/contributors
// -------------------------

if (
  request.method === "GET" &&
  url.pathname.match(/^\/v1\/tracks\/[^/]+\/contributors$/)
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token = authorization.substring(7);

    const user =
      await verifyToken(token, env.JWT_SECRET);

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // Track ID
    // -------------------------

    const trackId =
      url.pathname.split("/")[3];

    // -------------------------
    // Verify ownership
    // -------------------------

    const track =
      await env.DB
        .prepare(`
          SELECT
            tracks.id,
            tracks.title,
            releases.user_id
          FROM tracks
          INNER JOIN releases
            ON tracks.release_id = releases.id
          WHERE tracks.id = ?
        `)
        .bind(trackId)
        .first();

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    if (track.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to view this track"
      }, 403);
    }

    // -------------------------
    // Get contributors
    // -------------------------

    const result =
      await env.DB
        .prepare(`
          SELECT
            id,
            track_id,
            name,
            role,
            artist_id,
            created_at
          FROM track_contributors
          WHERE track_id = ?
          ORDER BY created_at ASC
        `)
        .bind(trackId)
        .all();

    return json({
      success: true,

      track: {
        id: track.id,
        title: track.title
      },

      contributors:
        result.results || []
    });

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to retrieve contributors"
    }, 500);
  }
}

// -------------------------
// DELETE TRACK CONTRIBUTOR
// DELETE /v1/tracks/:track_id/contributors/:contributor_id
// -------------------------

if (
  request.method === "DELETE" &&
  url.pathname.match(
    /^\/v1\/tracks\/[^/]+\/contributors\/[^/]+$/
  )
) {
  try {
    // -------------------------
    // Authentication
    // -------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token = authorization.substring(7);

    const user =
      await verifyToken(token, env.JWT_SECRET);

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------
    // IDs
    // -------------------------

    const parts =
      url.pathname.split("/");

    const trackId = parts[3];
    const contributorId = parts[5];

    // -------------------------
    // Verify track ownership
    // -------------------------

    const track =
      await env.DB
        .prepare(`
          SELECT
            tracks.id,
            releases.user_id
          FROM tracks
          INNER JOIN releases
            ON tracks.release_id = releases.id
          WHERE tracks.id = ?
        `)
        .bind(trackId)
        .first();

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    if (track.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to modify this track"
      }, 403);
    }

    // -------------------------
    // Find contributor
    // -------------------------

    const contributor =
      await env.DB
        .prepare(`
          SELECT
            id,
            name,
            role
          FROM track_contributors
          WHERE id = ?
            AND track_id = ?
        `)
        .bind(
          contributorId,
          trackId
        )
        .first();

    if (!contributor) {
      return json({
        success: false,
        error: "Contributor not found"
      }, 404);
    }

    // -------------------------
    // Delete
    // -------------------------

    await env.DB
      .prepare(`
        DELETE FROM track_contributors
        WHERE id = ?
          AND track_id = ?
      `)
      .bind(
        contributorId,
        trackId
      )
      .run();

    return json({
      success: true,
      message: "Contributor deleted successfully",
      contributor: {
        id: contributor.id,
        name: contributor.name,
        role: contributor.role
      }
    });

  } catch (error) {

    console.error(error);

    return json({
      success: false,
      error: "Unable to delete contributor"
    }, 500);
  }
}

// =====================================================
// UPDATE TRACK
// PATCH /v1/tracks/:track_id
// =====================================================

if (
  request.method === "PATCH" &&
  url.pathname.match(/^\/v1\/tracks\/[^/]+$/)
) {
  try {
    // -------------------------------------------------
    // Authentication
    // -------------------------------------------------

    const authorization =
      request.headers.get("Authorization");

    if (!authorization) {
      return json({
        success: false,
        error: "Authorization required"
      }, 401);
    }

    if (!authorization.startsWith("Bearer ")) {
      return json({
        success: false,
        error: "Invalid authorization format"
      }, 401);
    }

    const token = authorization.substring(7);

    const user =
      await verifyToken(token, env.JWT_SECRET);

    if (!user) {
      return json({
        success: false,
        error: "Invalid or expired token"
      }, 401);
    }

    // -------------------------------------------------
    // Get track ID
    // -------------------------------------------------

    const trackId =
      url.pathname.split("/")[3];

    if (!trackId) {
      return json({
        success: false,
        error: "Track ID is required"
      }, 400);
    }

    // -------------------------------------------------
    // Find track and verify ownership
    // -------------------------------------------------

    const track =
      await env.DB
        .prepare(`
          SELECT
            tracks.*,
            releases.user_id,
            releases.id AS release_id
          FROM tracks
          INNER JOIN releases
            ON tracks.release_id = releases.id
          WHERE tracks.id = ?
        `)
        .bind(trackId)
        .first();

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    if (track.user_id !== user.sub) {
      return json({
        success: false,
        error: "You do not have permission to modify this track"
      }, 403);
    }

    // -------------------------------------------------
    // Parse JSON body
    // -------------------------------------------------

    let body;

    try {
      body = await request.json();
    } catch {
      return json({
        success: false,
        error: "Invalid JSON body"
      }, 400);
    }

    if (
      !body ||
      typeof body !== "object" ||
      Array.isArray(body)
    ) {
      return json({
        success: false,
        error: "Request body must be a JSON object"
      }, 400);
    }

    // -------------------------------------------------
    // Allowed fields
    // -------------------------------------------------

    const allowedFields = [
      "title",
      "version",
      "isrc",
      "track_number",
      "disc_number",
      "duration_seconds",
      "genre",
      "language",
      "explicit",
      "lyrics"
    ];

    const suppliedFields =
      Object.keys(body);

    const unknownFields =
      suppliedFields.filter(
        field => !allowedFields.includes(field)
      );

    if (unknownFields.length > 0) {
      return json({
        success: false,
        error: "Unknown field(s)",
        fields: unknownFields,
        allowed_fields: allowedFields
      }, 400);
    }

    if (suppliedFields.length === 0) {
      return json({
        success: false,
        error: "No fields provided for update"
      }, 400);
    }

    // -------------------------------------------------
    // Prepare update values
    // -------------------------------------------------

    const updates = [];
    const values = [];

    // -------------------------------------------------
    // TITLE
    // -------------------------------------------------

    if (Object.prototype.hasOwnProperty.call(body, "title")) {

      if (
        typeof body.title !== "string" ||
        !body.title.trim()
      ) {
        return json({
          success: false,
          error: "Title must be a non-empty string"
        }, 400);
      }

      const title =
        body.title.trim();

      if (title.length > 300) {
        return json({
          success: false,
          error: "Title is too long"
        }, 400);
      }

      updates.push("title = ?");
      values.push(title);
    }

    // -------------------------------------------------
    // VERSION
    // -------------------------------------------------

    if (Object.prototype.hasOwnProperty.call(body, "version")) {

      if (
        body.version !== null &&
        typeof body.version !== "string"
      ) {
        return json({
          success: false,
          error: "Version must be a string or null"
        }, 400);
      }

      const version =
        body.version === null
          ? null
          : body.version.trim();

      if (
        version !== null &&
        version.length > 100
      ) {
        return json({
          success: false,
          error: "Version is too long"
        }, 400);
      }

      updates.push("version = ?");
      values.push(version);
    }

    // -------------------------------------------------
    // ISRC
    // -------------------------------------------------

    if (Object.prototype.hasOwnProperty.call(body, "isrc")) {

      if (
        body.isrc !== null &&
        typeof body.isrc !== "string"
      ) {
        return json({
          success: false,
          error: "ISRC must be a string or null"
        }, 400);
      }

      let isrc =
        body.isrc === null
          ? null
          : body.isrc
              .trim()
              .toUpperCase()
              .replace(/-/g, "");

      if (isrc !== null) {

        /*
         * ISRC format:
         *
         * Country      2 letters
         * Registrant   3 letters/numbers
         * Year         2 digits
         * Designation  5 digits
         *
         * Example:
         * USRC17607839
         */

        const isrcRegex =
          /^[A-Z]{2}[A-Z0-9]{3}[0-9]{2}[0-9]{5}$/;

        if (!isrcRegex.test(isrc)) {
          return json({
            success: false,
            error: "Invalid ISRC format",
            message:
              "ISRC must contain 12 characters in the format CCXXXYYNNNNN"
          }, 400);
        }

        // ---------------------------------------------
        // Check whether ISRC is already used
        // ---------------------------------------------

        const existingIsrc =
          await env.DB
            .prepare(`
              SELECT
                id,
                title
              FROM tracks
              WHERE isrc = ?
                AND id != ?
            `)
            .bind(isrc, trackId)
            .first();

        if (existingIsrc) {
          return json({
            success: false,
            error: "ISRC already exists",
            message:
              "This ISRC is already assigned to another track"
          }, 409);
        }
      }

      updates.push("isrc = ?");
      values.push(isrc);
    }

    // -------------------------------------------------
    // TRACK NUMBER
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "track_number"
      )
    ) {

      const trackNumber =
        body.track_number;

      if (
        !Number.isInteger(trackNumber) ||
        trackNumber < 1
      ) {
        return json({
          success: false,
          error:
            "track_number must be a positive integer"
        }, 400);
      }

      // -----------------------------------------------
      // Prevent duplicate track number on release
      // -----------------------------------------------

      const duplicate =
        await env.DB
          .prepare(`
            SELECT id
            FROM tracks
            WHERE release_id = ?
              AND track_number = ?
              AND id != ?
          `)
          .bind(
            track.release_id,
            trackNumber,
            trackId
          )
          .first();

      if (duplicate) {
        return json({
          success: false,
          error:
            "A track with this track number already exists on this release"
        }, 409);
      }

      updates.push("track_number = ?");
      values.push(trackNumber);
    }

    // -------------------------------------------------
    // DISC NUMBER
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "disc_number"
      )
    ) {

      const discNumber =
        body.disc_number;

      if (
        !Number.isInteger(discNumber) ||
        discNumber < 1
      ) {
        return json({
          success: false,
          error:
            "disc_number must be a positive integer"
        }, 400);
      }

      updates.push("disc_number = ?");
      values.push(discNumber);
    }

    // -------------------------------------------------
    // DURATION
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "duration_seconds"
      )
    ) {

      const duration =
        body.duration_seconds;

      if (
        duration !== null &&
        (
          typeof duration !== "number" ||
          !Number.isFinite(duration) ||
          duration <= 0
        )
      ) {
        return json({
          success: false,
          error:
            "duration_seconds must be a positive number or null"
        }, 400);
      }

      updates.push("duration_seconds = ?");
      values.push(duration);
    }

    // -------------------------------------------------
    // GENRE
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "genre"
      )
    ) {

      if (
        body.genre !== null &&
        typeof body.genre !== "string"
      ) {
        return json({
          success: false,
          error: "Genre must be a string or null"
        }, 400);
      }

      const genre =
        body.genre === null
          ? null
          : body.genre.trim();

      if (
        genre !== null &&
        genre.length > 100
      ) {
        return json({
          success: false,
          error: "Genre is too long"
        }, 400);
      }

      updates.push("genre = ?");
      values.push(genre);
    }

    // -------------------------------------------------
    // LANGUAGE
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "language"
      )
    ) {

      if (
        body.language !== null &&
        typeof body.language !== "string"
      ) {
        return json({
          success: false,
          error: "Language must be a string or null"
        }, 400);
      }

      const language =
        body.language === null
          ? null
          : body.language.trim();

      if (
        language !== null &&
        language.length > 100
      ) {
        return json({
          success: false,
          error: "Language is too long"
        }, 400);
      }

      updates.push("language = ?");
      values.push(language);
    }

    // -------------------------------------------------
    // EXPLICIT
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "explicit"
      )
    ) {

      if (typeof body.explicit !== "boolean") {
        return json({
          success: false,
          error: "explicit must be true or false"
        }, 400);
      }

      updates.push("explicit = ?");
      values.push(body.explicit ? 1 : 0);
    }

    // -------------------------------------------------
    // LYRICS
    // -------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        body,
        "lyrics"
      )
    ) {

      if (
        body.lyrics !== null &&
        typeof body.lyrics !== "string"
      ) {
        return json({
          success: false,
          error: "Lyrics must be a string or null"
        }, 400);
      }

      if (
        body.lyrics !== null &&
        body.lyrics.length > 50000
      ) {
        return json({
          success: false,
          error: "Lyrics are too long"
        }, 400);
      }

      updates.push("lyrics = ?");
      values.push(body.lyrics);
    }

    // -------------------------------------------------
    // Nothing to update
    // -------------------------------------------------

    if (updates.length === 0) {
      return json({
        success: false,
        error: "No valid fields provided for update"
      }, 400);
    }

    // -------------------------------------------------
    // Add updated_at
    // -------------------------------------------------

    updates.push("updated_at = CURRENT_TIMESTAMP");

    // -------------------------------------------------
    // Execute update
    // -------------------------------------------------

    values.push(trackId);

    await env.DB
      .prepare(`
        UPDATE tracks
        SET ${updates.join(", ")}
        WHERE id = ?
      `)
      .bind(...values)
      .run();

    // -------------------------------------------------
    // Return updated track
    // -------------------------------------------------

    const updatedTrack =
      await env.DB
        .prepare(`
          SELECT
            id,
            release_id,
            title,
            version,
            isrc,
            track_number,
            disc_number,
            duration_seconds,
            genre,
            language,
            explicit,
            lyrics,
            audio_asset_id,
            created_at,
            updated_at
          FROM tracks
          WHERE id = ?
        `)
        .bind(trackId)
        .first();

    return json({
      success: true,
      message: "Track updated successfully",
      track: updatedTrack
    });

  } catch (error) {

    console.error(
      "Update track error:",
      error
    );

    return json({
      success: false,
      error: "Unable to update track"
    }, 500);
  }
}

// ============================================================
// POST /v1/releases/:release_id/submit
// Submit release for distribution
// ============================================================

if (
  request.method === "POST" &&
  url.pathname.startsWith("/v1/releases/") &&
  url.pathname.endsWith("/submit")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const releaseId = parts[3];

  if (!releaseId) {
    return json(
      {
        success: false,
        error: "Release ID is required"
      },
      400
    );
  }

  // ----------------------------------------------------------
  // Load release
  // ----------------------------------------------------------

  const release = await env.DB
    .prepare(`
      SELECT *
      FROM releases
      WHERE id = ?
        AND user_id = ?
    `)
    .bind(releaseId, auth.sub)
    .first();

  if (!release) {
    return json(
      {
        success: false,
        error: "Release not found"
      },
      404
    );
  }

  // ----------------------------------------------------------
  // Check release status
  // ----------------------------------------------------------

  const blockedStatuses = [
    "submitted",
    "processing",
    "delivered",
    "live"
  ];

  if (blockedStatuses.includes(release.status)) {
    return json(
      {
        success: false,
        error: `Release cannot be submitted while status is '${release.status}'`
      },
      409
    );
  }

  // ----------------------------------------------------------
  // Load tracks
  // ----------------------------------------------------------

  const tracksResult = await env.DB
    .prepare(`
      SELECT *
      FROM tracks
      WHERE release_id = ?
      ORDER BY disc_number ASC, track_number ASC
    `)
    .bind(releaseId)
    .all();

  const tracks = tracksResult.results || [];

  if (tracks.length === 0) {
    return json(
      {
        success: false,
        error: "Release must contain at least one track"
      },
      422
    );
  }

  const errors = [];
  const warnings = [];

  // ----------------------------------------------------------
  // Album warning
  // ----------------------------------------------------------

  if (
    release.release_type === "album" &&
    tracks.length === 1
  ) {
    warnings.push({
      code: "ALBUM_HAS_ONE_TRACK",
      field: "tracks",
      message: "An album normally contains multiple tracks"
    });
  }

  // ----------------------------------------------------------
  // Validate artwork
  // ----------------------------------------------------------

  const artwork = await env.DB
    .prepare(`
      SELECT *
      FROM assets
      WHERE release_id = ?
        AND type = 'artwork'
        AND status = 'uploaded'
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(releaseId)
    .first();

  if (!artwork) {
    errors.push({
      code: "MISSING_ARTWORK",
      field: "artwork",
      message: "Release artwork is required"
    });
  }

  // ----------------------------------------------------------
  // Validate tracks
  // ----------------------------------------------------------

  for (const track of tracks) {

    const trackPrefix = `tracks.${track.track_number}`;

    // Audio
    const audio = await env.DB
      .prepare(`
        SELECT *
        FROM assets
        WHERE id = ?
          AND track_id = ?
          AND release_id = ?
          AND type = 'audio'
          AND status = 'uploaded'
        LIMIT 1
      `)
      .bind(
        track.audio_asset_id,
        track.id,
        releaseId
      )
      .first();

    if (!audio) {
      errors.push({
        code: "MISSING_AUDIO",
        field: `${trackPrefix}.audio`,
        message: `Audio file is required for track '${track.title}'`
      });
    }

    // ISRC
    if (!track.isrc) {
      errors.push({
        code: "MISSING_ISRC",
        field: `${trackPrefix}.isrc`,
        message: `ISRC is required for track '${track.title}'`
      });
    }

    // Duration
    if (
      !track.duration_seconds ||
      Number(track.duration_seconds) <= 0
    ) {
      errors.push({
        code: "MISSING_DURATION",
        field: `${trackPrefix}.duration_seconds`,
        message: `Track duration is required for '${track.title}'`
      });
    }

    // --------------------------------------------------------
    // Contributors
    // --------------------------------------------------------

    const contributorsResult = await env.DB
      .prepare(`
        SELECT *
        FROM track_contributors
        WHERE track_id = ?
      `)
      .bind(track.id)
      .all();

    const contributors =
      contributorsResult.results || [];

    // Primary artist
    const primaryArtist = contributors.find(
      c => c.role === "primary_artist"
    );

    if (!primaryArtist) {
      errors.push({
        code: "MISSING_PRIMARY_ARTIST",
        field: `${trackPrefix}.contributors`,
        message: `Primary artist is required for '${track.title}'`
      });
    }

    // Songwriter/composer
    const songwriter = contributors.find(
      c =>
        c.role === "songwriter" ||
        c.role === "composer"
    );

    if (!songwriter) {
      errors.push({
        code: "MISSING_SONGWRITER",
        field: `${trackPrefix}.contributors`,
        message: `Songwriter or composer is required for '${track.title}'`
      });
    }

    // Producer
    const producer = contributors.find(
      c => c.role === "producer"
    );

    if (!producer) {
      warnings.push({
        code: "MISSING_PRODUCER",
        field: `${trackPrefix}.contributors`,
        message: `Producer is recommended for '${track.title}'`
      });
    }
  }

  // ----------------------------------------------------------
  // Stop if validation failed
  // ----------------------------------------------------------

  if (errors.length > 0) {
    return json(
      {
        success: false,
        message: "Release validation failed",
        release_id: releaseId,
        validation: {
          valid: false,
          errors: errors.length,
          warnings: warnings.length
        },
        errors,
        warnings
      },
      422
    );
  }

  // ----------------------------------------------------------
  // Check for existing submission
  // ----------------------------------------------------------

  const existingSubmission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE release_id = ?
        AND status IN ('queued', 'processing')
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(releaseId)
    .first();

  if (existingSubmission) {
    return json(
      {
        success: false,
        error: "Release already has an active submission",
        submission: existingSubmission
      },
      409
    );
  }

  // ----------------------------------------------------------
  // Create submission ID
  // ----------------------------------------------------------

  const submissionId =
    `submission_${crypto.randomUUID()}`;

  // ----------------------------------------------------------
  // Create submission job
  // ----------------------------------------------------------

  await env.DB
    .prepare(`
      INSERT INTO release_submissions (
        id,
        release_id,
        user_id,
        status,
        submitted_at,
        created_at,
        updated_at
      )
      VALUES (
        ?,
        ?,
        ?,
        'queued',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
      )
    `)
    .bind(
      submissionId,
      releaseId,
      auth.sub
    )
    .run();

  // ----------------------------------------------------------
  // Update release
  // ----------------------------------------------------------

  await env.DB
    .prepare(`
      UPDATE releases
      SET
        status = 'submitted',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
    .bind(
      releaseId,
      auth.sub
    )
    .run();

  // ----------------------------------------------------------
  // Get created submission
  // ----------------------------------------------------------

  const submission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
    `)
    .bind(submissionId)
    .first();

  // ----------------------------------------------------------
  // Response
  // ----------------------------------------------------------

  return json({
    success: true,

    message: "Release submitted successfully",

    release: {
      ...release,
      status: "submitted"
    },

    submission,

    validation: {
      valid: true,
      errors: 0,
      warnings: warnings.length
    },

    next_step:
      "Submission has been queued for distribution processing"
  });
}

// ============================================================
// GET /v1/releases/:release_id/submission
// Get latest submission status
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/releases/") &&
  url.pathname.endsWith("/submission")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const releaseId = parts[3];

  if (!releaseId) {
    return json(
      {
        success: false,
        error: "Release ID is required"
      },
      400
    );
  }

  // ----------------------------------------------------------
  // Verify release ownership
  // ----------------------------------------------------------

  const release = await env.DB
    .prepare(`
      SELECT id, title, status
      FROM releases
      WHERE id = ?
        AND user_id = ?
    `)
    .bind(
      releaseId,
      auth.sub
    )
    .first();

  if (!release) {
    return json(
      {
        success: false,
        error: "Release not found"
      },
      404
    );
  }

  // ----------------------------------------------------------
  // Get latest submission
  // ----------------------------------------------------------

  const submission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE release_id = ?
        AND user_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(
      releaseId,
      auth.sub
    )
    .first();

  if (!submission) {
    return json(
      {
        success: true,
        release,
        submission: null,
        message: "This release has not been submitted yet"
      }
    );
  }

  return json({
    success: true,

    release,

    submission
  });
}

// ============================================================
// POST /v1/submissions/:submission_id/process
// Process a queued release submission
// ============================================================

if (
  request.method === "POST" &&
  url.pathname.startsWith("/v1/submissions/") &&
  url.pathname.endsWith("/process")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  // ----------------------------------------------------------
  // Get submission ID
  // URL:
  // /v1/submissions/:submission_id/process
  // ----------------------------------------------------------

  const parts = url.pathname.split("/");
  const submissionId = parts[3];

  if (!submissionId) {
    return json(
      {
        success: false,
        error: "Submission ID is required"
      },
      400
    );
  }

  // ----------------------------------------------------------
  // Load submission
  // ----------------------------------------------------------

  const submission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      submissionId,
      auth.sub
    )
    .first();

  if (!submission) {
    return json(
      {
        success: false,
        error: "Submission not found"
      },
      404
    );
  }

  // ----------------------------------------------------------
  // Check submission status
  // ----------------------------------------------------------

  if (submission.status === "processing") {
    return json(
      {
        success: false,
        error: "Submission is already being processed",
        submission
      },
      409
    );
  }

  if (submission.status === "ready") {
    return json(
      {
        success: false,
        error: "Submission has already been processed",
        submission
      },
      409
    );
  }

  if (submission.status === "delivered") {
    return json(
      {
        success: false,
        error: "Submission has already been delivered",
        submission
      },
      409
    );
  }

  if (submission.status === "rejected") {
    return json(
      {
        success: false,
        error: "Submission was rejected and cannot be processed",
        submission
      },
      409
    );
  }

  if (submission.status !== "queued") {
    return json(
      {
        success: false,
        error: `Submission cannot be processed from status '${submission.status}'`
      },
      409
    );
  }

  // ----------------------------------------------------------
  // Mark submission as processing
  // ----------------------------------------------------------

  await env.DB
    .prepare(`
      UPDATE release_submissions
      SET
        status = 'processing',
        started_at = CURRENT_TIMESTAMP,
        error_code = NULL,
        error_message = NULL,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
    .bind(
      submissionId,
      auth.sub
    )
    .run();

  // ----------------------------------------------------------
  // Load release
  // ----------------------------------------------------------

  const release = await env.DB
    .prepare(`
      SELECT *
      FROM releases
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      submission.release_id,
      auth.sub
    )
    .first();

  if (!release) {
    await env.DB
      .prepare(`
        UPDATE release_submissions
        SET
          status = 'rejected',
          error_code = 'RELEASE_NOT_FOUND',
          error_message = 'Release associated with submission was not found',
          completed_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(submissionId)
      .run();

    return json(
      {
        success: false,
        error: "Release associated with submission was not found"
      },
      404
    );
  }

  // ----------------------------------------------------------
  // Load artist
  // ----------------------------------------------------------

  let artist = null;

  if (release.artist_id) {
    artist = await env.DB
      .prepare(`
        SELECT *
        FROM artists
        WHERE id = ?
        LIMIT 1
      `)
      .bind(release.artist_id)
      .first();
  }

  // ----------------------------------------------------------
  // Load artwork
  // ----------------------------------------------------------

  const artwork = await env.DB
    .prepare(`
      SELECT *
      FROM assets
      WHERE release_id = ?
        AND type = 'artwork'
        AND status = 'uploaded'
      ORDER BY created_at DESC
      LIMIT 1
    `)
    .bind(release.id)
    .first();

  // ----------------------------------------------------------
  // Load tracks
  // ----------------------------------------------------------

  const tracksResult = await env.DB
    .prepare(`
      SELECT *
      FROM tracks
      WHERE release_id = ?
      ORDER BY disc_number ASC, track_number ASC
    `)
    .bind(release.id)
    .all();

  const tracks = tracksResult.results || [];

  if (tracks.length === 0) {
    await env.DB
      .prepare(`
        UPDATE release_submissions
        SET
          status = 'rejected',
          error_code = 'NO_TRACKS',
          error_message = 'Release contains no tracks',
          completed_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(submissionId)
      .run();

    return json(
      {
        success: false,
        error: "Release contains no tracks"
      },
      422
    );
  }

  // ----------------------------------------------------------
  // Build distribution tracks
  // ----------------------------------------------------------

  const distributionTracks = [];

  for (const track of tracks) {

    // Get audio asset
    let audioAsset = null;

    if (track.audio_asset_id) {
      audioAsset = await env.DB
        .prepare(`
          SELECT *
          FROM assets
          WHERE id = ?
            AND track_id = ?
            AND release_id = ?
          LIMIT 1
        `)
        .bind(
          track.audio_asset_id,
          track.id,
          release.id
        )
        .first();
    }

    // Get contributors
    const contributorsResult = await env.DB
      .prepare(`
        SELECT *
        FROM track_contributors
        WHERE track_id = ?
      `)
      .bind(track.id)
      .all();

    const contributors =
      contributorsResult.results || [];

    distributionTracks.push({
      id: track.id,
      title: track.title,
      version: track.version || null,

      track_number: track.track_number,
      disc_number: track.disc_number,

      isrc: track.isrc || null,

      duration_seconds:
        track.duration_seconds
          ? Number(track.duration_seconds)
          : null,

      genre: track.genre || null,
      language: track.language || null,

      explicit:
        Boolean(track.explicit),

      lyrics: track.lyrics || null,

      audio_asset: audioAsset
        ? {
            id: audioAsset.id,
            filename: audioAsset.filename,
            content_type: audioAsset.content_type,
            size_bytes: audioAsset.size_bytes,
            r2_key: audioAsset.r2_key,
            status: audioAsset.status
          }
        : null,

      contributors: contributors.map(
        contributor => ({
          id: contributor.id,
          role: contributor.role,
          name: contributor.name,
          artist_id:
            contributor.artist_id || null
        })
      )
    });
  }

  // ----------------------------------------------------------
  // Build distribution package
  // ----------------------------------------------------------

  const distributionPackage = {
    package_version: "1.0",

    generated_at: new Date().toISOString(),

    submission: {
      id: submission.id,
      release_id: release.id
    },

    release: {
      id: release.id,

      title: release.title,
      release_type: release.release_type,
      version: release.version || null,

      genre: release.genre || null,
      subgenre: release.subgenre || null,

      language: release.language || null,

      release_date:
        release.release_date || null,

      original_release_date:
        release.original_release_date || null,

      upc: release.upc || null,

      copyright_line:
        release.copyright_line || null,

      phonographic_copyright_line:
        release.phonographic_copyright_line || null,

      label_name:
        release.label_name || null,

      explicit:
        Boolean(release.explicit),

      status:
        release.status
    },

    artist: artist
      ? {
          id: artist.id,
          name: artist.name,
          bio: artist.bio || null,
          country: artist.country || null
        }
      : null,

    artwork: artwork
      ? {
          id: artwork.id,
          filename: artwork.filename,
          content_type: artwork.content_type,
          size_bytes: artwork.size_bytes,
          r2_key: artwork.r2_key,
          status: artwork.status
        }
      : null,

    tracks: distributionTracks
  };

  // ----------------------------------------------------------
  // Create package ID
  // ----------------------------------------------------------

  const packageId =
    `package_${crypto.randomUUID()}`;

  // ----------------------------------------------------------
  // Store distribution package
  // ----------------------------------------------------------

  try {

    await env.DB
      .prepare(`
        INSERT INTO distribution_packages (
          id,
          submission_id,
          release_id,
          user_id,
          package_version,
          status,
          metadata_json,
          created_at,
          updated_at
        )
        VALUES (
          ?,
          ?,
          ?,
          ?,
          '1.0',
          'ready',
          ?,
          CURRENT_TIMESTAMP,
          CURRENT_TIMESTAMP
        )
      `)
      .bind(
        packageId,
        submissionId,
        release.id,
        auth.sub,
        JSON.stringify(distributionPackage)
      )
      .run();

    // --------------------------------------------------------
    // Mark submission ready
    // --------------------------------------------------------

    await env.DB
      .prepare(`
        UPDATE release_submissions
        SET
          status = 'ready',
          completed_at = CURRENT_TIMESTAMP,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
      `)
      .bind(
        submissionId,
        auth.sub
      )
      .run();

    // --------------------------------------------------------
    // Update release status
    // --------------------------------------------------------

    await env.DB
      .prepare(`
        UPDATE releases
        SET
          status = 'ready',
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
      `)
      .bind(
        release.id,
        auth.sub
      )
      .run();

  } catch (error) {

    console.error(
      "Distribution processing failed:",
      error
    );

    await env.DB
      .prepare(`
        UPDATE release_submissions
        SET
          status = 'rejected',
          error_code = 'PACKAGE_CREATION_FAILED',
          error_message = ?,
          completed_at = CURRENT_TIMESTAMP,
          retry_count = retry_count + 1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
      `)
      .bind(
        error?.message || "Failed to create distribution package",
        submissionId,
        auth.sub
      )
      .run();

    return json(
      {
        success: false,
        error: "Distribution processing failed",
        submission_id: submissionId
      },
      500
    );
  }

  // ----------------------------------------------------------
  // Get final submission
  // ----------------------------------------------------------

  const finalSubmission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
    `)
    .bind(submissionId)
    .first();

  // ----------------------------------------------------------
  // Response
  // ----------------------------------------------------------

  return json({
    success: true,

    message:
      "Release processed successfully",

    submission: finalSubmission,

    package: {
      id: packageId,
      status: "ready",
      package_version: "1.0"
    },

    next_step:
      "Distribution package is ready for delivery"
  });
}

// ============================================================
// GET /v1/submissions/:submission_id
// Get submission details
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/submissions/") &&
  !url.pathname.endsWith("/package") &&
  !url.pathname.endsWith("/process")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const submissionId = parts[3];

  if (!submissionId) {
    return json(
      {
        success: false,
        error: "Submission ID is required"
      },
      400
    );
  }

  const submission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      submissionId,
      auth.sub
    )
    .first();

  if (!submission) {
    return json(
      {
        success: false,
        error: "Submission not found"
      },
      404
    );
  }

  const release = await env.DB
    .prepare(`
      SELECT
        id,
        title,
        release_type,
        artist_id,
        release_date,
        status
      FROM releases
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      submission.release_id,
      auth.sub
    )
    .first();

  const packageRecord = await env.DB
    .prepare(`
      SELECT
        id,
        package_version,
        status,
        created_at,
        updated_at
      FROM distribution_packages
      WHERE submission_id = ?
      LIMIT 1
    `)
    .bind(submissionId)
    .first();

  return json({
    success: true,

    submission,

    release,

    package: packageRecord || null
  });
}

// ============================================================
// GET /v1/submissions/:submission_id/package
// Get generated distribution package
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/submissions/") &&
  url.pathname.endsWith("/package")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const submissionId = parts[3];

  if (!submissionId) {
    return json(
      {
        success: false,
        error: "Submission ID is required"
      },
      400
    );
  }

  const submission = await env.DB
    .prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
    .bind(
      submissionId,
      auth.sub
    )
    .first();

  if (!submission) {
    return json(
      {
        success: false,
        error: "Submission not found"
      },
      404
    );
  }

  const packageRecord = await env.DB
    .prepare(`
      SELECT *
      FROM distribution_packages
      WHERE submission_id = ?
      LIMIT 1
    `)
    .bind(submissionId)
    .first();

  if (!packageRecord) {
    return json(
      {
        success: false,
        error: "Distribution package not found"
      },
      404
    );
  }

  let metadata;

  try {
    metadata = JSON.parse(
      packageRecord.metadata_json
    );
  } catch (error) {
    return json(
      {
        success: false,
        error: "Distribution package metadata is invalid"
      },
      500
    );
  }

  return json({
    success: true,

    package: {
      id: packageRecord.id,
      submission_id: packageRecord.submission_id,
      release_id: packageRecord.release_id,
      package_version: packageRecord.package_version,
      status: packageRecord.status,
      created_at: packageRecord.created_at,
      updated_at: packageRecord.updated_at
    },

    metadata
  });
}

if (
  request.method === "POST" &&
  url.pathname.startsWith("/v1/submissions/") &&
  url.pathname.endsWith("/deliver")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const submissionId = parts[3];

  if (!submissionId) {
    return json(
      {
        success: false,
        error: "Submission ID is required"
      },
      400
    );
  }

  // IMPORTANT:
  // Your JWT may use "userId" instead of "user_id".
  // Support both.
  const userId = auth.sub || auth.user_id || auth.userId || auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  try {
    // 1. Get submission
    const submission = await env.DB.prepare(`
      SELECT *
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(submissionId, userId)
      .first();

    if (!submission) {
      return json(
        {
          success: false,
          error: "Submission not found"
        },
        404
      );
    }

    // 2. Submission must be ready
    if (submission.status !== "ready") {
      return json(
        {
          success: false,
          error: "Submission is not ready for delivery",
          current_status: submission.status
        },
        409
      );
    }

    // 3. Find distribution package
    const packageRow = await env.DB.prepare(`
      SELECT *
      FROM distribution_packages
      WHERE submission_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `)
      .bind(submissionId)
      .first();

    if (!packageRow) {
      return json(
        {
          success: false,
          error: "Distribution package not found"
        },
        409
      );
    }

    // 4. Platforms
    const platforms = [
      "spotify",
      "apple_music",
      "youtube_music",
      "amazon_music",
      "deezer",
      "tiktok_music"
    ];

    const createdJobs = [];

    // 5. Create delivery jobs
    for (const platform of platforms) {
      const existingJob = await env.DB.prepare(`
        SELECT *
        FROM delivery_jobs
        WHERE submission_id = ?
          AND platform = ?
        LIMIT 1
      `)
        .bind(submissionId, platform)
        .first();

      if (existingJob) {
        createdJobs.push(existingJob);
        continue;
      }

      const jobId = `delivery_${crypto.randomUUID()}`;

      await env.DB.prepare(`
        INSERT INTO delivery_jobs (
          id,
          submission_id,
          release_id,
          user_id,
          platform,
          status,
          retry_count
        )
        VALUES (?, ?, ?, ?, ?, 'pending', 0)
      `)
        .bind(
          jobId,
          submission.id,
          submission.release_id,
          userId,
          platform
        )
        .run();

      const newJob = await env.DB.prepare(`
        SELECT *
        FROM delivery_jobs
        WHERE id = ?
        LIMIT 1
      `)
        .bind(jobId)
        .first();

      createdJobs.push(newJob);
    }

    // 6. Update submission
    await env.DB.prepare(`
      UPDATE release_submissions
      SET
        status = 'delivering',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(submissionId, userId)
      .run();

    // 7. Update release
    await env.DB.prepare(`
      UPDATE releases
      SET
        status = 'delivering',
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(submission.release_id, userId)
      .run();

    return json(
      {
        success: true,
        message: "Delivery jobs created successfully",

        submission: {
          id: submission.id,
          release_id: submission.release_id,
          status: "delivering"
        },

        package: {
          id: packageRow.id,
          package_version: packageRow.package_version,
          status: packageRow.status
        },

        delivery_jobs: createdJobs,

        next_step:
          "Delivery jobs are queued for platform-specific delivery"
      },
      201
    );

  } catch (error) {
    console.error("Delivery creation error:", error);

    return json(
      {
        success: false,
        error: "Failed to create delivery jobs",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// GET /v1/submissions/:submission_id/delivery
if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/submissions/") &&
  url.pathname.endsWith("/delivery")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId = auth.sub || auth.user_id || auth.userId || auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const submissionId = parts[3];

  if (!submissionId) {
    return json(
      {
        success: false,
        error: "Submission ID is required"
      },
      400
    );
  }

  try {
    // Verify submission belongs to user
    const submission = await env.DB.prepare(`
      SELECT
        id,
        release_id,
        user_id,
        status,
        submitted_at,
        started_at,
        completed_at,
        error_code,
        error_message,
        retry_count,
        created_at,
        updated_at
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(submissionId, userId)
      .first();

    if (!submission) {
      return json(
        {
          success: false,
          error: "Submission not found"
        },
        404
      );
    }

    // Get release
    const release = await env.DB.prepare(`
      SELECT
        id,
        title,
        release_type,
        artist_id,
        release_date,
        status
      FROM releases
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(submission.release_id, userId)
      .first();

    // Get delivery jobs
    const jobsResult = await env.DB.prepare(`
      SELECT
        id,
        submission_id,
        release_id,
        user_id,
        platform,
        status,
        external_id,
        submitted_at,
        delivered_at,
        error_code,
        error_message,
        retry_count,
        created_at,
        updated_at
      FROM delivery_jobs
      WHERE submission_id = ?
        AND user_id = ?
      ORDER BY created_at ASC
    `)
      .bind(submissionId, userId)
      .all();

    const jobs = jobsResult.results || [];

    // Count statuses
    const summary = {
      total: jobs.length,
      pending: 0,
      delivering: 0,
      delivered: 0,
      failed: 0
    };

    for (const job of jobs) {
      if (job.status === "pending") summary.pending++;
      else if (job.status === "delivering") summary.delivering++;
      else if (job.status === "delivered") summary.delivered++;
      else if (job.status === "failed") summary.failed++;
    }

    return json({
      success: true,

      submission: {
        id: submission.id,
        release_id: submission.release_id,
        status: submission.status,
        submitted_at: submission.submitted_at,
        started_at: submission.started_at,
        completed_at: submission.completed_at,
        error_code: submission.error_code,
        error_message: submission.error_message,
        retry_count: submission.retry_count,
        created_at: submission.created_at,
        updated_at: submission.updated_at
      },

      release,

      summary,

      delivery_jobs: jobs
    });

  } catch (error) {
    console.error("Get delivery jobs error:", error);

    return json(
      {
        success: false,
        error: "Failed to retrieve delivery jobs",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// POST /v1/delivery-jobs/:job_id/process
if (
  request.method === "POST" &&
  url.pathname.startsWith("/v1/delivery-jobs/") &&
  url.pathname.endsWith("/process")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId = auth.sub || auth.user_id || auth.userId || auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const jobId = parts[3];

  if (!jobId) {
    return json(
      {
        success: false,
        error: "Delivery job ID is required"
      },
      400
    );
  }

  try {
    // 1. Load job
    const job = await env.DB.prepare(`
      SELECT *
      FROM delivery_jobs
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(jobId, userId)
      .first();

    if (!job) {
      return json(
        {
          success: false,
          error: "Delivery job not found"
        },
        404
      );
    }

    // 2. Only pending or failed jobs can be processed
    if (job.status !== "pending" && job.status !== "failed") {
      return json(
        {
          success: false,
          error: "Delivery job cannot be processed in its current state",
          current_status: job.status
        },
        409
      );
    }

    // 3. Load distribution package
    const packageRow = await env.DB.prepare(`
      SELECT *
      FROM distribution_packages
      WHERE submission_id = ?
        AND release_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `)
      .bind(job.submission_id, job.release_id)
      .first();

    if (!packageRow) {
      return json(
        {
          success: false,
          error: "Distribution package not found"
        },
        409
      );
    }

    if (packageRow.status !== "ready") {
      return json(
        {
          success: false,
          error: "Distribution package is not ready",
          package_status: packageRow.status
        },
        409
      );
    }

    // 4. Parse package metadata
    let metadata;

    try {
      metadata = JSON.parse(packageRow.metadata_json);
    } catch (error) {
      return json(
        {
          success: false,
          error: "Distribution package metadata is invalid"
        },
        500
      );
    }

    // 5. Find platform adapter
    const integration = await getPlatformIntegration(
  env,
  job.platform
);

if (!integration) {
  return json(
    {
      success: false,
      error: "Platform integration not found",
      platform: job.platform,
      next_step: "Configure the platform integration first"
    },
    404
  );
}

if (!integration.enabled) {
  return json(
    {
      success: false,
      error: "Platform integration is disabled",
      platform: job.platform,
      integration: {
        id: integration.id,
        platform: integration.platform,
        enabled: Boolean(integration.enabled),
        mode: integration.mode,
        adapter_version: integration.adapter_version
      },
      next_step: "Enable the platform integration before attempting delivery"
    },
    409
  );
}

const adapter = getDeliveryAdapter(
  job.platform,
  integration.mode
);

if (!adapter) {
  return json(
    {
      success: false,
      error: "Platform delivery adapter is not configured",
      platform: job.platform,
      integration: {
        id: integration.id,
        platform: integration.platform,
        enabled: Boolean(integration.enabled),
        mode: integration.mode,
        adapter_version: integration.adapter_version
      },
      next_step: "Configure the platform adapter before attempting external delivery"
    },
    501
  );
}

    // 6. Mark job as delivering
    await env.DB.prepare(`
      UPDATE delivery_jobs
      SET
        status = 'delivering',
        submitted_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(jobId, userId)
      .run();

    // 7. Execute external platform adapter
    const result = await adapter({
      job,
      package: packageRow,
      metadata,
      env
    });

    // 8. Handle successful external response
    if (result && result.success === true) {
      await env.DB.prepare(`
        UPDATE delivery_jobs
        SET
          status = 'delivered',
          external_id = ?,
          delivered_at = CURRENT_TIMESTAMP,
          error_code = NULL,
          error_message = NULL,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
      `)
        .bind(
          result.external_id || null,
          jobId,
          userId
        )
        .run();

      // Update submission + release status based on all delivery jobs
      const parentStatus = await updateDeliveryParentStatus(
        env,
        job.submission_id,
        job.release_id
      );

      const updatedJob = await env.DB.prepare(`
        SELECT *
        FROM delivery_jobs
        WHERE id = ?
        LIMIT 1
      `)
        .bind(jobId)
        .first();

      return json({
        success: true,
        message: "Delivery completed successfully",
        job: updatedJob,
        delivery_summary: parentStatus
      });
    }

    // 9. Handle external failure
    await env.DB.prepare(`
      UPDATE delivery_jobs
      SET
        status = 'failed',
        error_code = ?,
        error_message = ?,
        retry_count = retry_count + 1,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(
        result?.error_code || "DELIVERY_FAILED",
        result?.error_message || "Platform delivery failed",
        jobId,
        userId
      )
      .run();

      const parentStatus = await updateDeliveryParentStatus(
        env,
        job.submission_id,
        job.release_id
      );

    const failedJob = await env.DB.prepare(`
      SELECT *
      FROM delivery_jobs
      WHERE id = ?
      LIMIT 1
    `)
      .bind(jobId)
      .first();

    return json(
      {
        success: false,
        error: "Platform delivery failed",
        job: failedJob,
        delivery_summary: parentStatus
      },
      502
    );

  } catch (error) {
    console.error("Delivery processing error:", error);

    // Try to record the failure
    try {
      await env.DB.prepare(`
        UPDATE delivery_jobs
        SET
          status = 'failed',
          error_code = 'PROCESSING_ERROR',
          error_message = ?,
          retry_count = retry_count + 1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND user_id = ?
      `)
        .bind(
          error?.message || String(error),
          jobId,
          userId
        )
        .run();
    } catch (dbError) {
      console.error("Failed to update delivery job:", dbError);
    }

    return json(
      {
        success: false,
        error: "Failed to process delivery job",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// GET /v1/delivery-jobs/:job_id
if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/delivery-jobs/")
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId = auth.sub || auth.user_id || auth.userId || auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  const parts = url.pathname.split("/");
  const jobId = parts[3];

  if (!jobId) {
    return json(
      {
        success: false,
        error: "Delivery job ID is required"
      },
      400
    );
  }

  try {
    const job = await env.DB.prepare(`
      SELECT
        id,
        submission_id,
        release_id,
        user_id,
        platform,
        status,
        external_id,
        submitted_at,
        delivered_at,
        error_code,
        error_message,
        retry_count,
        created_at,
        updated_at
      FROM delivery_jobs
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(jobId, userId)
      .first();

    if (!job) {
      return json(
        {
          success: false,
          error: "Delivery job not found"
        },
        404
      );
    }

    const submission = await env.DB.prepare(`
      SELECT
        id,
        release_id,
        status
      FROM release_submissions
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(job.submission_id, userId)
      .first();

    const release = await env.DB.prepare(`
      SELECT
        id,
        title,
        release_type,
        artist_id,
        release_date,
        status
      FROM releases
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(job.release_id, userId)
      .first();

    return json({
      success: true,

      job,

      submission,

      release
    });

  } catch (error) {
    console.error("Get delivery job error:", error);

    return json(
      {
        success: false,
        error: "Failed to retrieve delivery job",
        details: error?.message || String(error)
      },
      500
    );
  }
}

if (
  request.method === "GET" &&
  url.pathname === "/v1/platform-integrations"
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const result = await env.DB.prepare(`
    SELECT
      id,
      platform,
      enabled,
      mode,
      adapter_version,
      created_at,
      updated_at
    FROM platform_integrations
    ORDER BY platform ASC
  `).all();

  return json({
    success: true,
    integrations: result.results.map((integration) => ({
      ...integration,
      enabled: Boolean(integration.enabled)
    }))
  });
}

if (
  request.method === "GET" &&
  url.pathname.startsWith("/v1/platform-integrations/")
) {
  const platform = url.pathname.split("/").pop();

  if (!isValidPlatform(platform)) {
    return json(
      {
        success: false,
        error: "Unsupported platform"
      },
      400
    );
  }

  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const integration = await env.DB.prepare(`
    SELECT
      id,
      platform,
      enabled,
      mode,
      adapter_version,
      created_at,
      updated_at
    FROM platform_integrations
    WHERE platform = ?
    LIMIT 1
  `)
    .bind(platform)
    .first();

  if (!integration) {
    return json(
      {
        success: false,
        error: "Platform integration not found"
      },
      404
    );
  }

  return json({
    success: true,
    integration: {
      ...integration,
      enabled: Boolean(integration.enabled)
    }
  });
}

if (
  request.method === "PATCH" &&
  url.pathname.startsWith("/v1/platform-integrations/")
) {
  const platform = url.pathname.split("/").pop();

  if (!isValidPlatform(platform)) {
    return json(
      {
        success: false,
        error: "Unsupported platform"
      },
      400
    );
  }

  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "Authenticated user ID missing"
      },
      401
    );
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json(
      {
        success: false,
        error: "Invalid JSON body"
      },
      400
    );
  }

  const updates = [];

  const values = [];

  if (body.enabled !== undefined) {
    if (typeof body.enabled !== "boolean") {
      return json(
        {
          success: false,
          error: "enabled must be a boolean"
        },
        400
      );
    }

    updates.push("enabled = ?");
    values.push(body.enabled ? 1 : 0);
  }

  if (body.mode !== undefined) {
    if (!isValidIntegrationMode(body.mode)) {
      return json(
        {
          success: false,
          error: "mode must be either sandbox or production"
        },
        400
      );
    }

    updates.push("mode = ?");
    values.push(body.mode);
  }

  if (updates.length === 0) {
    return json(
      {
        success: false,
        error: "No valid fields to update"
      },
      400
    );
  }

  updates.push("updated_at = CURRENT_TIMESTAMP");

  values.push(platform);

  const result = await env.DB.prepare(`
    UPDATE platform_integrations
    SET ${updates.join(", ")}
    WHERE platform = ?
  `)
    .bind(...values)
    .run();

  if (!result.meta.changes) {
    return json(
      {
        success: false,
        error: "Platform integration not found"
      },
      404
    );
  }

  const integration = await env.DB.prepare(`
    SELECT
      id,
      platform,
      enabled,
      mode,
      adapter_version,
      created_at,
      updated_at
    FROM platform_integrations
    WHERE platform = ?
    LIMIT 1
  `)
    .bind(platform)
    .first();

  return json({
    success: true,
    message: "Platform integration updated",
    integration: {
      ...integration,
      enabled: Boolean(integration.enabled)
    }
  });
}

// POST /v1/analytics/events
if (
  request.method === "POST" &&
  url.pathname === "/v1/analytics/events"
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  try {
    const body = await request.json();

    const {
      release_id,
      track_id,
      platform,
      territory,
      event_type,
      streams,
      downloads,
      revenue_amount,
      currency,
      event_date,
      metadata
    } = body;

    // Required fields
    if (!platform) {
      return json(
        {
          success: false,
          error: "platform is required"
        },
        400
      );
    }

    if (!event_type) {
      return json(
        {
          success: false,
          error: "event_type is required"
        },
        400
      );
    }

    if (!event_date) {
      return json(
        {
          success: false,
          error: "event_date is required"
        },
        400
      );
    }

    // Validate date format
    if (!/^\d{4}-\d{2}-\d{2}$/.test(event_date)) {
      return json(
        {
          success: false,
          error: "event_date must use YYYY-MM-DD format"
        },
        400
      );
    }

    const allowedEventTypes = [
      "stream",
      "download",
      "revenue",
      "stream_download",
      "royalty"
    ];

    if (!allowedEventTypes.includes(event_type)) {
      return json(
        {
          success: false,
          error: "Invalid event_type",
          allowed_values: allowedEventTypes
        },
        400
      );
    }

    const allowedPlatforms = [
      "spotify",
      "apple_music",
      "youtube_music",
      "amazon_music",
      "deezer",
      "tiktok_music"
    ];

    if (!allowedPlatforms.includes(platform)) {
      return json(
        {
          success: false,
          error: "Invalid platform",
          allowed_values: allowedPlatforms
        },
        400
      );
    }

    // Verify release ownership if supplied
    if (release_id) {
      const release = await env.DB.prepare(`
        SELECT id
        FROM releases
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
        .bind(release_id, userId)
        .first();

      if (!release) {
        return json(
          {
            success: false,
            error: "Release not found"
          },
          404
        );
      }
    }

    // Verify track ownership if supplied
    if (track_id) {
      const track = await env.DB.prepare(`
        SELECT
          tracks.id
        FROM tracks
        INNER JOIN releases
          ON releases.id = tracks.release_id
        WHERE tracks.id = ?
          AND releases.user_id = ?
        LIMIT 1
      `)
        .bind(track_id, userId)
        .first();

      if (!track) {
        return json(
          {
            success: false,
            error: "Track not found"
          },
          404
        );
      }
    }

    const streamsValue = Number.isFinite(Number(streams))
      ? Number(streams)
      : 0;

    const downloadsValue = Number.isFinite(Number(downloads))
      ? Number(downloads)
      : 0;

    const revenueValue = Number.isFinite(Number(revenue_amount))
      ? Number(revenue_amount)
      : 0;

    if (streamsValue < 0) {
      return json(
        {
          success: false,
          error: "streams cannot be negative"
        },
        400
      );
    }

    if (downloadsValue < 0) {
      return json(
        {
          success: false,
          error: "downloads cannot be negative"
        },
        400
      );
    }

    if (revenueValue < 0) {
      return json(
        {
          success: false,
          error: "revenue_amount cannot be negative"
        },
        400
      );
    }

    const eventId =
      `analytics_${crypto.randomUUID()}`;

    await env.DB.prepare(`
      INSERT INTO analytics_events (
        id,
        user_id,
        release_id,
        track_id,
        platform,
        territory,
        event_type,
        streams,
        downloads,
        revenue_amount,
        currency,
        event_date,
        metadata_json
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `)
      .bind(
        eventId,
        userId,
        release_id || null,
        track_id || null,
        platform,
        territory || null,
        event_type,
        streamsValue,
        downloadsValue,
        revenueValue,
        currency || "USD",
        event_date,
        metadata
          ? JSON.stringify(metadata)
          : null
      )
      .run();

    const event = await env.DB.prepare(`
      SELECT *
      FROM analytics_events
      WHERE id = ?
      LIMIT 1
    `)
      .bind(eventId)
      .first();

    return json(
      {
        success: true,
        message: "Analytics event recorded",
        event
      },
      201
    );

  } catch (error) {
    console.error(
      "Analytics event error:",
      error
    );

    return json(
      {
        success: false,
        error: "Failed to record analytics event",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// POST /v1/analytics/aggregate
if (
  request.method === "POST" &&
  url.pathname === "/v1/analytics/aggregate"
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  try {
    const body = await request.json();

    const { event_id } = body;

    if (!event_id) {
      return json(
        {
          success: false,
          error: "event_id is required"
        },
        400
      );
    }

    const event = await env.DB.prepare(`
      SELECT *
      FROM analytics_events
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `).bind(
      event_id,
      userId
    ).first();

    if (!event) {
      return json(
        {
          success: false,
          error: "Analytics event not found"
        },
        404
      );
    }

    const result =
      await aggregateAnalyticsEvent(env, event_id);

    return json(
      {
        success: true,
        message: "Analytics event aggregated successfully",
        result
      },
      200
    );

  } catch (error) {
    console.error(
      "Analytics aggregation error:",
      error
    );

    return json(
      {
        success: false,
        error: "Failed to aggregate analytics event",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// GET /v1/analytics/overview
if (
  request.method === "GET" &&
  url.pathname === "/v1/analytics/overview"
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  try {
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const releaseId = url.searchParams.get("release_id");
    const trackId = url.searchParams.get("track_id");
    const platform = url.searchParams.get("platform");
    const territory = url.searchParams.get("territory");

    /*
     * ---------------------------------------------------------
     * Validate dates
     * ---------------------------------------------------------
     */

    if (from && !/^\d{4}-\d{2}-\d{2}$/.test(from)) {
      return json(
        {
          success: false,
          error: "from must use YYYY-MM-DD format"
        },
        400
      );
    }

    if (to && !/^\d{4}-\d{2}-\d{2}$/.test(to)) {
      return json(
        {
          success: false,
          error: "to must use YYYY-MM-DD format"
        },
        400
      );
    }

    if (from && to && from > to) {
      return json(
        {
          success: false,
          error: "from cannot be later than to"
        },
        400
      );
    }

    /*
     * ---------------------------------------------------------
     * Build analytics_daily query
     * ---------------------------------------------------------
     */

    let where = `
      WHERE user_id = ?
    `;

    const params = [userId];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    if (releaseId) {
      where += ` AND release_id = ?`;
      params.push(releaseId);
    }

    if (trackId) {
      where += ` AND track_id = ?`;
      params.push(trackId);
    }

    if (platform) {
      where += ` AND platform = ?`;
      params.push(platform);
    }

    if (territory) {
      where += ` AND territory = ?`;
      params.push(territory);
    }

    /*
     * ---------------------------------------------------------
     * Aggregate totals
     * ---------------------------------------------------------
     */

    const totals = await env.DB.prepare(`
      SELECT
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue
      FROM analytics_daily
      ${where}
    `).bind(...params).first();

    const tracksResult = await env.DB.prepare(`
      SELECT COUNT(DISTINCT track_id) AS count
      FROM analytics_daily
      ${where}
      AND track_id IS NOT NULL
    `).bind(...params).first();

    /*
     * ---------------------------------------------------------
     * Count releases
     * ---------------------------------------------------------
     */

    const releasesResult = await env.DB.prepare(`
      SELECT COUNT(DISTINCT release_id) AS count
      FROM analytics_daily
      ${where}
      AND release_id IS NOT NULL
    `).bind(...params).first();

    /*
     * ---------------------------------------------------------
     * Count platforms
     * ---------------------------------------------------------
     */

    const platformsResult = await env.DB.prepare(`
      SELECT COUNT(DISTINCT platform) AS count
      FROM analytics_daily
      ${where}
      AND platform IS NOT NULL
    `).bind(...params).first();

    /*
     * ---------------------------------------------------------
     * Count territories
     * ---------------------------------------------------------
     */

    const territoriesResult = await env.DB.prepare(`
      SELECT COUNT(DISTINCT territory) AS count
      FROM analytics_daily
      ${where}
      AND territory IS NOT NULL
    `).bind(...params).first();

    /*
     * ---------------------------------------------------------
     * Response
     * ---------------------------------------------------------
     */

    return json({
      success: true,

      overview: {
        streams: Number(totals?.streams || 0),
        downloads: Number(totals?.downloads || 0),
        revenue: Number(totals?.revenue || 0),
        currency: "USD",

        tracks: Number(tracksResult?.count || 0),
        releases: Number(releasesResult?.count || 0),
        platforms: Number(platformsResult?.count || 0),
        territories: Number(territoriesResult?.count || 0)
      },

      filters: {
        from: from || null,
        to: to || null,
        release_id: releaseId || null,
        track_id: trackId || null,
        platform: platform || null,
        territory: territory || null
      }
    });

  } catch (error) {
    console.error(
      "Analytics overview error:",
      error
    );

    return json(
      {
        success: false,
        error: "Failed to load analytics overview",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// GET /v1/analytics/tracks
if (
  request.method === "GET" &&
  url.pathname === "/v1/analytics/tracks"
) {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "User ID missing from authentication token"
      },
      401
    );
  }

  try {
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const releaseId = url.searchParams.get("release_id");
    const platform = url.searchParams.get("platform");

    let limit = Number(url.searchParams.get("limit") || 50);
    let offset = Number(url.searchParams.get("offset") || 0);

    if (!Number.isInteger(limit) || limit < 1) {
      return json(
        {
          success: false,
          error: "limit must be a positive integer"
        },
        400
      );
    }

    if (limit > 100) {
      limit = 100;
    }

    if (!Number.isInteger(offset) || offset < 0) {
      return json(
        {
          success: false,
          error: "offset must be a non-negative integer"
        },
        400
      );
    }

    /*
     * ---------------------------------------------------------
     * Validate dates
     * ---------------------------------------------------------
     */

    if (from && !/^\d{4}-\d{2}-\d{2}$/.test(from)) {
      return json(
        {
          success: false,
          error: "from must use YYYY-MM-DD format"
        },
        400
      );
    }

    if (to && !/^\d{4}-\d{2}-\d{2}$/.test(to)) {
      return json(
        {
          success: false,
          error: "to must use YYYY-MM-DD format"
        },
        400
      );
    }

    if (from && to && from > to) {
      return json(
        {
          success: false,
          error: "from cannot be later than to"
        },
        400
      );
    }

    /*
     * ---------------------------------------------------------
     * Build query
     *
     * We use analytics_daily here instead of analytics_tracks
     * because date/platform filters must be respected.
     * ---------------------------------------------------------
     */

    let where = `
      WHERE ad.user_id = ?
        AND ad.track_id IS NOT NULL
    `;

    const params = [userId];

    if (from) {
      where += ` AND ad.event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND ad.event_date <= ?`;
      params.push(to);
    }

    if (releaseId) {
      where += ` AND ad.release_id = ?`;
      params.push(releaseId);
    }

    if (platform) {
      where += ` AND ad.platform = ?`;
      params.push(platform);
    }

    /*
     * ---------------------------------------------------------
     * Count total tracks
     * ---------------------------------------------------------
     */

    const countResult = await env.DB.prepare(`
      SELECT COUNT(*) AS count
      FROM (
        SELECT ad.track_id
        FROM analytics_daily ad
        ${where}
        GROUP BY ad.track_id
      )
    `).bind(...params).first();

    const total = Number(countResult?.count || 0);

    /*
     * ---------------------------------------------------------
     * Track analytics
     * ---------------------------------------------------------
     */

    const tracksResult = await env.DB.prepare(`
      SELECT
        ad.track_id,
        ad.release_id,

        COALESCE(t.title, 'Unknown Track') AS title,
        t.version,
        t.isrc,
        t.track_number,
        t.disc_number,

        COALESCE(r.title, 'Unknown Release') AS release_title,

        COALESCE(SUM(ad.streams), 0) AS streams,
        COALESCE(SUM(ad.downloads), 0) AS downloads,
        COALESCE(SUM(ad.revenue_amount), 0) AS revenue,

        MAX(ad.event_date) AS last_stream_date,

        COUNT(DISTINCT ad.platform) AS platform_count,
        COUNT(DISTINCT ad.territory) AS territory_count

      FROM analytics_daily ad

      LEFT JOIN tracks t
        ON t.id = ad.track_id

      LEFT JOIN releases r
        ON r.id = ad.release_id

      ${where}

      GROUP BY
        ad.track_id,
        ad.release_id,
        t.title,
        t.version,
        t.isrc,
        t.track_number,
        t.disc_number,
        r.title

      ORDER BY streams DESC

      LIMIT ? OFFSET ?
    `).bind(
      ...params,
      limit,
      offset
    ).all();

    /*
     * ---------------------------------------------------------
     * Format response
     * ---------------------------------------------------------
     */

    const tracks = (tracksResult.results || []).map(track => ({
      track_id: track.track_id,
      release_id: track.release_id,

      title: track.title,
      version: track.version || null,
      isrc: track.isrc || null,

      track_number:
        track.track_number !== null
          ? Number(track.track_number)
          : null,

      disc_number:
        track.disc_number !== null
          ? Number(track.disc_number)
          : null,

      release_title: track.release_title,

      streams: Number(track.streams || 0),
      downloads: Number(track.downloads || 0),
      revenue: Number(track.revenue || 0),

      currency: "USD",

      last_stream_date:
        track.last_stream_date || null,

      platform_count:
        Number(track.platform_count || 0),

      territory_count:
        Number(track.territory_count || 0)
    }));

    return json({
      success: true,

      tracks,

      pagination: {
        total,
        limit,
        offset,
        returned: tracks.length,
        has_more: offset + tracks.length < total
      },

      filters: {
        from: from || null,
        to: to || null,
        release_id: releaseId || null,
        platform: platform || null
      }
    });

  } catch (error) {
    console.error(
      "Analytics tracks error:",
      error
    );

    return json(
      {
        success: false,
        error: "Failed to load track analytics",
        details: error?.message || String(error)
      },
      500
    );
  }
}

// GET /v1/analytics/tracks/charts
if (url.pathname === "/v1/analytics/tracks/charts" && request.method === "GET") {
  const token = getBearerToken(request);

  if (!token) {
    return json(
      {
        success: false,
        error: "Authorization required"
      },
      401
    );
  }

  const auth = await verifyToken(token, env.JWT_SECRET);

  if (!auth) {
    return json(
      {
        success: false,
        error: "Invalid or expired token"
      },
      401
    );
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return json(
      {
        success: false,
        error: "Invalid authentication payload"
      },
      401
    );
  }

  const trackId = url.searchParams.get("track_id");
  const releaseId = url.searchParams.get("release_id");
  const from = url.searchParams.get("from");
  const to = url.searchParams.get("to");
  const platform = url.searchParams.get("platform");
  const territory = url.searchParams.get("territory");

  // -----------------------------
  // Validate dates
  // -----------------------------

  const isValidDate = (value) => {
    if (!value) return true;

    if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
      return false;
    }

    const date = new Date(`${value}T00:00:00Z`);

    return !Number.isNaN(date.getTime()) &&
      date.toISOString().slice(0, 10) === value;
  };

  if (!isValidDate(from)) {
    return json(
      {
        success: false,
        error: "Invalid from date. Use YYYY-MM-DD."
      },
      400
    );
  }

  if (!isValidDate(to)) {
    return json(
      {
        success: false,
        error: "Invalid to date. Use YYYY-MM-DD."
      },
      400
    );
  }

  if (from && to && from > to) {
    return json(
      {
        success: false,
        error: "from date cannot be later than to date"
      },
      400
    );
  }

  // -----------------------------
  // Validate platform
  // -----------------------------

  const allowedPlatforms = [
    "spotify",
    "apple_music",
    "youtube_music",
    "amazon_music",
    "deezer",
    "tiktok_music"
  ];

  if (platform && !allowedPlatforms.includes(platform)) {
    return json(
      {
        success: false,
        error: "Invalid platform",
        allowed_platforms: allowedPlatforms
      },
      400
    );
  }

  // -----------------------------
  // Validate track ownership
  // -----------------------------

  if (trackId) {
    const trackResult = await env.DB.prepare(`
      SELECT
        t.id,
        t.release_id,
        t.title,
        t.version,
        t.isrc,
        r.title AS release_title
      FROM tracks t
      JOIN releases r
        ON r.id = t.release_id
      WHERE t.id = ?
        AND r.user_id = ?
      LIMIT 1
    `)
      .bind(trackId, userId)
      .first();

    if (!trackResult) {
      return json(
        {
          success: false,
          error: "Track not found"
        },
        404
      );
    }
  }

  // -----------------------------
  // Validate release ownership
  // -----------------------------

  if (releaseId) {
    const releaseResult = await env.DB.prepare(`
      SELECT id, title
      FROM releases
      WHERE id = ?
        AND user_id = ?
      LIMIT 1
    `)
      .bind(releaseId, userId)
      .first();

    if (!releaseResult) {
      return json(
        {
          success: false,
          error: "Release not found"
        },
        404
      );
    }
  }

  // -----------------------------
  // Build query
  // -----------------------------

  let query = `
    SELECT
      event_date AS date,
      SUM(streams) AS streams,
      SUM(downloads) AS downloads,
      SUM(revenue_amount) AS revenue
    FROM analytics_daily
    WHERE user_id = ?
  `;

  const params = [userId];

  if (trackId) {
    query += ` AND track_id = ?`;
    params.push(trackId);
  }

  if (releaseId) {
    query += ` AND release_id = ?`;
    params.push(releaseId);
  }

  if (from) {
    query += ` AND event_date >= ?`;
    params.push(from);
  }

  if (to) {
    query += ` AND event_date <= ?`;
    params.push(to);
  }

  if (platform) {
    query += ` AND platform = ?`;
    params.push(platform);
  }

  if (territory) {
    query += ` AND territory = ?`;
    params.push(territory.toUpperCase());
  }

  query += `
    GROUP BY event_date
    ORDER BY event_date ASC
  `;

  const result = await env.DB
    .prepare(query)
    .bind(...params)
    .all();

  const rows = result.results || [];

  // -----------------------------
  // Format chart data
  // -----------------------------

  const data = rows.map((row) => ({
    date: row.date,
    streams: Number(row.streams || 0),
    downloads: Number(row.downloads || 0),
    revenue: Number(row.revenue || 0)
  }));

  // -----------------------------
  // Calculate totals
  // -----------------------------

  const totals = data.reduce(
    (acc, row) => {
      acc.streams += row.streams;
      acc.downloads += row.downloads;
      acc.revenue += row.revenue;

      return acc;
    },
    {
      streams: 0,
      downloads: 0,
      revenue: 0
    }
  );

  // Keep revenue clean for JSON
  totals.revenue = Number(totals.revenue.toFixed(2));

  return json({
    success: true,

    chart: {
      metric: "streams",

      data,

      totals: {
        streams: totals.streams,
        downloads: totals.downloads,
        revenue: totals.revenue,
        currency: "USD"
      },

      days: data.length
    },

    filters: {
      track_id: trackId,
      release_id: releaseId,
      from,
      to,
      platform,
      territory: territory ? territory.toUpperCase() : null
    }
  });
}

// GET /v1/analytics/tracks/:isrc
if (
  url.pathname.startsWith("/v1/analytics/tracks/") &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    // --------------------------------
    // Get ISRC
    // --------------------------------

    const isrc = decodeURIComponent(
      url.pathname
        .replace("/v1/analytics/tracks/", "")
        .trim()
    )
      .replace(/-/g, "")
      .toUpperCase();

    if (!isrc) {
      return json(
        {
          success: false,
          error: "ISRC is required"
        },
        400
      );
    }

    // --------------------------------
    // Validate ISRC
    // --------------------------------

    if (!/^[A-Z]{2}[A-Z0-9]{3}[0-9]{2}[0-9]{5}$/.test(isrc)) {
      return json(
        {
          success: false,
          error: "Invalid ISRC format"
        },
        400
      );
    }

    // --------------------------------
    // Find track
    // --------------------------------

    const track = await env.DB.prepare(`
      SELECT
        t.id,
        t.release_id,
        t.title,
        t.version,
        t.isrc,
        t.track_number,
        t.disc_number,
        t.duration_seconds,
        t.genre,
        t.language,
        t.explicit,

        r.title AS release_title,
        r.release_type,
        r.release_date,
        r.artist_id,

        a.name AS artist_name

      FROM tracks t

      INNER JOIN releases r
        ON r.id = t.release_id

      LEFT JOIN artists a
        ON a.id = r.artist_id

      WHERE t.isrc = ?
        AND r.user_id = ?

      LIMIT 1
    `)
      .bind(isrc, userId)
      .first();

    if (!track) {
      return json(
        {
          success: false,
          error: "Track not found",
          isrc
        },
        404
      );
    }

    // --------------------------------
    // Filters
    // --------------------------------

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const platform = url.searchParams.get("platform");
    const territory = url.searchParams.get("territory");

    const isValidDate = (value) => {
      if (!value) return true;

      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        return false;
      }

      const date = new Date(`${value}T00:00:00Z`);

      return (
        !Number.isNaN(date.getTime()) &&
        date.toISOString().slice(0, 10) === value
      );
    };

    if (!isValidDate(from)) {
      return json(
        {
          success: false,
          error: "Invalid from date. Use YYYY-MM-DD."
        },
        400
      );
    }

    if (!isValidDate(to)) {
      return json(
        {
          success: false,
          error: "Invalid to date. Use YYYY-MM-DD."
        },
        400
      );
    }

    if (from && to && from > to) {
      return json(
        {
          success: false,
          error: "from date cannot be later than to date"
        },
        400
      );
    }

    const allowedPlatforms = [
      "spotify",
      "apple_music",
      "youtube_music",
      "amazon_music",
      "deezer",
      "tiktok_music"
    ];

    if (
      platform &&
      !allowedPlatforms.includes(platform)
    ) {
      return json(
        {
          success: false,
          error: "Invalid platform",
          allowed_platforms: allowedPlatforms
        },
        400
      );
    }

    // --------------------------------
    // Build WHERE
    // --------------------------------

    let where = `
      user_id = ?
      AND track_id = ?
    `;

    const params = [
      userId,
      track.id
    ];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    if (platform) {
      where += ` AND platform = ?`;
      params.push(platform);
    }

    if (territory) {
      where += ` AND territory = ?`;
      params.push(territory.toUpperCase());
    }

    // --------------------------------
    // TOTALS
    // --------------------------------

    const totals = await env.DB.prepare(`
      SELECT
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue,
        COUNT(DISTINCT platform) AS platform_count,
        COUNT(DISTINCT territory) AS territory_count,
        MIN(event_date) AS first_event_date,
        MAX(event_date) AS last_event_date
      FROM analytics_daily
      WHERE ${where}
    `)
      .bind(...params)
      .first();

    // --------------------------------
    // PLATFORM BREAKDOWN
    // --------------------------------

    const platformResult = await env.DB.prepare(`
      SELECT
        platform,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue
      FROM analytics_daily
      WHERE ${where}
      GROUP BY platform
      ORDER BY streams DESC
    `)
      .bind(...params)
      .all();

    const platforms = (platformResult.results || []).map((row) => ({
      platform: row.platform,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      )
    }));

    // --------------------------------
    // TERRITORY BREAKDOWN
    // --------------------------------

    const territoryResult = await env.DB.prepare(`
      SELECT
        territory,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue
      FROM analytics_daily
      WHERE ${where}
        AND territory IS NOT NULL
        AND territory != ''
      GROUP BY territory
      ORDER BY streams DESC
    `)
      .bind(...params)
      .all();

    const territories = (territoryResult.results || []).map((row) => ({
      territory: row.territory,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      )
    }));

    // --------------------------------
    // DAILY DATA
    // --------------------------------

    const dailyResult = await env.DB.prepare(`
      SELECT
        event_date AS date,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue
      FROM analytics_daily
      WHERE ${where}
      GROUP BY event_date
      ORDER BY event_date ASC
    `)
      .bind(...params)
      .all();

    const daily = (dailyResult.results || []).map((row) => ({
      date: row.date,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      )
    }));

    // --------------------------------
    // RESPONSE
    // --------------------------------

    return json({
      success: true,

      track: {
        id: track.id,
        isrc: track.isrc,
        title: track.title,
        version: track.version,
        track_number: Number(track.track_number || 0),
        disc_number: Number(track.disc_number || 0),
        duration_seconds: Number(
          track.duration_seconds || 0
        ),
        genre: track.genre,
        language: track.language,
        explicit: Boolean(track.explicit)
      },

      release: {
        id: track.release_id,
        title: track.release_title,
        type: track.release_type,
        release_date: track.release_date,
        artist_name: track.artist_name,
      },

      analytics: {
        streams: Number(totals?.streams || 0),
        downloads: Number(totals?.downloads || 0),
        revenue: Number(
          Number(totals?.revenue || 0).toFixed(2)
        ),
        currency: "USD",
        platforms: Number(
          totals?.platform_count || 0
        ),
        territories: Number(
          totals?.territory_count || 0
        ),
        first_event_date:
          totals?.first_event_date || null,
        last_event_date:
          totals?.last_event_date || null
      },

      platforms,

      territories,

      daily,

      filters: {
        from: from || null,
        to: to || null,
        platform: platform || null,
        territory: territory
          ? territory.toUpperCase()
          : null
      }
    });

  } catch (error) {

    console.error(
      "GET /v1/analytics/tracks/:isrc error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

if (
  url.pathname === "/v1/analytics/platforms" &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");

    const isValidDate = (value) => {
      if (!value) return true;

      if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
        return false;
      }

      const date = new Date(`${value}T00:00:00Z`);

      return (
        !Number.isNaN(date.getTime()) &&
        date.toISOString().slice(0, 10) === value
      );
    };

    if (!isValidDate(from)) {
      return json(
        {
          success: false,
          error: "Invalid from date. Use YYYY-MM-DD."
        },
        400
      );
    }

    if (!isValidDate(to)) {
      return json(
        {
          success: false,
          error: "Invalid to date. Use YYYY-MM-DD."
        },
        400
      );
    }

    if (from && to && from > to) {
      return json(
        {
          success: false,
          error: "from date cannot be later than to date"
        },
        400
      );
    }

    // Use analytics_daily when date filters are supplied.
    // This ensures the numbers respect the selected period.

    let where = `user_id = ?`;
    const params = [userId];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    const result = await env.DB.prepare(`
      SELECT
        platform,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue,
        MIN(event_date) AS first_event_date,
        MAX(event_date) AS last_event_date
      FROM analytics_daily
      WHERE ${where}
      GROUP BY platform
      ORDER BY streams DESC
    `)
      .bind(...params)
      .all();

    const platforms = (result.results || []).map((row) => ({
      platform: row.platform,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      ),
      first_event_date: row.first_event_date || null,
      last_event_date: row.last_event_date || null
    }));

    const totals = platforms.reduce(
      (acc, platform) => {
        acc.streams += platform.streams;
        acc.downloads += platform.downloads;
        acc.revenue += platform.revenue;
        return acc;
      },
      {
        streams: 0,
        downloads: 0,
        revenue: 0
      }
    );

    totals.revenue = Number(
      totals.revenue.toFixed(2)
    );

    return json({
      success: true,

      platforms,

      totals: {
        streams: totals.streams,
        downloads: totals.downloads,
        revenue: totals.revenue,
        platforms: platforms.length,
        currency: "USD"
      },

      filters: {
        from: from || null,
        to: to || null
      }
    });

  } catch (error) {
    console.error(
      "GET /v1/analytics/platforms error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

if (
  url.pathname === "/v1/analytics/platforms/data" &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const platform = url.searchParams.get("platform");

    let where = `user_id = ?`;
    const params = [userId];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    if (platform) {
      where += ` AND platform = ?`;
      params.push(platform);
    }

    const result = await env.DB.prepare(`
      SELECT
        event_date AS date,
        platform,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue
      FROM analytics_daily
      WHERE ${where}
      GROUP BY event_date, platform
      ORDER BY event_date ASC, streams DESC
    `)
      .bind(...params)
      .all();

    const data = (result.results || []).map((row) => ({
      date: row.date,
      platform: row.platform,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      )
    }));

    return json({
      success: true,

      data,

      filters: {
        from: from || null,
        to: to || null,
        platform: platform || null
      }
    });

  } catch (error) {
    console.error(
      "GET /v1/analytics/platforms/data error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

if (
  url.pathname === "/v1/analytics/platforms/total-streams" &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");

    let where = `user_id = ?`;
    const params = [userId];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    const result = await env.DB.prepare(`
      SELECT
        platform,
        COALESCE(SUM(streams), 0) AS streams
      FROM analytics_daily
      WHERE ${where}
      GROUP BY platform
      ORDER BY streams DESC
    `)
      .bind(...params)
      .all();

    const platforms = (result.results || []).map((row) => ({
      platform: row.platform,
      streams: Number(row.streams || 0)
    }));

    const totalStreams = platforms.reduce(
      (total, row) => total + row.streams,
      0
    );

    return json({
      success: true,

      total_streams: totalStreams,

      platforms,

      filters: {
        from: from || null,
        to: to || null
      }
    });

  } catch (error) {
    console.error(
      "GET /v1/analytics/platforms/total-streams error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

if (
  url.pathname === "/v1/analytics/platforms/additional" &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");

    let where = `user_id = ?`;
    const params = [userId];

    if (from) {
      where += ` AND event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND event_date <= ?`;
      params.push(to);
    }

    const result = await env.DB.prepare(`
      SELECT
        platform,
        COALESCE(SUM(streams), 0) AS streams,
        COALESCE(SUM(downloads), 0) AS downloads,
        COALESCE(SUM(revenue_amount), 0) AS revenue,
        COUNT(DISTINCT track_id) AS tracks,
        COUNT(DISTINCT territory) AS territories,
        COUNT(DISTINCT event_date) AS active_days
      FROM analytics_daily
      WHERE ${where}
      GROUP BY platform
      ORDER BY streams DESC
    `)
      .bind(...params)
      .all();

    const rows = result.results || [];

    const totalStreams = rows.reduce(
      (sum, row) => sum + Number(row.streams || 0),
      0
    );

    const totalRevenue = rows.reduce(
      (sum, row) => sum + Number(row.revenue || 0),
      0
    );

    const platforms = rows.map((row) => {
      const streams = Number(row.streams || 0);
      const revenue = Number(row.revenue || 0);

      return {
        platform: row.platform,
        streams,
        downloads: Number(row.downloads || 0),
        revenue: Number(revenue.toFixed(2)),
        tracks: Number(row.tracks || 0),
        territories: Number(row.territories || 0),
        active_days: Number(row.active_days || 0),
        stream_percentage:
          totalStreams > 0
            ? Number(
                ((streams / totalStreams) * 100).toFixed(2)
              )
            : 0,
        revenue_percentage:
          totalRevenue > 0
            ? Number(
                ((revenue / totalRevenue) * 100).toFixed(2)
              )
            : 0
      };
    });

    return json({
      success: true,

      platforms,

      totals: {
        streams: totalStreams,
        revenue: Number(totalRevenue.toFixed(2)),
        platforms: platforms.length,
        currency: "USD"
      },

      filters: {
        from: from || null,
        to: to || null
      }
    });

  } catch (error) {
    console.error(
      "GET /v1/analytics/platforms/additional error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

if (
  url.pathname === "/v1/analytics/platforms/additional/info" &&
  request.method === "GET"
) {
  try {
    const token = getBearerToken(request);

    if (!token) {
      return json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      );
    }

    const auth = await verifyToken(token, env.JWT_SECRET);

    if (!auth) {
      return json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      );
    }

    const userId =
      auth.sub ||
      auth.user_id ||
      auth.userId ||
      auth.id;

    if (!userId) {
      return json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      );
    }

    const platform = url.searchParams.get("platform");

    if (!platform) {
      return json(
        {
          success: false,
          error: "platform is required"
        },
        400
      );
    }

    const allowedPlatforms = [
      "spotify",
      "apple_music",
      "youtube_music",
      "amazon_music",
      "deezer",
      "tiktok_music"
    ];

    if (!allowedPlatforms.includes(platform)) {
      return json(
        {
          success: false,
          error: "Invalid platform",
          allowed_platforms: allowedPlatforms
        },
        400
      );
    }

    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");

    let where = `
      ad.user_id = ?
      AND ad.platform = ?
    `;

    const params = [
      userId,
      platform
    ];

    if (from) {
      where += ` AND ad.event_date >= ?`;
      params.push(from);
    }

    if (to) {
      where += ` AND ad.event_date <= ?`;
      params.push(to);
    }

    // --------------------------------
    // Platform summary
    // --------------------------------

    const summary = await env.DB.prepare(`
      SELECT
        COALESCE(SUM(ad.streams), 0) AS streams,
        COALESCE(SUM(ad.downloads), 0) AS downloads,
        COALESCE(SUM(ad.revenue_amount), 0) AS revenue,
        COUNT(DISTINCT ad.track_id) AS tracks,
        COUNT(DISTINCT ad.territory) AS territories,
        MIN(ad.event_date) AS first_event_date,
        MAX(ad.event_date) AS last_event_date
      FROM analytics_daily ad
      WHERE ${where}
    `)
      .bind(...params)
      .first();

    // --------------------------------
    // Top tracks
    // --------------------------------

    const trackResult = await env.DB.prepare(`
      SELECT
        ad.track_id,
        t.title,
        t.isrc,
        COALESCE(SUM(ad.streams), 0) AS streams,
        COALESCE(SUM(ad.downloads), 0) AS downloads,
        COALESCE(SUM(ad.revenue_amount), 0) AS revenue
      FROM analytics_daily ad
      LEFT JOIN tracks t
        ON t.id = ad.track_id
      WHERE ${where}
        AND ad.track_id IS NOT NULL
      GROUP BY
        ad.track_id,
        t.title,
        t.isrc
      ORDER BY streams DESC
      LIMIT 10
    `)
      .bind(...params)
      .all();

    const topTracks = (trackResult.results || []).map((row) => ({
      track_id: row.track_id,
      title: row.title || null,
      isrc: row.isrc || null,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      revenue: Number(
        Number(row.revenue || 0).toFixed(2)
      )
    }));

    // --------------------------------
    // Top territories
    // --------------------------------

    const territoryResult = await env.DB.prepare(`
      SELECT
        ad.territory,
        COALESCE(SUM(ad.streams), 0) AS streams,
        COALESCE(SUM(ad.downloads), 0) AS downloads,
        COALESCE(SUM(ad.revenue_amount), 0) AS revenue
      FROM analytics_daily ad
      WHERE ${where}
        AND ad.territory IS NOT NULL
        AND ad.territory != ''
      GROUP BY ad.territory
      ORDER BY streams DESC
      LIMIT 20
    `)
      .bind(...params)
      .all();

    const topTerritories =
      (territoryResult.results || []).map((row) => ({
        territory: row.territory,
        streams: Number(row.streams || 0),
        downloads: Number(row.downloads || 0),
        revenue: Number(
          Number(row.revenue || 0).toFixed(2)
        )
      }));

    return json({
      success: true,

      platform,

      summary: {
        streams: Number(summary?.streams || 0),
        downloads: Number(summary?.downloads || 0),
        revenue: Number(
          Number(summary?.revenue || 0).toFixed(2)
        ),
        tracks: Number(summary?.tracks || 0),
        territories: Number(summary?.territories || 0),
        currency: "USD",
        first_event_date:
          summary?.first_event_date || null,
        last_event_date:
          summary?.last_event_date || null
      },

      top_tracks: topTracks,

      top_territories: topTerritories,

      filters: {
        from: from || null,
        to: to || null,
        platform
      }
    });

  } catch (error) {
    console.error(
      "GET /v1/analytics/platforms/additional/info error:",
      error
    );

    return json(
      {
        success: false,
        error: "Internal server error",
        message: error?.message || String(error)
      },
      500
    );
  }
}

// ============================================================
// SALES API
// ============================================================

if (url.pathname.startsWith("/v1/sales")) {

  const authResult = await authenticateSalesRequest(request, env);

  if (!authResult.ok) {
    return authResult.response;
  }

  const { userId } = authResult;

  // ------------------------------------------------------------
  // SALES OVERVIEW
  // GET /v1/sales/overview
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/overview"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const conditions = ["sd.user_id = ?"];
    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    const releaseId = url.searchParams.get("release_id");
    const trackId = url.searchParams.get("track_id");
    const channel = url.searchParams.get("channel");
    const territory = url.searchParams.get("territory");
    const currencyFilter = url.searchParams.get("currency");

    if (releaseId) {
      conditions.push("sd.release_id = ?");
      params.push(releaseId);
    }

    if (trackId) {
      conditions.push("sd.track_id = ?");
      params.push(trackId);
    }

    if (channel) {
      conditions.push("sd.channel = ?");
      params.push(channel);
    }

    if (territory) {
      conditions.push("sd.territory = ?");
      params.push(territory);
    }

    if (currencyFilter) {
      conditions.push("sd.currency = ?");
      params.push(currencyFilter.toUpperCase());
    }

    const result = await env.DB.prepare(`
      SELECT
        sd.currency,
        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue
      FROM sales_daily sd
      WHERE ${conditions.join(" AND ")}
      GROUP BY sd.currency
      ORDER BY sd.currency ASC
    `).bind(...params).all();

    return json({
      success: true,
      overview: formatSalesSummary(result.results || []),
      filters: {
        from: dates.from,
        to: dates.to,
        release_id: releaseId,
        track_id: trackId,
        channel,
        territory,
        currency: currencyFilter
          ? currencyFilter.toUpperCase()
          : null
      }
    });
  }


  // ------------------------------------------------------------
  // SALES TRACKS
  // GET /v1/sales/tracks
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/tracks"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const pagination = getSalesPagination(url);

    const conditions = [
      "sd.user_id = ?",
      "sd.track_id IS NOT NULL"
    ];

    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    const releaseId = url.searchParams.get("release_id");
    const channel = url.searchParams.get("channel");
    const currencyFilter = url.searchParams.get("currency");

    if (releaseId) {
      conditions.push("sd.release_id = ?");
      params.push(releaseId);
    }

    if (channel) {
      conditions.push("sd.channel = ?");
      params.push(channel);
    }

    if (currencyFilter) {
      conditions.push("sd.currency = ?");
      params.push(currencyFilter.toUpperCase());
    }

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        sd.track_id,
        sd.release_id,
        sd.currency,

        t.title,
        t.version,
        t.isrc,
        t.track_number,
        t.disc_number,

        r.title AS release_title,

        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue,

        MIN(sd.event_date) AS first_sale_date,
        MAX(sd.event_date) AS last_sale_date,

        COUNT(DISTINCT sd.channel) AS channels,
        COUNT(DISTINCT sd.territory) AS territories

      FROM sales_daily sd

      JOIN tracks t
        ON t.id = sd.track_id

      JOIN releases r
        ON r.id = sd.release_id

      WHERE ${conditions.join(" AND ")}

      GROUP BY
        sd.track_id,
        sd.release_id,
        sd.currency,
        t.title,
        t.version,
        t.isrc,
        t.track_number,
        t.disc_number,
        r.title

      ORDER BY streams DESC

      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    const tracks = (result.results || []).map(row => ({
      track_id: row.track_id,
      release_id: row.release_id,
      title: row.title,
      version: row.version,
      isrc: row.isrc,
      track_number: Number(row.track_number),
      disc_number: Number(row.disc_number),
      release_title: row.release_title,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      units: Number(row.units || 0),
      gross_revenue: roundSalesMoney(row.gross_revenue),
      net_revenue: roundSalesMoney(row.net_revenue),
      currency: row.currency,
      first_sale_date: row.first_sale_date,
      last_sale_date: row.last_sale_date,
      channels: Number(row.channels || 0),
      territories: Number(row.territories || 0)
    }));

    return json({
      success: true,
      tracks,
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: tracks.length
      },
      filters: {
        from: dates.from,
        to: dates.to,
        release_id: releaseId,
        channel,
        currency: currencyFilter
          ? currencyFilter.toUpperCase()
          : null
      }
    });
  }


  // ------------------------------------------------------------
  // SALES TRACK DETAIL
  //
  // GET /v1/sales/tracks/:isrc/overview
  // GET /v1/sales/tracks/:isrc/channels
  // GET /v1/sales/tracks/:isrc/territories
  // ------------------------------------------------------------

  const trackMatch = url.pathname.match(
    /^\/v1\/sales\/tracks\/([^/]+)\/(overview|channels|territories)$/
  );

  if (
    request.method === "GET" &&
    trackMatch
  ) {
    const isrc = decodeURIComponent(trackMatch[1]);
    const action = trackMatch[2];

    const track = await resolveSalesTrack(
      env,
      userId,
      isrc
    );

    if (!track) {
      return json({
        success: false,
        error: "Track not found"
      }, 404);
    }

    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const conditions = [
      "sd.user_id = ?",
      "sd.track_id = ?"
    ];

    const params = [
      userId,
      track.id
    ];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    if (action === "overview") {

      const result = await env.DB.prepare(`
        SELECT
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date,
          COUNT(DISTINCT sd.channel) AS channels,
          COUNT(DISTINCT sd.territory) AS territories
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY sd.currency
      `).bind(...params).all();

      const rows = result.results || [];

      return json({
        success: true,
        track: {
          id: track.id,
          isrc: track.isrc,
          title: track.title,
          version: track.version,
          track_number: track.track_number,
          disc_number: track.disc_number,
          duration_seconds: track.duration_seconds,
          genre: track.genre,
          language: track.language,
          explicit: Boolean(track.explicit),
          release_id: track.release_id,
          release_title: track.release_title,
          artist_name: track.artist_name
        },
        overview: formatSalesSummary(rows),
        date_range: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "channels") {

      const result = await env.DB.prepare(`
        SELECT
          sd.channel,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.channel,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        track: {
          id: track.id,
          isrc: track.isrc,
          title: track.title
        },
        channels: (result.results || []).map(row => ({
          channel: row.channel,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency,
          first_sale_date: row.first_sale_date,
          last_sale_date: row.last_sale_date
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "territories") {

      const result = await env.DB.prepare(`
        SELECT
          sd.territory,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.territory,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        track: {
          id: track.id,
          isrc: track.isrc,
          title: track.title
        },
        territories: (result.results || []).map(row => ({
          territory: row.territory,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency,
          first_sale_date: row.first_sale_date,
          last_sale_date: row.last_sale_date
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }
  }


  // ------------------------------------------------------------
  // SALES RELEASES
  // GET /v1/sales/releases
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/releases"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const pagination = getSalesPagination(url);

    const conditions = [
      "sd.user_id = ?",
      "sd.release_id IS NOT NULL"
    ];

    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    const currencyFilter = url.searchParams.get("currency");

    if (currencyFilter) {
      conditions.push("sd.currency = ?");
      params.push(currencyFilter.toUpperCase());
    }

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        sd.release_id,
        sd.currency,

        r.title,
        r.release_type,
        r.release_date,
        a.name AS artist_name,

        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue,

        MIN(sd.event_date) AS first_sale_date,
        MAX(sd.event_date) AS last_sale_date,

        COUNT(DISTINCT sd.track_id) AS tracks,
        COUNT(DISTINCT sd.channel) AS channels,
        COUNT(DISTINCT sd.territory) AS territories

      FROM sales_daily sd

      JOIN releases r
        ON r.id = sd.release_id

      LEFT JOIN artists a
        ON a.id = r.artist_id

      WHERE ${conditions.join(" AND ")}

      GROUP BY
        sd.release_id,
        sd.currency,
        r.title,
        r.release_type,
        r.release_date,
        a.name

      ORDER BY streams DESC

      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    const releases = (result.results || []).map(row => ({
      release_id: row.release_id,
      title: row.title,
      release_type: row.release_type,
      release_date: row.release_date,
      artist_name: row.artist_name,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      units: Number(row.units || 0),
      gross_revenue: roundSalesMoney(row.gross_revenue),
      net_revenue: roundSalesMoney(row.net_revenue),
      currency: row.currency,
      first_sale_date: row.first_sale_date,
      last_sale_date: row.last_sale_date,
      tracks: Number(row.tracks || 0),
      channels: Number(row.channels || 0),
      territories: Number(row.territories || 0)
    }));

    return json({
      success: true,
      releases,
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: releases.length
      },
      filters: {
        from: dates.from,
        to: dates.to,
        currency: currencyFilter
          ? currencyFilter.toUpperCase()
          : null
      }
    });
  }


  // ------------------------------------------------------------
  // SALES RELEASE DETAIL
  //
  // GET /v1/sales/releases/:releaseId/overview
  // GET /v1/sales/releases/:releaseId/channels
  // GET /v1/sales/releases/:releaseId/territories
  // ------------------------------------------------------------

  const releaseMatch = url.pathname.match(
    /^\/v1\/sales\/releases\/([^/]+)\/(overview|channels|territories)$/
  );

  if (
    request.method === "GET" &&
    releaseMatch
  ) {
    const releaseId = decodeURIComponent(releaseMatch[1]);
    const action = releaseMatch[2];

    const release = await resolveSalesRelease(
      env,
      userId,
      releaseId
    );

    if (!release) {
      return json({
        success: false,
        error: "Release not found"
      }, 404);
    }

    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const conditions = [
      "sd.user_id = ?",
      "sd.release_id = ?"
    ];

    const params = [
      userId,
      release.id
    ];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    if (action === "overview") {

      const result = await env.DB.prepare(`
        SELECT
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date,
          COUNT(DISTINCT sd.track_id) AS tracks,
          COUNT(DISTINCT sd.channel) AS channels,
          COUNT(DISTINCT sd.territory) AS territories
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY sd.currency
      `).bind(...params).all();

      return json({
        success: true,
        release: {
          id: release.id,
          title: release.title,
          release_type: release.release_type,
          release_date: release.release_date,
          artist_id: release.artist_id,
          artist_name: release.artist_name
        },
        overview: formatSalesSummary(result.results || []),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "channels") {

      const result = await env.DB.prepare(`
        SELECT
          sd.channel,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.channel,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        release: {
          id: release.id,
          title: release.title
        },
        channels: (result.results || []).map(row => ({
          channel: row.channel,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency,
          first_sale_date: row.first_sale_date,
          last_sale_date: row.last_sale_date
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "territories") {

      const result = await env.DB.prepare(`
        SELECT
          sd.territory,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.territory,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        release: {
          id: release.id,
          title: release.title
        },
        territories: (result.results || []).map(row => ({
          territory: row.territory,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency,
          first_sale_date: row.first_sale_date,
          last_sale_date: row.last_sale_date
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }
  }


  // ------------------------------------------------------------
  // SALES ARTISTS
  // GET /v1/sales/artists
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/artists"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const pagination = getSalesPagination(url);

    const conditions = ["sd.user_id = ?"];
    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        a.id AS artist_id,
        a.name AS artist_name,
        sd.currency,

        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue,

        MIN(sd.event_date) AS first_sale_date,
        MAX(sd.event_date) AS last_sale_date,

        COUNT(DISTINCT sd.release_id) AS releases,
        COUNT(DISTINCT sd.track_id) AS tracks,
        COUNT(DISTINCT sd.channel) AS channels,
        COUNT(DISTINCT sd.territory) AS territories

      FROM sales_daily sd

      JOIN releases r
        ON r.id = sd.release_id

      JOIN artists a
        ON a.id = r.artist_id

      WHERE ${conditions.join(" AND ")}

      GROUP BY
        a.id,
        a.name,
        sd.currency

      ORDER BY streams DESC

      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    const artists = (result.results || []).map(row => ({
      artist_id: row.artist_id,
      artist_name: row.artist_name,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      units: Number(row.units || 0),
      gross_revenue: roundSalesMoney(row.gross_revenue),
      net_revenue: roundSalesMoney(row.net_revenue),
      currency: row.currency,
      first_sale_date: row.first_sale_date,
      last_sale_date: row.last_sale_date,
      releases: Number(row.releases || 0),
      tracks: Number(row.tracks || 0),
      channels: Number(row.channels || 0),
      territories: Number(row.territories || 0)
    }));

    return json({
      success: true,
      artists,
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: artists.length
      },
      filters: {
        from: dates.from,
        to: dates.to
      }
    });
  }


  // ------------------------------------------------------------
  // SALES ARTIST DETAIL
  //
  // GET /v1/sales/artists/:artist/overview
  // GET /v1/sales/artists/:artist/channels
  // GET /v1/sales/artists/:artist/territories
  // ------------------------------------------------------------

  const artistMatch = url.pathname.match(
    /^\/v1\/sales\/artists\/([^/]+)\/(overview|channels|territories)$/
  );

  if (
    request.method === "GET" &&
    artistMatch
  ) {
    const artistRef = decodeURIComponent(artistMatch[1]);
    const action = artistMatch[2];

    const artist = await resolveSalesArtist(
      env,
      userId,
      artistRef
    );

    if (!artist) {
      return json({
        success: false,
        error: "Artist not found"
      }, 404);
    }

    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const conditions = [
      "sd.user_id = ?",
      "r.artist_id = ?"
    ];

    const params = [
      userId,
      artist.id
    ];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    if (action === "overview") {

      const result = await env.DB.prepare(`
        SELECT
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date,
          COUNT(DISTINCT sd.release_id) AS releases,
          COUNT(DISTINCT sd.track_id) AS tracks,
          COUNT(DISTINCT sd.channel) AS channels,
          COUNT(DISTINCT sd.territory) AS territories
        FROM sales_daily sd
        JOIN releases r
          ON r.id = sd.release_id
        WHERE ${conditions.join(" AND ")}
        GROUP BY sd.currency
      `).bind(...params).all();

      return json({
        success: true,
        artist: {
          id: artist.id,
          name: artist.name
        },
        overview: formatSalesSummary(result.results || []),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "channels") {

      const result = await env.DB.prepare(`
        SELECT
          sd.channel,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue
        FROM sales_daily sd
        JOIN releases r
          ON r.id = sd.release_id
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.channel,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        artist: {
          id: artist.id,
          name: artist.name
        },
        channels: (result.results || []).map(row => ({
          channel: row.channel,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "territories") {

      const result = await env.DB.prepare(`
        SELECT
          sd.territory,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue
        FROM sales_daily sd
        JOIN releases r
          ON r.id = sd.release_id
        WHERE ${conditions.join(" AND ")}
        GROUP BY
          sd.territory,
          sd.currency
        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        artist: {
          id: artist.id,
          name: artist.name
        },
        territories: (result.results || []).map(row => ({
          territory: row.territory,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }
  }


  // ------------------------------------------------------------
  // SALES CHANNELS
  // GET /v1/sales/channels
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/channels"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const pagination = getSalesPagination(url);

    const conditions = ["sd.user_id = ?"];
    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        sd.channel,
        sd.currency,

        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue,

        MIN(sd.event_date) AS first_sale_date,
        MAX(sd.event_date) AS last_sale_date,

        COUNT(DISTINCT sd.release_id) AS releases,
        COUNT(DISTINCT sd.track_id) AS tracks,
        COUNT(DISTINCT sd.territory) AS territories

      FROM sales_daily sd

      WHERE ${conditions.join(" AND ")}

      GROUP BY
        sd.channel,
        sd.currency

      ORDER BY streams DESC

      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    const channels = (result.results || []).map(row => ({
      channel: row.channel,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      units: Number(row.units || 0),
      gross_revenue: roundSalesMoney(row.gross_revenue),
      net_revenue: roundSalesMoney(row.net_revenue),
      currency: row.currency,
      first_sale_date: row.first_sale_date,
      last_sale_date: row.last_sale_date,
      releases: Number(row.releases || 0),
      tracks: Number(row.tracks || 0),
      territories: Number(row.territories || 0)
    }));

    return json({
      success: true,
      channels,
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: channels.length
      },
      filters: {
        from: dates.from,
        to: dates.to
      }
    });
  }


  // ------------------------------------------------------------
  // SALES CHANNEL DETAIL
  //
  // GET /v1/sales/channels/:channel/overview
  // GET /v1/sales/channels/:channel/releases
  // GET /v1/sales/channels/:channel/territories
  // ------------------------------------------------------------

  const channelMatch = url.pathname.match(
    /^\/v1\/sales\/channels\/([^/]+)\/(overview|releases|territories)$/
  );

  if (
    request.method === "GET" &&
    channelMatch
  ) {
    const channel = decodeURIComponent(channelMatch[1]);
    const action = channelMatch[2];

    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const conditions = [
      "sd.user_id = ?",
      "sd.channel = ?"
    ];

    const params = [
      userId,
      channel
    ];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    if (action === "overview") {

      const result = await env.DB.prepare(`
        SELECT
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue,
          MIN(sd.event_date) AS first_sale_date,
          MAX(sd.event_date) AS last_sale_date,
          COUNT(DISTINCT sd.release_id) AS releases,
          COUNT(DISTINCT sd.track_id) AS tracks,
          COUNT(DISTINCT sd.territory) AS territories
        FROM sales_daily sd
        WHERE ${conditions.join(" AND ")}
        GROUP BY sd.currency
      `).bind(...params).all();

      return json({
        success: true,
        channel,
        overview: formatSalesSummary(result.results || []),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "releases") {

      const result = await env.DB.prepare(`
        SELECT
          sd.release_id,
          sd.currency,
          r.title,
          r.release_type,
          r.release_date,
          a.name AS artist_name,

          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue

        FROM sales_daily sd

        JOIN releases r
          ON r.id = sd.release_id

        LEFT JOIN artists a
          ON a.id = r.artist_id

        WHERE ${conditions.join(" AND ")}

        GROUP BY
          sd.release_id,
          sd.currency,
          r.title,
          r.release_type,
          r.release_date,
          a.name

        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        channel,
        releases: (result.results || []).map(row => ({
          release_id: row.release_id,
          title: row.title,
          release_type: row.release_type,
          release_date: row.release_date,
          artist_name: row.artist_name,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }


    if (action === "territories") {

      const result = await env.DB.prepare(`
        SELECT
          sd.territory,
          sd.currency,
          SUM(sd.streams) AS streams,
          SUM(sd.downloads) AS downloads,
          SUM(sd.units) AS units,
          SUM(sd.gross_revenue) AS gross_revenue,
          SUM(sd.net_revenue) AS net_revenue

        FROM sales_daily sd

        WHERE ${conditions.join(" AND ")}

        GROUP BY
          sd.territory,
          sd.currency

        ORDER BY streams DESC
      `).bind(...params).all();

      return json({
        success: true,
        channel,
        territories: (result.results || []).map(row => ({
          territory: row.territory,
          streams: Number(row.streams || 0),
          downloads: Number(row.downloads || 0),
          units: Number(row.units || 0),
          gross_revenue: roundSalesMoney(row.gross_revenue),
          net_revenue: roundSalesMoney(row.net_revenue),
          currency: row.currency
        })),
        filters: {
          from: dates.from,
          to: dates.to
        }
      });
    }
  }


  // ------------------------------------------------------------
  // SALES TERRITORIES
  // GET /v1/sales/territories
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/territories"
  ) {
    const dates = getSalesDateRange(url);

    if (dates.error) {
      return json({
        success: false,
        error: dates.error
      }, 400);
    }

    const pagination = getSalesPagination(url);

    const conditions = ["sd.user_id = ?"];
    const params = [userId];

    addSalesDateConditions(
      conditions,
      params,
      dates.from,
      dates.to,
      "sd.event_date"
    );

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        sd.territory,
        sd.currency,

        SUM(sd.streams) AS streams,
        SUM(sd.downloads) AS downloads,
        SUM(sd.units) AS units,
        SUM(sd.gross_revenue) AS gross_revenue,
        SUM(sd.net_revenue) AS net_revenue,

        MIN(sd.event_date) AS first_sale_date,
        MAX(sd.event_date) AS last_sale_date,

        COUNT(DISTINCT sd.release_id) AS releases,
        COUNT(DISTINCT sd.track_id) AS tracks,
        COUNT(DISTINCT sd.channel) AS channels

      FROM sales_daily sd

      WHERE ${conditions.join(" AND ")}

      GROUP BY
        sd.territory,
        sd.currency

      ORDER BY streams DESC

      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    const territories = (result.results || []).map(row => ({
      territory: row.territory,
      streams: Number(row.streams || 0),
      downloads: Number(row.downloads || 0),
      units: Number(row.units || 0),
      gross_revenue: roundSalesMoney(row.gross_revenue),
      net_revenue: roundSalesMoney(row.net_revenue),
      currency: row.currency,
      first_sale_date: row.first_sale_date,
      last_sale_date: row.last_sale_date,
      releases: Number(row.releases || 0),
      tracks: Number(row.tracks || 0),
      channels: Number(row.channels || 0)
    }));

    return json({
      success: true,
      territories,
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: territories.length
      },
      filters: {
        from: dates.from,
        to: dates.to
      }
    });
  }


  // ------------------------------------------------------------
  // STREAM RATES
  // GET /v1/sales/stream-rates
  // ------------------------------------------------------------

  if (
    request.method === "GET" &&
    url.pathname === "/v1/sales/stream-rates"
  ) {
    const pagination = getSalesPagination(url);

    const conditions = ["1 = 1"];
    const params = [];

    const service = url.searchParams.get("service");
    const territory = url.searchParams.get("territory");
    const currency = url.searchParams.get("currency");

    if (service) {
      conditions.push("service = ?");
      params.push(service);
    }

    if (territory) {
      conditions.push("territory = ?");
      params.push(territory.toUpperCase());
    }

    if (currency) {
      conditions.push("currency = ?");
      params.push(currency.toUpperCase());
    }

    params.push(pagination.limit);
    params.push(pagination.offset);

    const result = await env.DB.prepare(`
      SELECT
        id,
        service,
        territory,
        currency,
        rate,
        rate_type,
        effective_from,
        effective_to,
        source,
        metadata_json,
        created_at,
        updated_at
      FROM sales_stream_rates
      WHERE ${conditions.join(" AND ")}
      ORDER BY
        service ASC,
        territory ASC,
        effective_from DESC
      LIMIT ?
      OFFSET ?
    `).bind(...params).all();

    return json({
      success: true,
      rates: (result.results || []).map(row => ({
        id: row.id,
        service: row.service,
        territory: row.territory,
        currency: row.currency,
        rate: Number(row.rate || 0),
        rate_type: row.rate_type,
        effective_from: row.effective_from,
        effective_to: row.effective_to,
        source: row.source,
        metadata: row.metadata_json
          ? JSON.parse(row.metadata_json)
          : null,
        created_at: row.created_at,
        updated_at: row.updated_at
      })),
      pagination: {
        limit: pagination.limit,
        offset: pagination.offset,
        count: (result.results || []).length
      },
      filters: {
        service,
        territory: territory
          ? territory.toUpperCase()
          : null,
        currency: currency
          ? currency.toUpperCase()
          : null
      }
    });
  }


  // ------------------------------------------------------------
  // STREAM RATE SERVICE DETAIL
  //
  // GET /v1/sales/stream-rates/:service/overview
  // GET /v1/sales/stream-rates/:service/territories
  // ------------------------------------------------------------

  const rateMatch = url.pathname.match(
    /^\/v1\/sales\/stream-rates\/([^/]+)\/(overview|territories)$/
  );

  if (
    request.method === "GET" &&
    rateMatch
  ) {
    const service = decodeURIComponent(rateMatch[1]);
    const action = rateMatch[2];

    if (action === "overview") {

      const result = await env.DB.prepare(`
        SELECT
          id,
          service,
          territory,
          currency,
          rate,
          rate_type,
          effective_from,
          effective_to,
          source
        FROM sales_stream_rates
        WHERE service = ?
        ORDER BY
          effective_from DESC
      `).bind(service).all();

      const rows = result.results || [];

      const rates = rows.map(row => Number(row.rate || 0));

      const territories = [
        ...new Set(
          rows.map(row => row.territory)
        )
      ];

      const currencies = [
        ...new Set(
          rows.map(row => row.currency)
        )
      ];

      return json({
        success: true,
        service,
        overview: {
          rate_count: rows.length,
          territories: territories.length,
          currencies,
          min_rate: rates.length
            ? Math.min(...rates)
            : null,
          max_rate: rates.length
            ? Math.max(...rates)
            : null,
          latest_rate: rows.length
            ? {
                rate: Number(rows[0].rate || 0),
                currency: rows[0].currency,
                territory: rows[0].territory,
                rate_type: rows[0].rate_type,
                effective_from: rows[0].effective_from,
                effective_to: rows[0].effective_to,
                source: rows[0].source
              }
            : null
        }
      });
    }


    if (action === "territories") {

      const result = await env.DB.prepare(`
        SELECT
          id,
          territory,
          currency,
          rate,
          rate_type,
          effective_from,
          effective_to,
          source
        FROM sales_stream_rates
        WHERE service = ?
        ORDER BY
          territory ASC,
          effective_from DESC
      `).bind(service).all();

      return json({
        success: true,
        service,
        territories: (result.results || []).map(row => ({
          territory: row.territory,
          currency: row.currency,
          rate: Number(row.rate || 0),
          rate_type: row.rate_type,
          effective_from: row.effective_from,
          effective_to: row.effective_to,
          source: row.source
        }))
      });
    }
  }
}

// ============================================================
// AUDIORY SALES INGESTION + AGGREGATION ENGINE
// ============================================================
//
// Endpoints added:
//
// POST /v1/sales/events
// POST /v1/sales/events/batch
// GET  /v1/sales/events
// GET  /v1/sales/events/:id
//
// POST /v1/sales/aggregate
// POST /v1/sales/aggregate/batch
//
// GET  /v1/sales/imports/:id
//
// ============================================================


// ============================================================
// SALES CONSTANTS
// ============================================================

const SALES_PLATFORMS = [
  "spotify",
  "apple_music",
  "youtube_music",
  "amazon_music",
  "deezer",
  "tiktok_music"
];

const SALES_TYPES = [
  "stream",
  "download",
  "sale",
  "subscription",
  "royalty",
  "adjustment"
];

const SALES_CURRENCIES = [
  "USD",
  "EUR",
  "GBP",
  "KES",
  "CAD",
  "AUD",
  "JPY",
  "ZAR",
  "NGN",
  "GHS",
  "TZS",
  "UGX"
];


// ============================================================
// SALES AUTH HELPER
// ============================================================

async function requireSalesAuth(request, env) {
  const token = getBearerToken(request);

  if (!token) {
    return {
      ok: false,
      response: json(
        {
          success: false,
          error: "Authorization required"
        },
        401
      )
    };
  }

  const auth = await verifyToken(
    token,
    env.JWT_SECRET
  );

  if (!auth) {
    return {
      ok: false,
      response: json(
        {
          success: false,
          error: "Invalid or expired token"
        },
        401
      )
    };
  }

  const userId =
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id;

  if (!userId) {
    return {
      ok: false,
      response: json(
        {
          success: false,
          error: "Invalid authentication payload"
        },
        401
      )
    };
  }

  return {
    ok: true,
    auth,
    userId
  };
}


// ============================================================
// SALES VALIDATION HELPERS
// ============================================================

function isValidSalesPlatform(platform) {
  return SALES_PLATFORMS.includes(
    String(platform || "").toLowerCase()
  );
}


function isValidSalesType(type) {
  return SALES_TYPES.includes(
    String(type || "").toLowerCase()
  );
}


function isValidSalesCurrency(currency) {
  return SALES_CURRENCIES.includes(
    String(currency || "").toUpperCase()
  );
}


function isValidSalesDateStrict(value) {
  if (!value) return false;

  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }

  const date = new Date(
    `${value}T00:00:00Z`
  );

  if (Number.isNaN(date.getTime())) {
    return false;
  }

  return (
    date.toISOString().slice(0, 10) === value
  );
}


function normalizeSalesTerritory(value) {
  if (!value) return null;

  return String(value)
    .trim()
    .toUpperCase();
}


function normalizeSalesCurrency(value) {
  return String(
    value || "USD"
  )
    .trim()
    .toUpperCase();
}


function normalizeSalesPlatform(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function normalizeSalesType(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function normalizeSalesChannel(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}


function normalizeOptionalNumber(
  value,
  fieldName
) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return 0;
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    throw new Error(
      `${fieldName} must be a valid number`
    );
  }

  if (number < 0) {
    throw new Error(
      `${fieldName} cannot be negative`
    );
  }

  return number;
}


function normalizeOptionalInteger(
  value,
  fieldName
) {
  const number = normalizeOptionalNumber(
    value,
    fieldName
  );

  if (!Number.isInteger(number)) {
    throw new Error(
      `${fieldName} must be an integer`
    );
  }

  return number;
}


function roundMoney(value) {
  return Number(
    Number(value || 0).toFixed(6)
  );
}


// ============================================================
// SALES DATE FILTERS
// ============================================================

function validateSalesDate(value) {
  if (!value) return true;

  return isValidSalesDateStrict(value);
}


function getSalesDateFilters(url) {
  const from =
    url.searchParams.get("from");

  const to =
    url.searchParams.get("to");

  if (
    from &&
    !validateSalesDate(from)
  ) {
    throw new Error(
      "Invalid from date. Expected YYYY-MM-DD"
    );
  }

  if (
    to &&
    !validateSalesDate(to)
  ) {
    throw new Error(
      "Invalid to date. Expected YYYY-MM-DD"
    );
  }

  if (
    from &&
    to &&
    from > to
  ) {
    throw new Error(
      "from cannot be later than to"
    );
  }

  return {
    from,
    to
  };
}


function addSalesDateConditions(
  conditions,
  params,
  from,
  to,
  column = "se.event_date"
) {
  if (from) {
    conditions.push(
      `${column} >= ?`
    );

    params.push(from);
  }

  if (to) {
    conditions.push(
      `${column} <= ?`
    );

    params.push(to);
  }
}


function salesUserId(auth) {
  return (
    auth.sub ||
    auth.user_id ||
    auth.userId ||
    auth.id
  );
}


// ============================================================
// OWNERSHIP VALIDATION
// ============================================================

async function validateSalesReleaseOwnership(
  env,
  releaseId,
  userId
) {
  if (!releaseId) {
    return null;
  }

  const release =
    await env.DB
      .prepare(`
        SELECT
          id,
          user_id,
          artist_id,
          title,
          release_type
        FROM releases
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
      .bind(
        releaseId,
        userId
      )
      .first();

  if (!release) {
    throw new Error(
      "Release not found or does not belong to this account"
    );
  }

  return release;
}


async function validateSalesTrackOwnership(
  env,
  trackId,
  userId
) {
  if (!trackId) {
    return null;
  }

  const track =
    await env.DB
      .prepare(`
        SELECT
          t.id,
          t.release_id,
          t.isrc,
          t.title,
          r.user_id,
          r.artist_id
        FROM tracks t
        INNER JOIN releases r
          ON r.id = t.release_id
        WHERE t.id = ?
          AND r.user_id = ?
        LIMIT 1
      `)
      .bind(
        trackId,
        userId
      )
      .first();

  if (!track) {
    throw new Error(
      "Track not found or does not belong to this account"
    );
  }

  return track;
}


async function validateSalesArtistOwnership(
  env,
  artistId,
  userId
) {
  if (!artistId) {
    return null;
  }

  const artist =
    await env.DB
      .prepare(`
        SELECT
          id,
          name,
          country
        FROM artists
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
      .bind(
        artistId,
        userId
      )
      .first();

  if (!artist) {
    throw new Error(
      "Artist not found or does not belong to this account"
    );
  }

  return artist;
}


// ============================================================
// STREAM RATE LOOKUP
// ============================================================

async function findSalesStreamRate(
  env,
  service,
  territory,
  currency,
  eventDate
) {
  if (
    !service ||
    !territory ||
    !currency ||
    !eventDate
  ) {
    return null;
  }

  const result =
    await env.DB
      .prepare(`
        SELECT
          id,
          service,
          territory,
          currency,
          rate,
          rate_type,
          effective_from,
          effective_to,
          source,
          metadata_json
        FROM sales_stream_rates
        WHERE service = ?
          AND territory = ?
          AND currency = ?
          AND effective_from <= ?
          AND (
            effective_to IS NULL
            OR effective_to >= ?
          )
        ORDER BY effective_from DESC
        LIMIT 1
      `)
      .bind(
        service,
        territory,
        currency,
        eventDate,
        eventDate
      )
      .first();

  return result || null;
}


// ============================================================
// NORMALIZE SALES EVENT
// ============================================================

async function normalizeSalesEvent(
  env,
  input,
  userId
) {
  if (!input || typeof input !== "object") {
    throw new Error(
      "Sales event must be a JSON object"
    );
  }

  const platform =
    normalizeSalesPlatform(
      input.platform ||
      input.channel
    );

  if (!platform) {
    throw new Error(
      "platform is required"
    );
  }

  if (!isValidSalesPlatform(platform)) {
    throw new Error(
      `Unsupported platform: ${platform}`
    );
  }

  const saleType =
    normalizeSalesType(
      input.sale_type ||
      input.event_type ||
      "stream"
    );

  if (!isValidSalesType(saleType)) {
    throw new Error(
      `Unsupported sale_type: ${saleType}`
    );
  }

  const eventDate =
    input.event_date;

  if (!isValidSalesDateStrict(eventDate)) {
    throw new Error(
      "event_date must use YYYY-MM-DD format"
    );
  }

  const territory =
    normalizeSalesTerritory(
      input.territory
    );

  const currency =
    normalizeSalesCurrency(
      input.currency
    );

  if (!isValidSalesCurrency(currency)) {
    throw new Error(
      `Unsupported currency: ${currency}`
    );
  }

  const releaseId =
    input.release_id ||
    null;

  const trackId =
    input.track_id ||
    null;

  const artistId =
    input.artist_id ||
    null;

  const release =
    await validateSalesReleaseOwnership(
      env,
      releaseId,
      userId
    );

  const track =
    await validateSalesTrackOwnership(
      env,
      trackId,
      userId
    );

  const artist =
    await validateSalesArtistOwnership(
      env,
      artistId,
      userId
    );

  if (
    track &&
    releaseId &&
    track.release_id !== releaseId
  ) {
    throw new Error(
      "track_id does not belong to release_id"
    );
  }

  if (
    track &&
    !releaseId
  ) {
    throw new Error(
      "release_id is required when track_id is supplied"
    );
  }

  if (
    release &&
    artistId &&
    release.artist_id !== artistId
  ) {
    throw new Error(
      "artist_id does not belong to release_id"
    );
  }

  const streams =
    normalizeOptionalInteger(
      input.streams,
      "streams"
    );

  const downloads =
    normalizeOptionalInteger(
      input.downloads,
      "downloads"
    );

  let units =
    normalizeOptionalInteger(
      input.units,
      "units"
    );

  const explicitGross =
    input.gross_revenue !== undefined &&
    input.gross_revenue !== null &&
    input.gross_revenue !== "";

  const explicitNet =
    input.net_revenue !== undefined &&
    input.net_revenue !== null &&
    input.net_revenue !== "";

  let grossRevenue =
    normalizeOptionalNumber(
      input.gross_revenue,
      "gross_revenue"
    );

  let netRevenue =
    normalizeOptionalNumber(
      input.net_revenue,
      "net_revenue"
    );

  let streamRate =
    input.stream_rate !== undefined &&
    input.stream_rate !== null &&
    input.stream_rate !== ""
      ? normalizeOptionalNumber(
          input.stream_rate,
          "stream_rate"
        )
      : null;

  if (streamRate !== null) {
    if (streamRate < 0) {
      throw new Error(
        "stream_rate cannot be negative"
      );
    }
  }

  /*
   * If units are not supplied:
   *
   * stream events => streams
   * download events => downloads
   *
   * Otherwise leave the supplied value.
   */

  if (
    input.units === undefined ||
    input.units === null ||
    input.units === ""
  ) {
    if (saleType === "stream") {
      units = streams;
    } else if (
      saleType === "download"
    ) {
      units = downloads;
    }
  }

  /*
   * Resolve stream rate automatically when possible.
   *
   * We only calculate gross revenue automatically.
   * We NEVER invent a net revenue value.
   */

  let resolvedRate = null;

  if (
    streamRate === null &&
    saleType === "stream" &&
    territory
  ) {
    resolvedRate =
      await findSalesStreamRate(
        env,
        platform,
        territory,
        currency,
        eventDate
      );

    if (resolvedRate) {
      streamRate =
        Number(resolvedRate.rate);
    }
  }

  if (
    !explicitGross &&
    streamRate !== null &&
    streams > 0
  ) {
    grossRevenue =
      roundMoney(
        streams * streamRate
      );
  }

  /*
   * If net revenue wasn't supplied,
   * do not manufacture it.
   *
   * For example:
   *
   * gross = $5.00
   * net = $4.75
   *
   * is valid when supplied by the distributor.
   *
   * We do not assume a universal platform fee.
   */

  if (!explicitNet) {
    netRevenue = grossRevenue;
  }

  /*
   * For a royalty/sale record where the
   * source only provides net revenue and
   * gross is zero, preserve the supplied
   * net amount.
   */

  if (
    explicitNet &&
    !explicitGross &&
    grossRevenue === 0
  ) {
    grossRevenue = netRevenue;
  }

  let metadataJson = null;

  if (
    input.metadata !== undefined &&
    input.metadata !== null
  ) {
    if (
      typeof input.metadata === "string"
    ) {
      try {
        JSON.parse(input.metadata);
        metadataJson = input.metadata;
      } catch {
        throw new Error(
          "metadata must contain valid JSON"
        );
      }
    } else {
      metadataJson =
        JSON.stringify(
          input.metadata
        );
    }
  }

  return {
    id:
      input.id ||
      `sale_${crypto.randomUUID()}`,

    user_id:
      userId,

    release_id:
      releaseId,

    track_id:
      trackId,

    isrc:
      input.isrc ||
      track?.isrc ||
      null,

    artist_id:
      artistId ||
      release?.artist_id ||
      track?.artist_id ||
      null,

    channel:
      platform,

    territory,

    sale_type:
      saleType,

    event_date:
      eventDate,

    streams,

    downloads,

    units,

    gross_revenue:
      roundMoney(grossRevenue),

    net_revenue:
      roundMoney(netRevenue),

    currency,

    stream_rate:
      streamRate === null
        ? null
        : roundMoney(streamRate),

    source:
      String(
        input.source ||
        "api"
      )
        .trim()
        .toLowerCase(),

    source_record_id:
      input.source_record_id ||
      input.external_id ||
      null,

    metadata_json:
      metadataJson,

    resolved_rate:
      resolvedRate
        ? {
            id: resolvedRate.id,
            rate: Number(
              resolvedRate.rate
            ),
            source:
              resolvedRate.source
          }
        : null
  };
}


// ============================================================
// INSERT SALES EVENT
// ============================================================

async function insertSalesEvent(
  env,
  sale
) {
  /*
   * Source + source_record_id provides
   * idempotency for distributor reports.
   */

  if (
    sale.source_record_id
  ) {
    const existing =
      await env.DB
        .prepare(`
          SELECT *
          FROM sales_events
          WHERE user_id = ?
            AND source = ?
            AND source_record_id = ?
          LIMIT 1
        `)
        .bind(
          sale.user_id,
          sale.source,
          sale.source_record_id
        )
        .first();

    if (existing) {
      return {
        inserted: false,
        duplicate: true,
        event: existing
      };
    }
  }

  await env.DB
    .prepare(`
      INSERT INTO sales_events (
        id,
        user_id,
        release_id,
        track_id,
        isrc,
        artist_id,
        channel,
        territory,
        sale_type,
        event_date,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency,
        stream_rate,
        source,
        source_record_id,
        metadata_json,
        aggregation_status
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
        'pending'
      )
    `)
    .bind(
      sale.id,
      sale.user_id,
      sale.release_id,
      sale.track_id,
      sale.isrc,
      sale.artist_id,
      sale.channel,
      sale.territory,
      sale.sale_type,
      sale.event_date,
      sale.streams,
      sale.downloads,
      sale.units,
      sale.gross_revenue,
      sale.net_revenue,
      sale.currency,
      sale.stream_rate,
      sale.source,
      sale.source_record_id,
      sale.metadata_json
    )
    .run();

  const event =
    await env.DB
      .prepare(`
        SELECT *
        FROM sales_events
        WHERE id = ?
        LIMIT 1
      `)
      .bind(sale.id)
      .first();

  return {
    inserted: true,
    duplicate: false,
    event
  };
}


// ============================================================
// AGGREGATION HELPERS
// ============================================================

async function upsertSalesDaily(
  env,
  event
) {
  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM sales_daily
        WHERE user_id = ?
          AND COALESCE(release_id, '') =
              COALESCE(?, '')
          AND COALESCE(track_id, '') =
              COALESCE(?, '')
          AND channel = ?
          AND COALESCE(territory, '') =
              COALESCE(?, '')
          AND event_date = ?
          AND currency = ?
        LIMIT 1
      `)
      .bind(
        event.user_id,
        event.release_id,
        event.track_id,
        event.channel,
        event.territory,
        event.event_date,
        event.currency
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE sales_daily
        SET
          streams = streams + ?,
          downloads = downloads + ?,
          units = units + ?,
          gross_revenue =
            gross_revenue + ?,
          net_revenue =
            net_revenue + ?,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        event.streams,
        event.downloads,
        event.units,
        event.gross_revenue,
        event.net_revenue,
        existing.id
      )
      .run();

    return existing.id;
  }

  const id =
    `sales_daily_${crypto.randomUUID()}`;

  await env.DB
    .prepare(`
      INSERT INTO sales_daily (
        id,
        user_id,
        release_id,
        track_id,
        channel,
        territory,
        event_date,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `)
    .bind(
      id,
      event.user_id,
      event.release_id,
      event.track_id,
      event.channel,
      event.territory,
      event.event_date,
      event.streams,
      event.downloads,
      event.units,
      event.gross_revenue,
      event.net_revenue,
      event.currency
    )
    .run();

  return id;
}


// ============================================================
// SALES TRACK AGGREGATION
// ============================================================

async function upsertSalesTrack(
  env,
  event
) {
  if (!event.track_id) {
    return null;
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM sales_tracks
        WHERE user_id = ?
          AND track_id = ?
          AND currency = ?
        LIMIT 1
      `)
      .bind(
        event.user_id,
        event.track_id,
        event.currency
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE sales_tracks
        SET
          streams =
            streams + ?,
          downloads =
            downloads + ?,
          units =
            units + ?,
          gross_revenue =
            gross_revenue + ?,
          net_revenue =
            net_revenue + ?,
          first_sale_date =
            CASE
              WHEN first_sale_date IS NULL
                OR first_sale_date > ?
              THEN ?
              ELSE first_sale_date
            END,
          last_sale_date =
            CASE
              WHEN last_sale_date IS NULL
                OR last_sale_date < ?
              THEN ?
              ELSE last_sale_date
            END,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        event.streams,
        event.downloads,
        event.units,
        event.gross_revenue,
        event.net_revenue,
        event.event_date,
        event.event_date,
        event.event_date,
        event.event_date,
        existing.id
      )
      .run();

    return existing.id;
  }

  const track =
    await env.DB
      .prepare(`
        SELECT
          id,
          release_id,
          isrc,
          title
        FROM tracks
        WHERE id = ?
        LIMIT 1
      `)
      .bind(event.track_id)
      .first();

  const id =
    `sales_track_${crypto.randomUUID()}`;

  await env.DB
    .prepare(`
      INSERT INTO sales_tracks (
        id,
        user_id,
        track_id,
        release_id,
        isrc,
        title,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency,
        first_sale_date,
        last_sale_date
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `)
    .bind(
      id,
      event.user_id,
      event.track_id,
      event.release_id ||
        track?.release_id ||
        null,
      event.isrc ||
        track?.isrc ||
        null,
      track?.title ||
        null,
      event.streams,
      event.downloads,
      event.units,
      event.gross_revenue,
      event.net_revenue,
      event.currency,
      event.event_date,
      event.event_date
    )
    .run();

  return id;
}


// ============================================================
// SALES RELEASE AGGREGATION
// ============================================================

async function upsertSalesRelease(
  env,
  event
) {
  if (!event.release_id) {
    return null;
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM sales_releases
        WHERE user_id = ?
          AND release_id = ?
          AND currency = ?
        LIMIT 1
      `)
      .bind(
        event.user_id,
        event.release_id,
        event.currency
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE sales_releases
        SET
          streams =
            streams + ?,
          downloads =
            downloads + ?,
          units =
            units + ?,
          gross_revenue =
            gross_revenue + ?,
          net_revenue =
            net_revenue + ?,
          first_sale_date =
            CASE
              WHEN first_sale_date IS NULL
                OR first_sale_date > ?
              THEN ?
              ELSE first_sale_date
            END,
          last_sale_date =
            CASE
              WHEN last_sale_date IS NULL
                OR last_sale_date < ?
              THEN ?
              ELSE last_sale_date
            END,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        event.streams,
        event.downloads,
        event.units,
        event.gross_revenue,
        event.net_revenue,
        event.event_date,
        event.event_date,
        event.event_date,
        event.event_date,
        existing.id
      )
      .run();

    return existing.id;
  }

  const release =
    await env.DB
      .prepare(`
        SELECT
          id,
          title
        FROM releases
        WHERE id = ?
        LIMIT 1
      `)
      .bind(event.release_id)
      .first();

  const id =
    `sales_release_${crypto.randomUUID()}`;

  await env.DB
    .prepare(`
      INSERT INTO sales_releases (
        id,
        user_id,
        release_id,
        title,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency,
        first_sale_date,
        last_sale_date
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `)
    .bind(
      id,
      event.user_id,
      event.release_id,
      release?.title ||
        null,
      event.streams,
      event.downloads,
      event.units,
      event.gross_revenue,
      event.net_revenue,
      event.currency,
      event.event_date,
      event.event_date
    )
    .run();

  return id;
}


// ============================================================
// SALES CHANNEL AGGREGATION
// ============================================================

async function upsertSalesChannel(
  env,
  event
) {
  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM sales_channels
        WHERE user_id = ?
          AND channel = ?
          AND currency = ?
        LIMIT 1
      `)
      .bind(
        event.user_id,
        event.channel,
        event.currency
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE sales_channels
        SET
          streams =
            streams + ?,
          downloads =
            downloads + ?,
          units =
            units + ?,
          gross_revenue =
            gross_revenue + ?,
          net_revenue =
            net_revenue + ?,
          first_sale_date =
            CASE
              WHEN first_sale_date IS NULL
                OR first_sale_date > ?
              THEN ?
              ELSE first_sale_date
            END,
          last_sale_date =
            CASE
              WHEN last_sale_date IS NULL
                OR last_sale_date < ?
              THEN ?
              ELSE last_sale_date
            END,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        event.streams,
        event.downloads,
        event.units,
        event.gross_revenue,
        event.net_revenue,
        event.event_date,
        event.event_date,
        event.event_date,
        event.event_date,
        existing.id
      )
      .run();

    return existing.id;
  }

  const id =
    `sales_channel_${crypto.randomUUID()}`;

  await env.DB
    .prepare(`
      INSERT INTO sales_channels (
        id,
        user_id,
        channel,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency,
        first_sale_date,
        last_sale_date
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `)
    .bind(
      id,
      event.user_id,
      event.channel,
      event.streams,
      event.downloads,
      event.units,
      event.gross_revenue,
      event.net_revenue,
      event.currency,
      event.event_date,
      event.event_date
    )
    .run();

  return id;
}


// ============================================================
// SALES TERRITORY AGGREGATION
// ============================================================

async function upsertSalesTerritory(
  env,
  event
) {
  if (!event.territory) {
    return null;
  }

  const existing =
    await env.DB
      .prepare(`
        SELECT id
        FROM sales_territories
        WHERE user_id = ?
          AND territory = ?
          AND currency = ?
        LIMIT 1
      `)
      .bind(
        event.user_id,
        event.territory,
        event.currency
      )
      .first();

  if (existing) {
    await env.DB
      .prepare(`
        UPDATE sales_territories
        SET
          streams =
            streams + ?,
          downloads =
            downloads + ?,
          units =
            units + ?,
          gross_revenue =
            gross_revenue + ?,
          net_revenue =
            net_revenue + ?,
          first_sale_date =
            CASE
              WHEN first_sale_date IS NULL
                OR first_sale_date > ?
              THEN ?
              ELSE first_sale_date
            END,
          last_sale_date =
            CASE
              WHEN last_sale_date IS NULL
                OR last_sale_date < ?
              THEN ?
              ELSE last_sale_date
            END,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        event.streams,
        event.downloads,
        event.units,
        event.gross_revenue,
        event.net_revenue,
        event.event_date,
        event.event_date,
        event.event_date,
        event.event_date,
        existing.id
      )
      .run();

    return existing.id;
  }

  const id =
    `sales_territory_${crypto.randomUUID()}`;

  await env.DB
    .prepare(`
      INSERT INTO sales_territories (
        id,
        user_id,
        territory,
        streams,
        downloads,
        units,
        gross_revenue,
        net_revenue,
        currency,
        first_sale_date,
        last_sale_date
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      )
    `)
    .bind(
      id,
      event.user_id,
      event.territory,
      event.streams,
      event.downloads,
      event.units,
      event.gross_revenue,
      event.net_revenue,
      event.currency,
      event.event_date,
      event.event_date
    )
    .run();

  return id;
}


// ============================================================
// AGGREGATE ONE SALES EVENT
// ============================================================

async function aggregateSalesEvent(
  env,
  eventId
) {
  const event =
    await env.DB
      .prepare(`
        SELECT *
        FROM sales_events
        WHERE id = ?
        LIMIT 1
      `)
      .bind(eventId)
      .first();

  if (!event) {
    throw new Error(
      "Sales event not found"
    );
  }

  /*
   * Already aggregated.
   */

  if (
    event.aggregation_status ===
    "aggregated"
  ) {
    return {
      success: true,
      event_id: event.id,
      already_aggregated: true,
      status: "aggregated"
    };
  }

  /*
   * Acquire aggregation lock.
   *
   * Only a pending event can enter processing.
   */

  const lock =
    await env.DB
      .prepare(`
        UPDATE sales_events
        SET
          aggregation_status = 'processing',
          aggregation_error = NULL,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
          AND aggregation_status = 'pending'
      `)
      .bind(eventId)
      .run();

  if (
    !lock.meta ||
    !lock.meta.changes
  ) {
    const current =
      await env.DB
        .prepare(`
          SELECT
            id,
            aggregation_status,
            aggregation_error
          FROM sales_events
          WHERE id = ?
          LIMIT 1
        `)
        .bind(eventId)
        .first();

    if (
      current?.aggregation_status ===
      "aggregated"
    ) {
      return {
        success: true,
        event_id: eventId,
        already_aggregated: true,
        status: "aggregated"
      };
    }

    if (
      current?.aggregation_status ===
      "processing"
    ) {
      return {
        success: false,
        event_id: eventId,
        status: "processing",
        message:
          "Sales event is already being aggregated"
      };
    }

    throw new Error(
      current?.aggregation_error ||
      "Unable to acquire sales aggregation lock"
    );
  }

  try {
    /*
     * --------------------------------------------
     * 1. DAILY
     * --------------------------------------------
     */

    const dailyId =
      await upsertSalesDaily(
        env,
        event
      );

    /*
     * --------------------------------------------
     * 2. TRACK
     * --------------------------------------------
     */

    const trackId =
      await upsertSalesTrack(
        env,
        event
      );

    /*
     * --------------------------------------------
     * 3. RELEASE
     * --------------------------------------------
     */

    const releaseId =
      await upsertSalesRelease(
        env,
        event
      );

    /*
     * --------------------------------------------
     * 4. CHANNEL
     * --------------------------------------------
     */

    const channelId =
      await upsertSalesChannel(
        env,
        event
      );

    /*
     * --------------------------------------------
     * 5. TERRITORY
     * --------------------------------------------
     */

    const territoryId =
      await upsertSalesTerritory(
        env,
        event
      );

    /*
     * --------------------------------------------
     * 6. MARK AGGREGATED
     * --------------------------------------------
     */

    await env.DB
      .prepare(`
        UPDATE sales_events
        SET
          aggregation_status =
            'aggregated',
          aggregated_at =
            CURRENT_TIMESTAMP,
          aggregation_error =
            NULL,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(eventId)
      .run();

    return {
      success: true,

      event_id:
        event.id,

      status:
        "aggregated",

      aggregates: {
        daily_id:
          dailyId,

        track_id:
          trackId,

        release_id:
          releaseId,

        channel_id:
          channelId,

        territory_id:
          territoryId
      }
    };

  } catch (error) {

    /*
     * If aggregation fails, leave it retryable.
     */

    await env.DB
      .prepare(`
        UPDATE sales_events
        SET
          aggregation_status =
            'pending',
          aggregation_error = ?,
          updated_at =
            CURRENT_TIMESTAMP
        WHERE id = ?
      `)
      .bind(
        error?.message ||
          String(error),
        eventId
      )
      .run();

    throw error;
  }
}


// ============================================================
// POST /v1/sales/events
// INGEST ONE SALES EVENT
// ============================================================

if (
  request.method === "POST" &&
  url.pathname === "/v1/sales/events"
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    let body;

    try {
      body =
        await request.json();
    } catch {
      return json(
        {
          success: false,
          error: "Invalid JSON body"
        },
        400
      );
    }

    const sale =
      await normalizeSalesEvent(
        env,
        body,
        userId
      );

    const result =
      await insertSalesEvent(
        env,
        sale
      );

    /*
     * Do not aggregate duplicates again.
     */

    if (result.duplicate) {
      return json({
        success: true,

        duplicate: true,

        message:
          "Sales event already exists",

        event:
          result.event
      });
    }

    /*
     * Automatically aggregate the event.
     */

    const aggregation =
      await aggregateSalesEvent(
        env,
        sale.id
      );

    const event =
      await env.DB
        .prepare(`
          SELECT *
          FROM sales_events
          WHERE id = ?
          LIMIT 1
        `)
        .bind(sale.id)
        .first();

    return json(
      {
        success: true,

        message:
          "Sales event ingested and aggregated successfully",

        event,

        aggregation,

        rate_resolution:
          sale.resolved_rate
      },
      201
    );

  } catch (error) {

    console.error(
      "POST /v1/sales/events error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to ingest sales event"
      },
      400
    );
  }
}


// ============================================================
// POST /v1/sales/events/batch
// BATCH SALES INGESTION
// ============================================================

if (
  request.method === "POST" &&
  url.pathname === "/v1/sales/events/batch"
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    let body;

    try {
      body =
        await request.json();
    } catch {
      return json(
        {
          success: false,
          error: "Invalid JSON body"
        },
        400
      );
    }

    const events =
      Array.isArray(body)
        ? body
        : body.events;

    if (!Array.isArray(events)) {
      return json(
        {
          success: false,
          error:
            "events must be an array"
        },
        400
      );
    }

    if (events.length === 0) {
      return json(
        {
          success: false,
          error:
            "events cannot be empty"
        },
        400
      );
    }

    if (events.length > 100) {
      return json(
        {
          success: false,
          error:
            "Maximum 100 sales events per request"
        },
        400
      );
    }

    const results = [];

    let received = 0;
    let imported = 0;
    let skipped = 0;
    let failed = 0;

    for (
      const input of events
    ) {
      received++;

      try {
        const sale =
          await normalizeSalesEvent(
            env,
            input,
            userId
          );

        const inserted =
          await insertSalesEvent(
            env,
            sale
          );

        if (
          inserted.duplicate
        ) {
          skipped++;

          results.push({
            success: true,
            duplicate: true,
            event_id:
              inserted.event.id,
            source_record_id:
              inserted.event
                .source_record_id,
            message:
              "Sales event already exists"
          });

          continue;
        }

        imported++;

        /*
         * Aggregate immediately.
         */

        const aggregation =
          await aggregateSalesEvent(
            env,
            sale.id
          );

        results.push({
          success: true,
          event_id:
            sale.id,
          duplicate: false,
          aggregation_status:
            aggregation.status,
          rate_resolution:
            sale.resolved_rate
        });

      } catch (error) {

        failed++;

        results.push({
          success: false,
          error:
            error?.message ||
            String(error)
        });
      }
    }

    return json(
      {
        success:
          failed === 0,

        message:
          failed === 0
            ? "Sales batch imported successfully"
            : "Sales batch completed with errors",

        summary: {
          received,
          imported,
          skipped,
          failed
        },

        results
      },
      failed === events.length
        ? 400
        : 201
    );

  } catch (error) {

    console.error(
      "POST /v1/sales/events/batch error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to process sales batch"
      },
      500
    );
  }
}


// ============================================================
// POST /v1/sales/aggregate
// AGGREGATE ONE EXISTING EVENT
// ============================================================

if (
  request.method === "POST" &&
  url.pathname === "/v1/sales/aggregate"
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    let body;

    try {
      body =
        await request.json();
    } catch {
      return json(
        {
          success: false,
          error: "Invalid JSON body"
        },
        400
      );
    }

    const eventId =
      body.event_id;

    if (!eventId) {
      return json(
        {
          success: false,
          error:
            "event_id is required"
        },
        400
      );
    }

    const event =
      await env.DB
        .prepare(`
          SELECT *
          FROM sales_events
          WHERE id = ?
            AND user_id = ?
          LIMIT 1
        `)
        .bind(
          eventId,
          userId
        )
        .first();

    if (!event) {
      return json(
        {
          success: false,
          error:
            "Sales event not found"
        },
        404
      );
    }

    const result =
      await aggregateSalesEvent(
        env,
        eventId
      );

    return json({
      success: true,

      message:
        result.already_aggregated
          ? "Sales event was already aggregated"
          : "Sales event aggregated successfully",

      result
    });

  } catch (error) {

    console.error(
      "POST /v1/sales/aggregate error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to aggregate sales event"
      },
      500
    );
  }
}


// ============================================================
// POST /v1/sales/aggregate/batch
// AGGREGATE MULTIPLE EXISTING EVENTS
// ============================================================

if (
  request.method === "POST" &&
  url.pathname === "/v1/sales/aggregate/batch"
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    let body;

    try {
      body =
        await request.json();
    } catch {
      return json(
        {
          success: false,
          error: "Invalid JSON body"
        },
        400
      );
    }

    let eventIds =
      body.event_ids;

    /*
     * If no event_ids are supplied,
     * process pending events.
     */

    if (
      !Array.isArray(eventIds) ||
      eventIds.length === 0
    ) {
      const pending =
        await env.DB
          .prepare(`
            SELECT id
            FROM sales_events
            WHERE user_id = ?
              AND aggregation_status = 'pending'
            ORDER BY event_date ASC
            LIMIT 100
          `)
          .bind(userId)
          .all();

      eventIds =
        (pending.results || [])
          .map(row => row.id);
    }

    if (eventIds.length === 0) {
      return json({
        success: true,

        message:
          "No pending sales events to aggregate",

        summary: {
          requested: 0,
          aggregated: 0,
          already_aggregated: 0,
          failed: 0
        },

        results: []
      });
    }

    if (eventIds.length > 100) {
      return json(
        {
          success: false,
          error:
            "Maximum 100 events per aggregation request"
        },
        400
      );
    }

    let aggregated = 0;
    let alreadyAggregated = 0;
    let failed = 0;

    const results = [];

    for (
      const eventId of eventIds
    ) {
      try {
        const event =
          await env.DB
            .prepare(`
              SELECT id
              FROM sales_events
              WHERE id = ?
                AND user_id = ?
              LIMIT 1
            `)
            .bind(
              eventId,
              userId
            )
            .first();

        if (!event) {
          failed++;

          results.push({
            success: false,
            event_id: eventId,
            error:
              "Sales event not found"
          });

          continue;
        }

        const result =
          await aggregateSalesEvent(
            env,
            eventId
          );

        if (
          result.already_aggregated
        ) {
          alreadyAggregated++;
        } else if (
          result.status ===
          "aggregated"
        ) {
          aggregated++;
        }

        results.push({
          success: true,
          event_id: eventId,
          ...result
        });

      } catch (error) {

        failed++;

        results.push({
          success: false,
          event_id: eventId,
          error:
            error?.message ||
            String(error)
        });
      }
    }

    return json({
      success:
        failed === 0,

      message:
        failed === 0
          ? "Sales aggregation completed"
          : "Sales aggregation completed with errors",

      summary: {
        requested:
          eventIds.length,

        aggregated,

        already_aggregated:
          alreadyAggregated,

        failed
      },

      results
    });

  } catch (error) {

    console.error(
      "POST /v1/sales/aggregate/batch error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to aggregate sales batch"
      },
      500
    );
  }
}


// ============================================================
// GET /v1/sales/events
// LIST RAW SALES EVENTS
// ============================================================

if (
  request.method === "GET" &&
  url.pathname === "/v1/sales/events"
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    const {
      from,
      to
    } =
      getSalesDateFilters(url);

    const platform =
      url.searchParams.get(
        "platform"
      );

    const territory =
      url.searchParams.get(
        "territory"
      );

    const releaseId =
      url.searchParams.get(
        "release_id"
      );

    const trackId =
      url.searchParams.get(
        "track_id"
      );

    const status =
      url.searchParams.get(
        "aggregation_status"
      );

    let limit =
      Number(
        url.searchParams.get(
          "limit"
        ) || 50
      );

    let offset =
      Number(
        url.searchParams.get(
          "offset"
        ) || 0
      );

    if (
      !Number.isInteger(limit) ||
      limit < 1
    ) {
      return json(
        {
          success: false,
          error:
            "limit must be a positive integer"
        },
        400
      );
    }

    if (limit > 100) {
      limit = 100;
    }

    if (
      !Number.isInteger(offset) ||
      offset < 0
    ) {
      return json(
        {
          success: false,
          error:
            "offset must be a non-negative integer"
        },
        400
      );
    }

    if (
      platform &&
      !isValidSalesPlatform(
        platform
      )
    ) {
      return json(
        {
          success: false,
          error:
            "Invalid platform"
        },
        400
      );
    }

    const conditions = [
      "se.user_id = ?"
    ];

    const params = [
      userId
    ];

    addSalesDateConditions(
      conditions,
      params,
      from,
      to,
      "se.event_date"
    );

    if (platform) {
      conditions.push(
        "se.channel = ?"
      );

      params.push(
        normalizeSalesPlatform(
          platform
        )
      );
    }

    if (territory) {
      conditions.push(
        "se.territory = ?"
      );

      params.push(
        normalizeSalesTerritory(
          territory
        )
      );
    }

    if (releaseId) {
      conditions.push(
        "se.release_id = ?"
      );

      params.push(
        releaseId
      );
    }

    if (trackId) {
      conditions.push(
        "se.track_id = ?"
      );

      params.push(
        trackId
      );
    }

    if (status) {
      conditions.push(
        "se.aggregation_status = ?"
      );

      params.push(
        status
      );
    }

    const where =
      conditions.join(
        " AND "
      );

    const countResult =
      await env.DB
        .prepare(`
          SELECT COUNT(*) AS count
          FROM sales_events se
          WHERE ${where}
        `)
        .bind(...params)
        .first();

    const total =
      Number(
        countResult?.count || 0
      );

    const result =
      await env.DB
        .prepare(`
          SELECT
            se.*
          FROM sales_events se
          WHERE ${where}
          ORDER BY
            se.event_date DESC,
            se.created_at DESC
          LIMIT ?
          OFFSET ?
        `)
        .bind(
          ...params,
          limit,
          offset
        )
        .all();

    const events =
      (result.results || [])
        .map(event => ({
          ...event,

          streams:
            Number(
              event.streams || 0
            ),

          downloads:
            Number(
              event.downloads || 0
            ),

          units:
            Number(
              event.units || 0
            ),

          gross_revenue:
            Number(
              Number(
                event.gross_revenue || 0
              ).toFixed(6)
            ),

          net_revenue:
            Number(
              Number(
                event.net_revenue || 0
              ).toFixed(6)
            ),

          stream_rate:
            event.stream_rate === null
              ? null
              : Number(
                  event.stream_rate
                )
        }));

    return json({
      success: true,

      events,

      pagination: {
        total,
        limit,
        offset,
        returned:
          events.length,
        has_more:
          offset +
            events.length <
          total
      },

      filters: {
        from:
          from || null,

        to:
          to || null,

        platform:
          platform || null,

        territory:
          territory
            ? normalizeSalesTerritory(
                territory
              )
            : null,

        release_id:
          releaseId || null,

        track_id:
          trackId || null,

        aggregation_status:
          status || null
      }
    });

  } catch (error) {

    console.error(
      "GET /v1/sales/events error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to load sales events"
      },
      500
    );
  }
}

// ============================================================
// POST /v1/sales/imports
// Create and process a distributor sales import
// ============================================================

if (
  request.method === "POST" &&
  url.pathname === "/v1/sales/imports"
) {
  const authResult = await requireSalesAuth(
    request,
    env
  );

  if (!authResult.success) {
    return authResult.response;
  }

  const userId = authResult.userId;

  try {
    const body = await request.json();

    const source = normalizeImportSource(
      body.source
    );

    const sourceReportId = String(
      body.source_report_id ||
      body.report_id ||
      ""
    ).trim();

    const sourceValidation =
      validateImportSource(source);

    if (!sourceValidation.valid) {
      return json({
        success: false,
        error: sourceValidation.error
      }, 400);
    }

    const reportValidation =
      validateImportReportId(sourceReportId);

    if (!reportValidation.valid) {
      return json({
        success: false,
        error: reportValidation.error
      }, 400);
    }

    const rows = normalizeImportRows(body);

    if (!rows.length) {
      return json({
        success: false,
        error: "No sales rows supplied"
      }, 400);
    }

    if (rows.length > SALES_IMPORT_MAX_ROWS) {
      return json({
        success: false,
        error:
          `Import cannot contain more than ${SALES_IMPORT_MAX_ROWS} rows`
      }, 400);
    }

    // --------------------------------------------------------
    // Import-level idempotency
    // --------------------------------------------------------

    const existingImport =
      await env.DB.prepare(`
        SELECT *
        FROM sales_imports
        WHERE user_id = ?
          AND source = ?
          AND source_report_id = ?
        LIMIT 1
      `)
        .bind(
          userId,
          source,
          sourceReportId
        )
        .first();

    if (existingImport) {
      return json({
        success: true,
        duplicate: true,
        message:
          "This distributor report has already been imported",
        import: existingImport
      });
    }

    const importId =
      generateSalesImportId();

    // --------------------------------------------------------
    // Create import
    // --------------------------------------------------------

    await env.DB.prepare(`
      INSERT INTO sales_imports (
        id,
        user_id,
        source,
        source_report_id,
        period_start,
        period_end,
        status,
        records_received,
        records_imported,
        records_skipped,
        total_gross_revenue,
        total_net_revenue,
        currency,
        started_at
      )
      VALUES (
        ?, ?, ?, ?, NULL, NULL,
        'processing',
        ?, 0, 0, 0, 0, NULL,
        CURRENT_TIMESTAMP
      )
    `)
      .bind(
        importId,
        userId,
        source,
        sourceReportId,
        rows.length
      )
      .run();

    let imported = 0;
    let skipped = 0;
    let failed = 0;

    let totalGross = 0;
    let totalNet = 0;

    const currencies = new Set();

    let periodStart = null;
    let periodEnd = null;

    const rowResults = [];

    // --------------------------------------------------------
    // Process rows
    // --------------------------------------------------------

    for (
      let index = 0;
      index < rows.length;
      index++
    ) {
      const rowNumber = index + 1;
      const rawRow = rows[index];

      const normalized =
        normalizeImportedSalesRow(
          rawRow,
          rowNumber
        );

      const data = normalized.data;

      const validationErrors =
        validateImportedSalesRow(data);

      if (validationErrors.length) {
        failed++;

        for (
          const validationError
          of validationErrors
        ) {
          await createSalesImportError(
            env,
            {
              importId,
              rowNumber,
              sourceRecordId:
                data.source_record_id,
              errorCode:
                validationError.code,
              errorMessage:
                validationError.message,
              rawData: rawRow
            }
          );
        }

        rowResults.push({
          row: rowNumber,
          status: "failed",
          errors: validationErrors
        });

        continue;
      }

      // ------------------------------------------------------
      // Duplicate row detection
      // ------------------------------------------------------

      const existingEvent =
        await findExistingSalesEvent(
          env,
          userId,
          source,
          data.source_record_id
        );

      if (existingEvent) {
        skipped++;

        rowResults.push({
          row: rowNumber,
          status: "duplicate",
          source_record_id:
            data.source_record_id,
          existing_event_id:
            existingEvent.id
        });

        continue;
      }

      // ------------------------------------------------------
      // Insert sales event
      // ------------------------------------------------------

      try {
        const eventId =
          `sale_${crypto.randomUUID()}`;

        await env.DB.prepare(`
          INSERT INTO sales_events (
            id,
            user_id,
            release_id,
            track_id,
            isrc,
            artist_id,
            channel,
            territory,
            sale_type,
            event_date,
            streams,
            downloads,
            units,
            gross_revenue,
            net_revenue,
            currency,
            stream_rate,
            source,
            source_record_id,
            metadata_json
          )
          VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          )
        `)
          .bind(
            eventId,
            userId,
            data.release_id,
            data.track_id,
            data.isrc,
            data.artist_id,
            data.channel,
            data.territory,
            data.sale_type,
            data.event_date,
            data.streams,
            data.downloads,
            data.units,
            data.gross_revenue,
            data.net_revenue,
            data.currency,
            data.stream_rate,
            source,
            data.source_record_id,
            data.metadata_json
              ? JSON.stringify(
                  data.metadata_json
                )
              : null
          )
          .run();

        // ----------------------------------------------------
        // Automatic aggregation
        // ----------------------------------------------------

        const aggregation =
          await aggregateSalesEvent(
            env,
            eventId
          );

        if (
          !aggregation ||
          aggregation.success !== true
        ) {
          throw new Error(
            "Sales event aggregation failed"
          );
        }

        imported++;

        totalGross +=
          data.gross_revenue;

        totalNet +=
          data.net_revenue;

        currencies.add(
          data.currency
        );

        if (
          !periodStart ||
          data.event_date < periodStart
        ) {
          periodStart =
            data.event_date;
        }

        if (
          !periodEnd ||
          data.event_date > periodEnd
        ) {
          periodEnd =
            data.event_date;
        }

        rowResults.push({
          row: rowNumber,
          status: "imported",
          event_id: eventId,
          aggregation:
            aggregation
        });

      } catch (error) {
        failed++;

        await createSalesImportError(
          env,
          {
            importId,
            rowNumber,
            sourceRecordId:
              data.source_record_id,
            errorCode:
              "ROW_IMPORT_FAILED",
            errorMessage:
              error?.message ||
              "Failed to import sales row",
            rawData: rawRow
          }
        );

        rowResults.push({
          row: rowNumber,
          status: "failed",
          errors: [
            {
              code:
                "ROW_IMPORT_FAILED",
              message:
                error?.message ||
                "Failed to import sales row"
            }
          ]
        });
      }
    }

    // --------------------------------------------------------
    // Determine currency
    // --------------------------------------------------------

    const importCurrency =
      currencies.size === 1
        ? [...currencies][0]
        : null;

    // --------------------------------------------------------
    // Determine import status
    // --------------------------------------------------------

    let status = "completed";

    if (failed > 0 && imported > 0) {
      status = "completed_with_errors";
    } else if (failed > 0 && imported === 0) {
      status = "failed";
    }

    // --------------------------------------------------------
    // Update import
    // --------------------------------------------------------

    await env.DB.prepare(`
      UPDATE sales_imports
      SET
        period_start = ?,
        period_end = ?,
        status = ?,
        records_imported = ?,
        records_skipped = ?,
        total_gross_revenue = ?,
        total_net_revenue = ?,
        currency = ?,
        completed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(
        periodStart,
        periodEnd,
        status,
        imported,
        skipped,
        totalGross,
        totalNet,
        importCurrency,
        importId,
        userId
      )
      .run();

    const finalImport =
      await env.DB.prepare(`
        SELECT *
        FROM sales_imports
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
        .bind(
          importId,
          userId
        )
        .first();

    return json({
      success: true,
      message:
        "Sales import processed",
      import: finalImport,
      summary: {
        records_received:
          rows.length,
        records_imported:
          imported,
        records_skipped:
          skipped,
        records_failed:
          failed,
        currencies:
          [...currencies]
      },
      rows: rowResults
    }, 201);

  } catch (error) {
    console.error(
      "POST /v1/sales/imports error:",
      error
    );

    return json({
      success: false,
      error:
        "Failed to process sales import",
      details:
        error?.message ||
        String(error)
    }, 500);
  }
}

// ============================================================
// GET /v1/sales/imports/:id/errors
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.match(
    /^\/v1\/sales\/imports\/[^/]+\/errors$/
  )
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.success) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    const parts =
      url.pathname.split("/");

    const importId = parts[4];

    if (!importId) {
      return json({
        success: false,
        error: "Import ID is required"
      }, 400);
    }

    const salesImport =
      await env.DB.prepare(`
        SELECT *
        FROM sales_imports
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
        .bind(
          importId,
          userId
        )
        .first();

    if (!salesImport) {
      return json({
        success: false,
        error: "Sales import not found"
      }, 404);
    }

    const errors =
      await env.DB.prepare(`
        SELECT *
        FROM sales_import_errors
        WHERE import_id = ?
        ORDER BY row_number ASC
      `)
        .bind(importId)
        .all();

    return json({
      success: true,
      import: salesImport,
      errors:
        errors.results || [],
      total_errors:
        (errors.results || []).length
    });

  } catch (error) {
    console.error(
      "GET sales import errors:",
      error
    );

    return json({
      success: false,
      error:
        "Failed to retrieve import errors",
      details:
        error?.message ||
        String(error)
    }, 500);
  }
}

// ============================================================
// POST /v1/sales/imports/:id/retry
// Retry failed import rows
// ============================================================

if (
  request.method === "POST" &&
  url.pathname.match(
    /^\/v1\/sales\/imports\/[^/]+\/retry$/
  )
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.success) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    const parts =
      url.pathname.split("/");

    const importId = parts[4];

    const salesImport =
      await env.DB.prepare(`
        SELECT *
        FROM sales_imports
        WHERE id = ?
          AND user_id = ?
        LIMIT 1
      `)
        .bind(
          importId,
          userId
        )
        .first();

    if (!salesImport) {
      return json({
        success: false,
        error: "Sales import not found"
      }, 404);
    }

    const errorsResult =
      await env.DB.prepare(`
        SELECT *
        FROM sales_import_errors
        WHERE import_id = ?
          AND status = 'failed'
        ORDER BY row_number ASC
      `)
        .bind(importId)
        .all();

    const errors =
      errorsResult.results || [];

    if (!errors.length) {
      return json({
        success: true,
        message:
          "There are no failed rows to retry",
        import: salesImport,
        retried: 0
      });
    }

    let imported = 0;
    let skipped = 0;
    let stillFailed = 0;

    for (const errorRow of errors) {
      let rawData;

      try {
        rawData = JSON.parse(
          errorRow.raw_data_json
        );
      } catch {
        stillFailed++;

        await env.DB.prepare(`
          UPDATE sales_import_errors
          SET
            retry_count = retry_count + 1,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(errorRow.id)
          .run();

        continue;
      }

      const normalized =
        normalizeImportedSalesRow(
          rawData,
          errorRow.row_number
        );

      const data =
        normalized.data;

      const validationErrors =
        validateImportedSalesRow(
          data
        );

      if (validationErrors.length) {
        stillFailed++;

        await env.DB.prepare(`
          UPDATE sales_import_errors
          SET
            retry_count = retry_count + 1,
            error_code = ?,
            error_message = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(
            validationErrors[0].code,
            validationErrors[0].message,
            errorRow.id
          )
          .run();

        continue;
      }

      const existingEvent =
        await findExistingSalesEvent(
          env,
          userId,
          salesImport.source,
          data.source_record_id
        );

      if (existingEvent) {
        skipped++;

        await env.DB.prepare(`
          UPDATE sales_import_errors
          SET
            status = 'resolved',
            resolved_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(errorRow.id)
          .run();

        continue;
      }

      try {
        const eventId =
          `sale_${crypto.randomUUID()}`;

        await env.DB.prepare(`
          INSERT INTO sales_events (
            id,
            user_id,
            release_id,
            track_id,
            isrc,
            artist_id,
            channel,
            territory,
            sale_type,
            event_date,
            streams,
            downloads,
            units,
            gross_revenue,
            net_revenue,
            currency,
            stream_rate,
            source,
            source_record_id,
            metadata_json
          )
          VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          )
        `)
          .bind(
            eventId,
            userId,
            data.release_id,
            data.track_id,
            data.isrc,
            data.artist_id,
            data.channel,
            data.territory,
            data.sale_type,
            data.event_date,
            data.streams,
            data.downloads,
            data.units,
            data.gross_revenue,
            data.net_revenue,
            data.currency,
            data.stream_rate,
            salesImport.source,
            data.source_record_id,
            data.metadata_json
              ? JSON.stringify(
                  data.metadata_json
                )
              : null
          )
          .run();

        const aggregation =
          await aggregateSalesEvent(
            env,
            eventId
          );

        if (
          !aggregation ||
          aggregation.success !== true
        ) {
          throw new Error(
            "Sales event aggregation failed"
          );
        }

        imported++;

        await env.DB.prepare(`
          UPDATE sales_import_errors
          SET
            status = 'resolved',
            resolved_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(errorRow.id)
          .run();

      } catch (error) {
        stillFailed++;

        await env.DB.prepare(`
          UPDATE sales_import_errors
          SET
            retry_count = retry_count + 1,
            error_code = 'RETRY_FAILED',
            error_message = ?,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = ?
        `)
          .bind(
            error?.message ||
              "Retry failed",
            errorRow.id
          )
          .run();
      }
    }

    const remainingResult =
      await env.DB.prepare(`
        SELECT COUNT(*) AS count
        FROM sales_import_errors
        WHERE import_id = ?
          AND status = 'failed'
      `)
        .bind(importId)
        .first();

    const remaining =
      Number(
        remainingResult?.count || 0
      );

    let status;

    if (remaining > 0) {
      status = "completed_with_errors";
    } else {
      status = "completed";
    }

    await env.DB.prepare(`
      UPDATE sales_imports
      SET
        records_imported =
          records_imported + ?,
        records_skipped =
          records_skipped + ?,
        status = ?,
        completed_at = CURRENT_TIMESTAMP,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
        AND user_id = ?
    `)
      .bind(
        imported,
        skipped,
        status,
        importId,
        userId
      )
      .run();

    const finalImport =
      await env.DB.prepare(`
        SELECT *
        FROM sales_imports
        WHERE id = ?
        LIMIT 1
      `)
        .bind(importId)
        .first();

    return json({
      success: true,
      message:
        "Failed sales rows retried",
      import: finalImport,
      retry: {
        attempted: errors.length,
        imported,
        skipped,
        still_failed: remaining
      }
    });

  } catch (error) {
    console.error(
      "POST sales import retry error:",
      error
    );

    return json({
      success: false,
      error:
        "Failed to retry sales import rows",
      details:
        error?.message ||
        String(error)
    }, 500);
  }
}


// ============================================================
// GET /v1/sales/events/:id
// GET ONE RAW SALES EVENT
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.startsWith(
    "/v1/sales/events/"
  ) &&
  !url.pathname.endsWith(
    "/batch"
  )
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    const parts =
      url.pathname.split("/");

    const eventId =
      parts[4];

    if (!eventId) {
      return json(
        {
          success: false,
          error:
            "Sales event ID is required"
        },
        400
      );
    }

    const event =
      await env.DB
        .prepare(`
          SELECT *
          FROM sales_events
          WHERE id = ?
            AND user_id = ?
          LIMIT 1
        `)
        .bind(
          eventId,
          userId
        )
        .first();

    if (!event) {
      return json(
        {
          success: false,
          error:
            "Sales event not found"
        },
        404
      );
    }

    return json({
      success: true,

      event: {
        ...event,

        streams:
          Number(
            event.streams || 0
          ),

        downloads:
          Number(
            event.downloads || 0
          ),

        units:
          Number(
            event.units || 0
          ),

        gross_revenue:
          Number(
            Number(
              event.gross_revenue || 0
            ).toFixed(6)
          ),

        net_revenue:
          Number(
            Number(
              event.net_revenue || 0
            ).toFixed(6)
          ),

        stream_rate:
          event.stream_rate === null
            ? null
            : Number(
                event.stream_rate
              )
      }
    });

  } catch (error) {

    console.error(
      "GET /v1/sales/events/:id error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to load sales event"
      },
      500
    );
  }
}


// ============================================================
// GET /v1/sales/imports/:id
// GET IMPORT STATUS
// ============================================================

if (
  request.method === "GET" &&
  url.pathname.startsWith(
    "/v1/sales/imports/"
  )
) {
  const authResult =
    await requireSalesAuth(
      request,
      env
    );

  if (!authResult.ok) {
    return authResult.response;
  }

  const userId =
    authResult.userId;

  try {
    const parts =
      url.pathname.split("/");

    const importId =
      parts[4];

    if (!importId) {
      return json(
        {
          success: false,
          error:
            "Import ID is required"
        },
        400
      );
    }

    // --------------------------------------------------------
    // LOAD IMPORT
    // --------------------------------------------------------

    const salesImport =
      await env.DB
        .prepare(`
          SELECT *
          FROM sales_imports
          WHERE id = ?
            AND user_id = ?
          LIMIT 1
        `)
        .bind(
          importId,
          userId
        )
        .first();

    if (!salesImport) {
      return json(
        {
          success: false,
          error:
            "Sales import not found"
        },
        404
      );
    }

    // --------------------------------------------------------
    // LOAD ROW-LEVEL ERROR SUMMARY
    // --------------------------------------------------------

    const errorSummary =
      await env.DB
        .prepare(`
          SELECT
            COUNT(*) AS total,

            SUM(
              CASE
                WHEN status = 'failed'
                THEN 1
                ELSE 0
              END
            ) AS failed,

            SUM(
              CASE
                WHEN status = 'resolved'
                THEN 1
                ELSE 0
              END
            ) AS resolved

          FROM sales_import_errors
          WHERE import_id = ?
        `)
        .bind(importId)
        .first();

    // --------------------------------------------------------
    // RETURN IMPORT STATUS
    // --------------------------------------------------------

    return json({
      success: true,

      import: {
        ...salesImport,

        records_received:
          Number(
            salesImport
              .records_received || 0
          ),

        records_imported:
          Number(
            salesImport
              .records_imported || 0
          ),

        records_skipped:
          Number(
            salesImport
              .records_skipped || 0
          ),

        total_gross_revenue:
          Number(
            Number(
              salesImport
                .total_gross_revenue ||
                0
            ).toFixed(6)
          ),

        total_net_revenue:
          Number(
            Number(
              salesImport
                .total_net_revenue ||
                0
            ).toFixed(6)
          )
      },

      // ------------------------------------------------------
      // ROW-LEVEL IMPORT ERRORS
      // ------------------------------------------------------

      errors: {
        total:
          Number(
            errorSummary?.total || 0
          ),

        failed:
          Number(
            errorSummary?.failed || 0
          ),

        resolved:
          Number(
            errorSummary?.resolved || 0
          )
      }
    });

  } catch (error) {

    console.error(
      "GET /v1/sales/imports/:id error:",
      error
    );

    return json(
      {
        success: false,
        error:
          error?.message ||
          "Failed to load sales import"
      },
      500
    );
  }
}

    // -------------------------
    // 404
    // -------------------------

    return json({
      success: false,
      error: "Endpoint not found"
    }, 404);
  }
};

/**
 * Proxy helper for Cloudflare API calls.
 * All requests go through this so the API token never leaves the Worker.
 */

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

export const SUPER_ADMIN_ROLE_ID = '33666b9c79b9a5273fc7344ff42f953d';

export const STANDARD_SUB_USER_PERMISSIONS = [
  'ssl:read', 'ssl:write',
  'bots:read', 'bots:write',
  'analytics:read',
  'dns:read',
  'cache:purge',
];

export const OPERATION_ALLOWLIST = [
  { method: 'GET',   pattern: /^\/api\/zones\/?$/,                          permission: null },
  { method: 'POST',  pattern: /^\/api\/zones\/refresh\/?$/,                 permission: null },
  { method: 'GET',   pattern: /^\/api\/zones\/security-insights\/?$/,       permission: null },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/?$/,                   permission: null },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/rule-counts\/?$/,      permission: null },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/ssl\/?$/,              permission: 'ssl:read' },
  { method: 'PATCH', pattern: /^\/api\/zones\/[^/]+\/ssl\/.+$/,             permission: 'ssl:write' },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/bots\/.+$/,            permission: 'bots:read' },
  { method: 'PUT',   pattern: /^\/api\/zones\/[^/]+\/bots\/config\/?$/,     permission: 'bots:write' },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/dns\/?$/,              permission: 'dns:read' },
  { method: 'GET',   pattern: /^\/api\/zones\/[^/]+\/analytics\/.*/,        permission: 'analytics:read' },
  { method: 'POST',  pattern: /^\/api\/zones\/[^/]+\/purge\/?$/,            permission: 'cache:purge' },
  { method: 'GET',   pattern: /^\/api\/me\/?$/,                             permission: null },
  { method: 'GET',   pattern: /^\/api\/auth\/check\/?$/,                    permission: null },
];

// ──────────────────────────────────────────────
// Token encryption helpers (AES-256-GCM + HKDF)
// ──────────────────────────────────────────────

let _cachedKey = null;
let _cachedKeySecret = null;

async function deriveKey(secret) {
  if (_cachedKey && _cachedKeySecret === secret) return _cachedKey;

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    'HKDF',
    false,
    ['deriveKey'],
  );

  _cachedKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: new TextEncoder().encode('cf-dash-token') },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  _cachedKeySecret = secret;
  return _cachedKey;
}

export async function encryptToken(plaintext, secret) {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

  // Combine iv + ciphertext and base64-encode
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertext), iv.length);

  return btoa(String.fromCharCode(...combined));
}

export async function decryptToken(encoded, secret) {
  const key = await deriveKey(secret);
  const combined = Uint8Array.from(atob(encoded), c => c.charCodeAt(0));

  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  return new TextDecoder().decode(decrypted);
}

// ──────────────────────────────────────────────
// CF API helpers
// ──────────────────────────────────────────────

/**
 * Call CF API using a provided token (used during login only — token is not stored)
 */
export async function cfApiWithToken(token, path, options = {}) {
  const { method = 'GET', params } = options;
  let url = `${CF_API_BASE}${path}`;
  if (params) url += `?${new URLSearchParams(params)}`;

  try {
    const res = await fetch(url, {
      method,
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
    });
    return await res.json();
  } catch (err) {
    return { success: false, errors: [{ message: err.message }] };
  }
}

export async function cfApi(env, path, options = {}, token = null) {
  const { method = 'GET', body, params } = options;

  let url = `${CF_API_BASE}${path}`;

  // Append query params
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }

  const bearerToken = token ?? env.CF_API_TOKEN;
  const headers = {
    'Authorization': `Bearer ${bearerToken}`,
    'Content-Type': 'application/json',
  };

  const fetchOptions = { method, headers };
  if (body && ['POST', 'PUT', 'PATCH'].includes(method)) {
    fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  try {
    const response = await fetch(url, fetchOptions);
    const data = await response.json();

    if (!data.success && response.status !== 404) {
      console.error(`[cfApi] ${method} ${path} → ${response.status}`, JSON.stringify(data.errors));
    }

    return data;
  } catch (err) {
    console.error(`[cfApi] ${method} ${path} threw:`, err.message);
    return { success: false, errors: [{ message: err.message }] };
  }
}

/**
 * GraphQL helper for Cloudflare Analytics API
 */
export async function cfGraphQL(env, query, variables = {}, token = null) {
  const bearerToken = token ?? env.CF_API_TOKEN;
  try {
    const response = await fetch(`${CF_API_BASE}/graphql`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ query, variables }),
    });

    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch {
      console.error(`[cfGraphQL] Non-JSON response (${response.status}):`, text.slice(0, 500));
      return { data: null, errors: [{ message: `Non-JSON response: ${response.status}` }] };
    }
  } catch (err) {
    console.error(`[cfGraphQL] Fetch threw:`, err.message);
    return { data: null, errors: [{ message: err.message }] };
  }
}

/**
 * Factory that returns API helpers bound to the user's decrypted token from Hono context.
 */
export function userApiClient(c) {
  const token = c.get('userToken');
  return {
    api: (path, opts = {}) => cfApi(c.env, path, opts, token),
    graphql: (query, vars = {}) => cfGraphQL(c.env, query, vars, token),
  };
}

/**
 * Check if a user has a specific permission on a zone
 */
export function hasPermission(zoneConfig, permission) {
  if (!zoneConfig || !zoneConfig.permissions) return false;
  return zoneConfig.permissions.includes(permission);
}

/**
 * KV cache helper for tab data.
 * Returns cached data if available and refresh not requested.
 * Calls fetchFn to get fresh data, stores result in KV, returns it.
 */
export async function withCache(c, cacheKey, fetchFn) {
  const refresh = c.req.query('refresh') === 'true';
  const kv = c.env.USER_CONFIG;

  if (!refresh) {
    const cached = await kv.get(cacheKey, 'json');
    if (cached) {
      return c.json(cached);
    }
  }

  try {
    const data = await fetchFn();
    const record = { ...data, _cachedAt: new Date().toISOString() };
    // Store in KV with 10 minute TTL so stale data eventually expires
    await kv.put(cacheKey, JSON.stringify(record), { expirationTtl: 600 });
    return c.json(record);
  } catch (err) {
    // On error, try to return stale cache if available
    const stale = await kv.get(cacheKey, 'json');
    if (stale) {
      return c.json(stale);
    }
    return c.json({ error: err.message }, 500);
  }
}

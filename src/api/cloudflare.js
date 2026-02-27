/**
 * Proxy helper for Cloudflare API calls.
 * All requests go through this so the API token never leaves the Worker.
 */

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

export async function cfApi(env, path, options = {}) {
  const { method = 'GET', body, params } = options;

  let url = `${CF_API_BASE}${path}`;

  // Append query params
  if (params) {
    const qs = new URLSearchParams(params).toString();
    url += `?${qs}`;
  }

  const headers = {
    'Authorization': `Bearer ${env.CF_API_TOKEN}`,
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
export async function cfGraphQL(env, query, variables = {}) {
  try {
    const response = await fetch(`${CF_API_BASE}/graphql`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.CF_API_TOKEN}`,
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

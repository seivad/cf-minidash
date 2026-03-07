import { Hono } from 'hono';
import { setCookie, deleteCookie, getCookie } from 'hono/cookie';
import { cfApiWithToken, encryptToken, SUPER_ADMIN_ROLE_ID, STANDARD_SUB_USER_PERMISSIONS } from './cloudflare.js';

export const authRoutes = new Hono();

/**
 * Derive a stable short identifier from a token (for KV cache keys and display).
 * Uses first 12 chars of SHA-256 hash — never stores the raw token.
 */
async function tokenFingerprint(token) {
  const data = new TextEncoder().encode(token);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const hex = [...new Uint8Array(hash)].map(b => b.toString(16).padStart(2, '0')).join('');
  return hex.slice(0, 12);
}

/**
 * Probe which capabilities the user's token has on a sample zone.
 * Returns an object like { ssl: true, bots: false, analytics: true, dns: true, ... }
 */
async function probeZoneCapabilities(token, sampleZoneId) {
  const probes = {
    ssl:       `/zones/${sampleZoneId}/settings`,
    bots:      `/zones/${sampleZoneId}/bot_management`,
    analytics: `/graphql`,  // will test via a lightweight query below
    dns:       `/zones/${sampleZoneId}/dns_records?per_page=1`,
  };

  const results = {};
  const probeEntries = Object.entries(probes).filter(([k]) => k !== 'analytics');

  const settled = await Promise.allSettled(
    probeEntries.map(async ([key, path]) => {
      const res = await cfApiWithToken(token, path);
      return [key, res.success === true];
    })
  );

  for (const result of settled) {
    if (result.status === 'fulfilled') {
      const [key, ok] = result.value;
      results[key] = ok;
    }
  }

  // Lightweight analytics probe — just test the endpoint accepts auth
  try {
    const res = await cfApiWithToken(token, '/graphql');
    // GraphQL endpoint returns data even on empty query; 403 means no access
    results.analytics = !(res.errors?.[0]?.message || '').includes('authentication');
  } catch {
    results.analytics = false;
  }

  return results;
}

/**
 * Probe account-level capabilities with the user's token.
 */
async function probeAccountCapabilities(token, accountId) {
  const caps = { hasSecurityInsights: false, hasAccountMembers: false };

  const [insightsRes, membersRes] = await Promise.allSettled([
    cfApiWithToken(token, `/accounts/${accountId}/security-center/insights`, { params: { per_page: '1' } }),
    cfApiWithToken(token, `/accounts/${accountId}/members`),
  ]);

  if (insightsRes.status === 'fulfilled' && insightsRes.value.success) {
    caps.hasSecurityInsights = true;
  }
  if (membersRes.status === 'fulfilled' && membersRes.value.success) {
    caps.hasAccountMembers = true;
  }

  return caps;
}

/**
 * POST /api/auth/login
 * CF API token login flow:
 * 1. Verify token works (try /user/tokens/verify, fall back to zone probe)
 * 2. Optionally get user email via /user
 * 3. Check if super admin via account members (using user's token)
 * 4. Discover zones (using user's token only — no cross-reference)
 * 5. Probe capabilities on a sample zone
 * 6. Encrypt and store token in KV session
 */
authRoutes.post('/login', async (c) => {
  const { apiToken } = await c.req.json();

  if (!apiToken || typeof apiToken !== 'string' || apiToken.trim().length < 10) {
    return c.json({ error: 'A valid Cloudflare API token is required' }, 400);
  }

  const token = apiToken.trim();
  const accountId = c.env.CF_ACCOUNT_ID;

  // 1. Verify token — try /user/tokens/verify first, fall back to zone probe
  let email = null;
  let tokenValid = false;

  const verify = await cfApiWithToken(token, '/user/tokens/verify');
  if (verify.success && verify.result?.status === 'active') {
    tokenValid = true;

    // Try to get user email (requires User Details:Read on token)
    const userInfo = await cfApiWithToken(token, '/user');
    if (userInfo.success && userInfo.result?.email) {
      email = userInfo.result.email.toLowerCase();
    }
  } else {
    // Token might be valid but /user/tokens/verify doesn't recognize it
    // (e.g. account-owned or service token). Verify by probing zones.
    const probeZones = await cfApiWithToken(token, '/zones', {
      params: { 'account.id': accountId, per_page: '1' },
    });
    if (probeZones.success && probeZones.result) {
      tokenValid = true;
    }
  }

  if (!tokenValid) {
    const detail = verify.errors?.[0]?.message || JSON.stringify(verify.errors || verify);
    return c.json({ error: `Token verification failed: ${detail}` }, 401);
  }

  // 2. Check super admin status using user's own token (graceful if no permission)
  let isSuperAdmin = false;

  if (email) {
    const members = await cfApiWithToken(token, `/accounts/${accountId}/members`);
    if (members.success && members.result) {
      const member = members.result.find(m =>
        m.user?.email?.toLowerCase() === email
      );
      if (member) {
        isSuperAdmin = member.roles?.some(r => r.id === SUPER_ADMIN_ROLE_ID) || false;
      }
    }
    // If token lacks permission for /members, isSuperAdmin stays false (graceful)
  }

  // 3. Discover zones using user's own token — no cross-reference needed
  const allowedZones = [];
  let page = 1;
  while (true) {
    const data = await cfApiWithToken(token, '/zones', {
      params: { page: String(page), per_page: '50', order: 'name', direction: 'asc' },
    });
    if (!data.success || !data.result?.length) break;
    for (const z of data.result) {
      allowedZones.push({ id: z.id, name: z.name });
    }
    if (page >= (data.result_info?.total_pages || 1)) break;
    page++;
  }

  if (!allowedZones.length) {
    return c.json({ error: 'Token has no access to any zones' }, 403);
  }

  // 4. Probe capabilities on a sample zone
  const sampleZoneId = allowedZones[0].id;
  const zoneCapabilities = await probeZoneCapabilities(token, sampleZoneId);
  const accountCapabilities = await probeAccountCapabilities(token, accountId);

  const capabilities = { ...zoneCapabilities, ...accountCapabilities };

  // 5. Build identity — use email if available, otherwise a token fingerprint
  const identity = email || `token:${await tokenFingerprint(token)}`;

  // 6. Build permissions
  const permissions = isSuperAdmin
    ? [...STANDARD_SUB_USER_PERMISSIONS, 'dns:write']
    : [...STANDARD_SUB_USER_PERMISSIONS];

  // 7. Encrypt the user's token for storage
  const encryptedToken = await encryptToken(token, c.env.AUTH_SECRET);

  // 8. Create session in KV
  const sessionId = crypto.randomUUID();
  const session = {
    email: identity,
    isSuperAdmin,
    allowedZones,
    permissions,
    capabilities,
    encryptedToken,
    createdAt: Date.now(),
    expiresAt: Date.now() + (24 * 60 * 60 * 1000),
  };

  await c.env.USER_CONFIG.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: 86400 }
  );

  setCookie(c, 'session', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: 86400,
    path: '/',
  });

  return c.json({
    ok: true,
    email: identity,
    isSuperAdmin,
    permissions,
    capabilities,
    zones: allowedZones,
  });
});

/**
 * POST /api/auth/logout
 */
authRoutes.post('/logout', async (c) => {
  const sessionId = getCookie(c, 'session');

  if (sessionId) {
    await c.env.USER_CONFIG.delete(`session:${sessionId}`);
    deleteCookie(c, 'session');
  }

  return c.json({ ok: true });
});

/**
 * GET /api/auth/check
 * Check if the current session is valid
 */
authRoutes.get('/check', async (c) => {
  const session = c.get('session');
  if (!session) {
    return c.json({ authenticated: false }, 401);
  }

  return c.json({
    authenticated: true,
    email: session.email,
    isSuperAdmin: session.isSuperAdmin,
    permissions: session.permissions,
    capabilities: session.capabilities,
    zones: session.allowedZones,
  });
});

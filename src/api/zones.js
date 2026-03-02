import { Hono } from 'hono';
import { cfApi, withCache } from './cloudflare.js';

export const zonesRoutes = new Hono();

/**
 * Fetch all zones from the Cloudflare account API
 */
async function fetchZonesFromCF(env, permissions) {
  const accountId = env.CF_ACCOUNT_ID;

  const allZones = [];
  let page = 1;
  while (true) {
    const data = await cfApi(env, '/zones', {
      params: { 'account.id': accountId, page: String(page), per_page: '50', order: 'name', direction: 'asc' },
    });

    if (!data.success || !data.result?.length) break;

    for (const z of data.result) {
      allZones.push({
        id: z.id,
        name: z.name,
        status: z.status,
        paused: z.paused,
        plan: z.plan?.name,
        nameServers: z.name_servers,
        permissions,
      });
    }

    const totalPages = data.result_info?.total_pages || 1;
    if (page >= totalPages) break;
    page++;
  }

  return allZones;
}

/**
 * GET /api/zones
 * Returns cached zones from KV. If none cached, fetches from CF API and stores them.
 * Sub-users only see zones in their session's allowedZones list.
 */
zonesRoutes.get('/', async (c) => {
  const session = c.get('session');
  const email = session.email;
  const kvKey = `zones:${email}`;

  // Try loading from KV cache
  const cached = await c.env.USER_CONFIG.get(kvKey, 'json');
  if (cached && cached.zones?.length) {
    const zones = filterZonesForSession(cached.zones, session);
    return c.json({ zones, lastRefreshed: cached.lastRefreshed });
  }

  // No cache — fetch from CF API and store
  const allZones = await fetchZonesFromCF(c.env, session.permissions);
  const record = { zones: allZones, lastRefreshed: new Date().toISOString() };
  await c.env.USER_CONFIG.put(kvKey, JSON.stringify(record));

  const zones = filterZonesForSession(allZones, session);
  return c.json({ zones, lastRefreshed: record.lastRefreshed });
});

/**
 * POST /api/zones/refresh
 * Fetches fresh zones from CF API, merges with cached data, and stores in KV.
 */
zonesRoutes.post('/refresh', async (c) => {
  const session = c.get('session');
  const email = session.email;
  const kvKey = `zones:${email}`;

  const allZones = await fetchZonesFromCF(c.env, session.permissions);
  const record = { zones: allZones, lastRefreshed: new Date().toISOString() };
  await c.env.USER_CONFIG.put(kvKey, JSON.stringify(record));

  const zones = filterZonesForSession(allZones, session);
  return c.json({ zones, lastRefreshed: record.lastRefreshed });
});

/**
 * Filter zones to only those the session is allowed to see.
 * Super admins see all; sub-users see only their allowedZones.
 */
function filterZonesForSession(zones, session) {
  if (session.isSuperAdmin) return zones;
  const allowedIds = new Set(session.allowedZones.map(z => z.id));
  return zones.filter(z => allowedIds.has(z.id));
}

/**
 * GET /api/zones/security-insights
 * Fetch account-level security insights, grouped by zone
 */
zonesRoutes.get('/security-insights', async (c) => {
  const session = c.get('session');
  const email = session.email;
  const accountId = c.env.CF_ACCOUNT_ID;
  const kv = c.env.USER_CONFIG;
  const cacheKey = `security-insights:${email}`;
  const refresh = c.req.query('refresh') === 'true';

  if (!accountId) {
    return c.json({ error: 'CF_ACCOUNT_ID not configured' }, 500);
  }

  // Return cached data if available and not refreshing
  if (!refresh) {
    const cached = await kv.get(cacheKey, 'json');
    if (cached) {
      return c.json(cached);
    }
  }

  const data = await cfApi(c.env, `/accounts/${accountId}/security-center/insights`, {
    params: { per_page: '100', dismissed: 'false' },
  });

  if (!data.success) {
    // On error, try returning stale cache
    const stale = await kv.get(cacheKey, 'json');
    if (stale) return c.json(stale);
    return c.json({ error: 'Failed to fetch security insights', details: data.errors }, 500);
  }

  // Debug mode: return raw response
  if (c.req.query('debug') === 'true') {
    return c.json(data);
  }

  const issues = data.result?.issues || [];
  console.log(`[security-insights] fetched ${issues.length} issues`);

  // Build zone name lookup from cached zones
  const cachedZones = await kv.get(`zones:${email}`, 'json');
  const zoneMap = new Map((cachedZones?.zones || []).map(z => [z.id, z.name]));

  // Group by zone
  const byZone = {};
  let total = 0;

  for (const issue of issues) {
    const zoneTag = issue.payload?.zone_tag;

    const mapped = {
      id: issue.id,
      issueClass: issue.issue_class,
      issueType: issue.issue_type,
      severity: issue.severity,
      subject: issue.subject,
      resolveText: issue.resolve_text,
      detectionMethod: issue.payload?.detection_method,
      since: issue.since,
    };

    if (zoneTag) {
      if (!byZone[zoneTag]) byZone[zoneTag] = [];
      byZone[zoneTag].push(mapped);
    } else {
      // Account-level issue — match subject to zone name
      let matched = false;
      for (const [zId, zName] of zoneMap) {
        if (issue.subject && issue.subject.includes(zName)) {
          if (!byZone[zId]) byZone[zId] = [];
          byZone[zId].push(mapped);
          matched = true;
          break;
        }
      }
      if (!matched) {
        if (!byZone['_account']) byZone['_account'] = [];
        byZone['_account'].push(mapped);
      }
    }
    total++;
  }

  // Deduplicate issues within each zone by issueType
  for (const key of Object.keys(byZone)) {
    const seen = new Set();
    byZone[key] = byZone[key].filter(issue => {
      if (seen.has(issue.issueType)) return false;
      seen.add(issue.issueType);
      return true;
    });
  }

  total = Object.values(byZone).reduce((sum, arr) => sum + arr.length, 0);

  const record = { insights: byZone, total, _cachedAt: new Date().toISOString() };
  await kv.put(cacheKey, JSON.stringify(record), { expirationTtl: 600 });

  return c.json(record);
});

/**
 * GET /api/zones/:zoneId/rule-counts
 * Returns counts of Cache Rules, WAF Custom Rules, and Page Rules
 */
zonesRoutes.get('/:zoneId/rule-counts', async (c) => {
  const zoneId = c.req.param('zoneId');

  return withCache(c, `tab:${zoneId}:rule-counts`, async () => {
    const [cacheRuleset, securityRuleset, pageRules] = await Promise.all([
      cfApi(c.env, `/zones/${zoneId}/rulesets/phases/http_request_cache_settings/entrypoint`),
      cfApi(c.env, `/zones/${zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`),
      cfApi(c.env, `/zones/${zoneId}/pagerules`, { params: { status: 'active' } }),
    ]);

    return {
      cacheRules: cacheRuleset.result?.rules?.length ?? 0,
      securityRules: securityRuleset.result?.rules?.length ?? 0,
      pageRules: pageRules.result?.length ?? 0,
    };
  });
});

/**
 * GET /api/zones/:zoneId
 * Detailed zone info
 */
zonesRoutes.get('/:zoneId', async (c) => {
  const zoneId = c.req.param('zoneId');
  const data = await cfApi(c.env, `/zones/${zoneId}`);

  if (!data.success) {
    return c.json({ error: 'Failed to fetch zone' }, 500);
  }

  const z = data.result;
  const zoneConfig = c.get('zoneConfig');

  return c.json({
    id: z.id,
    name: z.name,
    status: z.status,
    paused: z.paused,
    plan: z.plan?.name,
    nameServers: z.name_servers,
    originalNameServers: z.original_name_servers,
    createdOn: z.created_on,
    modifiedOn: z.modified_on,
    permissions: zoneConfig.permissions,
  });
});

/**
 * POST /api/zones/:zoneId/purge
 * Purge cache for the zone
 */
zonesRoutes.post('/:zoneId/purge', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!zoneConfig.permissions.includes('cache:purge')) {
    return c.json({ error: 'No permission to purge cache' }, 403);
  }

  const body = await c.req.json();
  const data = await cfApi(c.env, `/zones/${zoneId}/purge_cache`, {
    method: 'POST',
    body,
  });

  return c.json(data);
});

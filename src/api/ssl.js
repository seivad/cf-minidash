import { Hono } from 'hono';
import { cfApi, hasPermission, withCache } from './cloudflare.js';

export const sslRoutes = new Hono();

/**
 * GET /api/zones/:zoneId/ssl
 * Returns current SSL/TLS settings for the zone
 */
sslRoutes.get('/', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'ssl:read') && !hasPermission(zoneConfig, 'ssl:write')) {
    return c.json({ error: 'No SSL access' }, 403);
  }

  const cacheKey = `tab:${zoneId}:ssl`;

  return withCache(c, cacheKey, async () => {
    const data = await cfApi(c.env, `/zones/${zoneId}/settings`);
    if (!data.success) throw new Error('Failed to fetch zone settings');

    // Build a map of setting id → value for quick lookup
    const settings = new Map(data.result.map(s => [s.id, s.value]));

    return {
      minTlsVersion: settings.get('min_tls_version') || '1.0',
      tls13: settings.get('tls_1_3') || 'off',
      alwaysUseHttps: settings.get('always_use_https') === 'on',
      automaticHttpsRewrites: settings.get('automatic_https_rewrites') === 'on',
      sslMode: settings.get('ssl') || 'off',
    };
  });
});

/** Helper to patch a zone setting and invalidate SSL cache */
async function patchSetting(c, settingName, body) {
  const zoneConfig = c.get('zoneConfig');
  if (!hasPermission(zoneConfig, 'ssl:write')) {
    return c.json({ error: 'No permission to edit SSL settings' }, 403);
  }

  const zoneId = c.req.param('zoneId');
  const data = await cfApi(c.env, `/zones/${zoneId}/settings/${settingName}`, {
    method: 'PATCH',
    body,
  });
  if (!data.success) {
    return c.json({ error: `Failed to update ${settingName}`, details: data.errors }, 500);
  }
  await c.env.USER_CONFIG.delete(`tab:${zoneId}:ssl`);
  return data;
}

/**
 * PATCH /api/zones/:zoneId/ssl/min-tls
 */
sslRoutes.patch('/min-tls', async (c) => {
  const { value } = await c.req.json();
  const allowed = ['1.0', '1.1', '1.2', '1.3'];
  if (!allowed.includes(value)) {
    return c.json({ error: `Invalid TLS version. Must be one of: ${allowed.join(', ')}` }, 400);
  }
  const data = await patchSetting(c, 'min_tls_version', { value });
  if (data instanceof Response) return data;
  return c.json({ value: data.result?.value });
});

/**
 * PATCH /api/zones/:zoneId/ssl/always-https
 */
sslRoutes.patch('/always-https', async (c) => {
  const { value } = await c.req.json();
  const data = await patchSetting(c, 'always_use_https', { value: value ? 'on' : 'off' });
  if (data instanceof Response) return data;
  return c.json({ value: data.result?.value === 'on' });
});

/**
 * PATCH /api/zones/:zoneId/ssl/auto-rewrites
 */
sslRoutes.patch('/auto-rewrites', async (c) => {
  const { value } = await c.req.json();
  const data = await patchSetting(c, 'automatic_https_rewrites', { value: value ? 'on' : 'off' });
  if (data instanceof Response) return data;
  return c.json({ value: data.result?.value === 'on' });
});

/**
 * PATCH /api/zones/:zoneId/ssl/mode
 */
sslRoutes.patch('/mode', async (c) => {
  const { value } = await c.req.json();
  const allowed = ['off', 'flexible', 'full', 'strict'];
  if (!allowed.includes(value)) {
    return c.json({ error: `Invalid SSL mode. Must be one of: ${allowed.join(', ')}` }, 400);
  }
  const data = await patchSetting(c, 'ssl', { value });
  if (data instanceof Response) return data;
  return c.json({ value: data.result?.value });
});

/**
 * PATCH /api/zones/:zoneId/ssl/tls13
 */
sslRoutes.patch('/tls13', async (c) => {
  const { value } = await c.req.json();
  const data = await patchSetting(c, 'tls_1_3', { value: value ? 'on' : 'off' });
  if (data instanceof Response) return data;
  return c.json({ value: data.result?.value === 'on' });
});

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, deleteCookie } from 'hono/cookie';
import { dnsRoutes } from './api/dns.js';
import { analyticsRoutes } from './api/analytics.js';
import { botsRoutes } from './api/bots.js';
import { zonesRoutes } from './api/zones.js';
import { sslRoutes } from './api/ssl.js';
import { authRoutes } from './api/auth.js';
import { OPERATION_ALLOWLIST } from './api/cloudflare.js';

const app = new Hono();

// CORS for API routes
app.use('/api/*', cors());

// ──────────────────────────────────────────────
// Auth middleware — validates session cookie
// ──────────────────────────────────────────────
app.use('/api/*', async (c, next) => {
  // Skip auth for login/logout
  if (c.req.path === '/api/auth/login' || c.req.path === '/api/auth/logout') {
    return next();
  }

  const sessionId = getCookie(c, 'session');
  if (!sessionId) {
    return c.json({ error: 'Unauthorized' }, 401);
  }

  // Look up session in KV
  const session = await c.env.USER_CONFIG.get(`session:${sessionId}`, 'json');
  if (!session || session.expiresAt < Date.now()) {
    deleteCookie(c, 'session');
    return c.json({ error: 'Session expired' }, 401);
  }

  // Attach session to context
  c.set('session', session);

  // Operation allowlist enforcement for sub-users
  if (!session.isSuperAdmin) {
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;

    const matched = OPERATION_ALLOWLIST.find(
      op => op.method === method && op.pattern.test(path)
    );

    if (!matched) {
      return c.json({ error: 'Operation not permitted' }, 403);
    }

    if (matched.permission && !session.permissions.includes(matched.permission)) {
      return c.json({ error: `Missing permission: ${matched.permission}` }, 403);
    }
  }

  return next();
});

// ──────────────────────────────────────────────
// Zone access middleware — validates zone access
// ──────────────────────────────────────────────
app.use('/api/zones/:zoneId/*', async (c, next) => {
  const zoneId = c.req.param('zoneId');
  // Skip zone validation for non-zone-id paths
  if (zoneId === 'security-insights' || zoneId === 'refresh') return next();

  const session = c.get('session');

  // Check if zone is in the user's allowed list
  const allowed = session.allowedZones.find(z => z.id === zoneId);
  if (!allowed) {
    return c.json({ error: 'No access to this zone' }, 403);
  }

  // Build zoneConfig for downstream route handlers
  const zoneConfig = {
    id: zoneId,
    name: allowed.name,
    permissions: session.permissions,
  };

  c.set('zoneConfig', zoneConfig);
  return next();
});

// ──────────────────────────────────────────────
// Mount API routes
// ──────────────────────────────────────────────
app.route('/api/auth', authRoutes);
app.route('/api/zones', zonesRoutes);
app.route('/api/zones/:zoneId/dns', dnsRoutes);
app.route('/api/zones/:zoneId/analytics', analyticsRoutes);
app.route('/api/zones/:zoneId/bots', botsRoutes);
app.route('/api/zones/:zoneId/ssl', sslRoutes);

// User info endpoint
app.get('/api/me', async (c) => {
  const session = c.get('session');
  return c.json({
    email: session.email,
    isSuperAdmin: session.isSuperAdmin,
    permissions: session.permissions,
    zones: session.allowedZones,
  });
});

// ──────────────────────────────────────────────
// Everything else → static assets (public/)
// ──────────────────────────────────────────────

export default {
  fetch: app.fetch,
  async scheduled(controller, env, ctx) {
    const { runSecurityReport } = await import('./scheduled/securityReport.js');
    ctx.waitUntil(runSecurityReport(env));
  },
};

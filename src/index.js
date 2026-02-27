import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { dnsRoutes } from './api/dns.js';
import { analyticsRoutes } from './api/analytics.js';
import { botsRoutes } from './api/bots.js';
import { zonesRoutes } from './api/zones.js';
import { sslRoutes } from './api/ssl.js';
import { authRoutes } from './api/auth.js';

const app = new Hono();

// CORS for API routes
app.use('/api/*', cors());

// ──────────────────────────────────────────────
// Auth middleware — validates session cookie
// If using Cloudflare Access, swap this for JWT validation
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

  // Load user config
  const userConfig = await c.env.USER_CONFIG.get(`user:${session.email}`, 'json');
  if (!userConfig) {
    return c.json({ error: 'No access configured for this user' }, 403);
  }

  // Attach to context
  c.set('userEmail', session.email);
  c.set('userConfig', userConfig);

  return next();
});

// ──────────────────────────────────────────────
// Zone access middleware — validates zone access
// ──────────────────────────────────────────────
app.use('/api/zones/:zoneId/*', async (c, next) => {
  const zoneId = c.req.param('zoneId');
  // Skip zone validation for non-zone-id paths
  if (zoneId === 'security-insights' || zoneId === 'refresh') return next();
  const userConfig = c.get('userConfig');

  // Check if zone has explicit permissions in user config, otherwise use defaults
  const zoneConfig = userConfig.zones?.find(z => z.id === zoneId) || {
    id: zoneId,
    permissions: ['dns:read', 'analytics:read', 'bots:read'],
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
  const userConfig = c.get('userConfig');
  const email = c.get('userEmail');
  return c.json({
    email,
    zones: userConfig.zones.map(z => ({
      id: z.id,
      name: z.name,
      permissions: z.permissions
    }))
  });
});

// ──────────────────────────────────────────────
// Everything else → static assets (public/)
// ──────────────────────────────────────────────

export default app;

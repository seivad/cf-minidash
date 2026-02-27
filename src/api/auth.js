import { Hono } from 'hono';
import { setCookie, deleteCookie } from 'hono/cookie';

export const authRoutes = new Hono();

/**
 * POST /api/auth/login
 * Simple auth: validates email against known users in KV.
 *
 * For production, swap this for:
 *   - Cloudflare Access (JWT in CF-Access-JWT-Assertion header)
 *   - Magic link / OTP via email
 *   - OAuth (Google, GitHub, etc.)
 *
 * For now, we accept { email, password } and validate against KV.
 */
authRoutes.post('/login', async (c) => {
  const { email, password } = await c.req.json();

  if (!email) {
    return c.json({ error: 'Email is required' }, 400);
  }

  // Look up user
  const userConfig = await c.env.USER_CONFIG.get(`user:${email.toLowerCase()}`, 'json');
  if (!userConfig) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  // Validate password (simple hash comparison)
  // In production, use bcrypt or Cloudflare Access instead
  const encoder = new TextEncoder();
  const data = encoder.encode(password + c.env.AUTH_SECRET);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

  if (hashHex !== userConfig.passwordHash) {
    return c.json({ error: 'Invalid credentials' }, 401);
  }

  // Create session
  const sessionId = crypto.randomUUID();
  const session = {
    email: email.toLowerCase(),
    createdAt: Date.now(),
    expiresAt: Date.now() + (24 * 60 * 60 * 1000), // 24 hours
  };

  await c.env.USER_CONFIG.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    { expirationTtl: 86400 } // Auto-expire in KV after 24h
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
    email: email.toLowerCase(),
    zones: userConfig.zones.map(z => ({ id: z.id, name: z.name, permissions: z.permissions })),
  });
});

/**
 * POST /api/auth/logout
 */
authRoutes.post('/logout', async (c) => {
  const { getCookie } = await import('hono/cookie');
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
  // This route goes through the auth middleware in index.js
  // If we get here, the session is valid
  const email = c.get('userEmail');
  const userConfig = c.get('userConfig');

  if (!email || !userConfig) {
    return c.json({ authenticated: false }, 401);
  }

  return c.json({
    authenticated: true,
    email,
    zones: userConfig.zones.map(z => ({ id: z.id, name: z.name, permissions: z.permissions })),
  });
});

import { Hono } from 'hono';
import { cfApi, cfGraphQL, hasPermission, withCache } from './cloudflare.js';

export const botsRoutes = new Hono();

/**
 * GET /api/zones/:zoneId/bots/config
 * Get bot management configuration
 */
botsRoutes.get('/config', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'bots:read') && !hasPermission(zoneConfig, 'bots:write')) {
    return c.json({ error: 'No bot management access' }, 403);
  }

  return withCache(c, `tab:${zoneId}:bots`, async () => {
    const data = await cfApi(c.env, `/zones/${zoneId}/bot_management`);

    if (!data.success) {
      throw new Error('Failed to fetch bot config');
    }

    return {
      config: data.result,
      canEdit: hasPermission(zoneConfig, 'bots:write'),
    };
  });
});

/**
 * PUT /api/zones/:zoneId/bots/config
 * Update bot management configuration
 */
botsRoutes.put('/config', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'bots:write')) {
    return c.json({ error: 'No permission to edit bot config' }, 403);
  }

  const body = await c.req.json();

  // Whitelist allowed fields
  const updates = {};
  if (body.fight_mode !== undefined) updates.fight_mode = body.fight_mode;
  if (body.enable_js !== undefined) updates.enable_js = body.enable_js;
  if (body.optimize_wordpress !== undefined) updates.optimize_wordpress = body.optimize_wordpress;
  if (body.sbfm_definitely_automated !== undefined) updates.sbfm_definitely_automated = body.sbfm_definitely_automated;
  if (body.sbfm_likely_automated !== undefined) updates.sbfm_likely_automated = body.sbfm_likely_automated;
  if (body.sbfm_verified_bots !== undefined) updates.sbfm_verified_bots = body.sbfm_verified_bots;
  if (body.sbfm_static_resource_protection !== undefined) updates.sbfm_static_resource_protection = body.sbfm_static_resource_protection;
  if (body.suppress_session_score !== undefined) updates.suppress_session_score = body.suppress_session_score;
  if (body.auto_update_model !== undefined) updates.auto_update_model = body.auto_update_model;

  const data = await cfApi(c.env, `/zones/${zoneId}/bot_management`, {
    method: 'PUT',
    body: updates,
  });

  if (!data.success) {
    return c.json({ error: 'Failed to update bot config', details: data.errors }, 400);
  }

  return c.json({ config: data.result });
});

/**
 * GET /api/zones/:zoneId/bots/analytics
 * Bot analytics via GraphQL
 */
botsRoutes.get('/analytics', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'bots:read') && !hasPermission(zoneConfig, 'analytics:read')) {
    return c.json({ error: 'No bot analytics access' }, 403);
  }

  const since = c.req.query('since') || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const until = c.req.query('until') || new Date().toISOString();

  const query = `
    query BotAnalytics($zoneTag: string!, $since: Time!, $until: Time!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          httpRequestsAdaptiveGroups(
            filter: { datetime_geq: $since, datetime_leq: $until }
            limit: 1000
            orderBy: [datetimeHour_ASC]
          ) {
            count
            dimensions {
              datetimeHour
              botScore
              botScoreSrcName
            }
          }
        }
      }
    }
  `;

  const data = await cfGraphQL(c.env, query, {
    zoneTag: zoneId,
    since,
    until,
  });

  if (data.errors && data.errors.length > 0) {
    return c.json({ error: 'Bot analytics query failed', details: data.errors }, 500);
  }

  const groups = data.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups || [];

  // Summarise by bot score ranges
  const summary = {
    verified: 0,
    likely_human: 0,
    likely_bot: 0,
    definitely_bot: 0,
  };

  groups.forEach(g => {
    const score = g.dimensions.botScore;
    if (score === undefined || score === null) return;
    if (score >= 30) summary.likely_human += g.count;
    else if (score >= 10) summary.likely_bot += g.count;
    else if (score >= 1) summary.definitely_bot += g.count;
    else summary.verified += g.count;
  });

  return c.json({ summary, raw: groups });
});

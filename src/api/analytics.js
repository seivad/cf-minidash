import { Hono } from 'hono';
import { userApiClient, hasPermission, withCache } from './cloudflare.js';

export const analyticsRoutes = new Hono();

/**
 * GET /api/zones/:zoneId/analytics/traffic
 * HTTP traffic analytics (requests, bandwidth, threats, etc.)
 */
analyticsRoutes.get('/traffic', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'analytics:read')) {
    return c.json({ error: 'No analytics access' }, 403);
  }

  // Default: last 24 hours
  const since = c.req.query('since') || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const until = c.req.query('until') || new Date().toISOString();

  const query = `
    query TrafficAnalytics($zoneTag: string!, $since: Time!, $until: Time!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          httpRequestsAdaptiveGroups(
            filter: { datetime_geq: $since, datetime_leq: $until }
            limit: 1000
            orderBy: [datetimeHour_ASC]
          ) {
            count
            sum {
              edgeResponseBytes
              visits
              pageViews
            }
            dimensions {
              datetimeHour
            }
          }
          httpRequests1hGroups(
            filter: { datetime_geq: $since, datetime_leq: $until }
            limit: 168
            orderBy: [datetime_ASC]
          ) {
            sum {
              requests
              cachedRequests
              threats
              bytes
              cachedBytes
              countryMap {
                clientCountryName
                requests
                threats
              }
            }
            dimensions {
              datetime
            }
          }
        }
      }
    }
  `;

  const { graphql } = userApiClient(c);
  const data = await graphql(query, {
    zoneTag: zoneId,
    since,
    until,
  });

  if (data.errors && data.errors.length > 0) {
    return c.json({ error: 'Analytics query failed', details: data.errors }, 500);
  }

  const zones = data.data?.viewer?.zones?.[0];
  return c.json({
    adaptive: zones?.httpRequestsAdaptiveGroups || [],
    hourly: zones?.httpRequests1hGroups || [],
  });
});

/**
 * GET /api/zones/:zoneId/analytics/security
 * Firewall / security events
 */
analyticsRoutes.get('/security', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'analytics:read')) {
    return c.json({ error: 'No analytics access' }, 403);
  }

  const since = c.req.query('since') || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const until = c.req.query('until') || new Date().toISOString();

  const query = `
    query SecurityAnalytics($zoneTag: string!, $since: Time!, $until: Time!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          firewallEventsAdaptiveGroups(
            filter: { datetime_geq: $since, datetime_leq: $until }
            limit: 1000
            orderBy: [datetimeHour_ASC]
          ) {
            count
            dimensions {
              datetimeHour
              action
              source
              ruleId
              clientCountryName
              clientIP
              userAgent
            }
          }
        }
      }
    }
  `;

  const { graphql } = userApiClient(c);
  const data = await graphql(query, {
    zoneTag: zoneId,
    since,
    until,
  });

  if (data.errors && data.errors.length > 0) {
    return c.json({ error: 'Security analytics query failed', details: data.errors }, 500);
  }

  const events = data.data?.viewer?.zones?.[0]?.firewallEventsAdaptiveGroups || [];
  return c.json({ events });
});

/**
 * GET /api/zones/:zoneId/analytics/dns
 * DNS query analytics
 */
analyticsRoutes.get('/dns', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'analytics:read') && !hasPermission(zoneConfig, 'dns:read')) {
    return c.json({ error: 'No analytics access' }, 403);
  }

  const since = c.req.query('since') || new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const until = c.req.query('until') || new Date().toISOString();

  const query = `
    query DNSAnalytics($zoneTag: string!, $since: Time!, $until: Time!) {
      viewer {
        zones(filter: { zoneTag: $zoneTag }) {
          dnsAnalyticsAdaptiveGroups(
            filter: { datetime_geq: $since, datetime_leq: $until }
            limit: 1000
            orderBy: [datetime_ASC]
          ) {
            count
            dimensions {
              datetime
              queryName
              queryType
              responseCode
            }
          }
        }
      }
    }
  `;

  const { graphql } = userApiClient(c);
  const data = await graphql(query, {
    zoneTag: zoneId,
    since,
    until,
  });

  if (data.errors && data.errors.length > 0) {
    return c.json({ error: 'DNS analytics query failed', details: data.errors }, 500);
  }

  const records = data.data?.viewer?.zones?.[0]?.dnsAnalyticsAdaptiveGroups || [];
  return c.json({ records });
});

/**
 * GET /api/zones/:zoneId/analytics/summary
 * Quick summary stats for dashboard cards
 */
analyticsRoutes.get('/summary', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'analytics:read')) {
    return c.json({ error: 'No analytics access' }, 403);
  }

  // Use GraphQL API (REST analytics/dashboard was sunset)
  // Strip milliseconds — httpRequests1hGroups requires "2026-02-27T00:00:00Z" format
  const stripMs = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

  let sinceParam = c.req.query('since');
  // Handle old REST API "-minutes" format (e.g. "-1440")
  if (sinceParam && /^-?\d+$/.test(sinceParam)) {
    sinceParam = stripMs(new Date(Date.now() + parseInt(sinceParam) * 60 * 1000));
  } else if (sinceParam) {
    sinceParam = stripMs(new Date(sinceParam));
  }

  let untilParam = c.req.query('until');
  if (untilParam) {
    untilParam = stripMs(new Date(untilParam));
  }

  const since = sinceParam || stripMs(new Date(Date.now() - 24 * 60 * 60 * 1000));
  const until = untilParam || stripMs(new Date());

  // Pick dataset based on range: <=3 days → hourly, >3 days → daily
  const rangeSeconds = (new Date(until) - new Date(since)) / 1000;
  const useDaily = rangeSeconds > 259200; // 3 days
  const dataset = useDaily ? 'httpRequests1dGroups' : 'httpRequests1hGroups';
  const limit = useDaily ? 90 : 168;
  // Daily uses date_geq/date_leq + date dimension; hourly uses datetime_geq/datetime_leq + datetime
  const filterField = useDaily ? 'date' : 'datetime';
  const sinceValue = useDaily ? since.split('T')[0] : since;
  const untilValue = useDaily ? until.split('T')[0] : until;

  // Cache key includes range bucket (24h, 7d, 30d)
  const rangeBucket = useDaily ? (rangeSeconds > 604800 ? '30d' : '7d') : '24h';
  const cacheKey = `tab:${zoneId}:analytics:${rangeBucket}`;

  const { graphql } = userApiClient(c);

  const fetchAnalytics = async () => {
    const query = `
      query AnalyticsSummary($zoneTag: string!, $since: Date!, $until: Date!) {
        viewer {
          zones(filter: { zoneTag: $zoneTag }) {
            ${dataset}(
              filter: { ${filterField}_geq: $since, ${filterField}_leq: $until }
              limit: ${limit}
              orderBy: [${filterField}_ASC]
            ) {
              sum {
                requests
                cachedRequests
                threats
                bytes
                cachedBytes
                pageViews
              }
              uniq {
                uniques
              }
              dimensions {
                ${filterField}
              }
            }
          }
        }
      }
    `;

    const data = await graphql(query, {
      zoneTag: zoneId,
      since: sinceValue,
      until: untilValue,
    });

    if (data.errors && data.errors.length > 0) {
      console.error('[analytics/summary] GraphQL error:', JSON.stringify(data.errors));
      throw new Error('Analytics query failed');
    }

    const groups = data.data?.viewer?.zones?.[0]?.[dataset] || [];

    const totals = groups.reduce((acc, g) => {
      acc.requests += g.sum.requests || 0;
      acc.cachedRequests += g.sum.cachedRequests || 0;
      acc.bandwidth += g.sum.bytes || 0;
      acc.cachedBandwidth += g.sum.cachedBytes || 0;
      acc.threats += g.sum.threats || 0;
      acc.pageViews += g.sum.pageViews || 0;
      acc.uniqueVisitors += g.uniq?.uniques || 0;
      return acc;
    }, { requests: 0, cachedRequests: 0, bandwidth: 0, cachedBandwidth: 0, threats: 0, pageViews: 0, uniqueVisitors: 0 });

    return {
      requests: totals.requests,
      cachedRequests: totals.cachedRequests,
      uncachedRequests: totals.requests - totals.cachedRequests,
      bandwidth: totals.bandwidth,
      cachedBandwidth: totals.cachedBandwidth,
      threats: totals.threats,
      uniqueVisitors: totals.uniqueVisitors,
      pageViews: totals.pageViews,
      timeseries: groups.map(g => ({
        since: g.dimensions[filterField],
        requests: { all: g.sum.requests, cached: g.sum.cachedRequests },
        bandwidth: { all: g.sum.bytes, cached: g.sum.cachedBytes },
        threats: { all: g.sum.threats },
        pageviews: { all: g.sum.pageViews },
        uniques: { all: g.uniq?.uniques || 0 },
      })),
    };
  };

  return withCache(c, cacheKey, fetchAnalytics);
});

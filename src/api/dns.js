import { Hono } from 'hono';
import { userApiClient, hasPermission, withCache } from './cloudflare.js';

export const dnsRoutes = new Hono();

/**
 * GET /api/zones/:zoneId/dns
 * List DNS records with optional filtering
 */
dnsRoutes.get('/', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'dns:read') && !hasPermission(zoneConfig, 'dns:write')) {
    return c.json({ error: 'No DNS access' }, 403);
  }

  const { api } = userApiClient(c);
  const type = c.req.query('type');
  const search = c.req.query('search');
  const page = c.req.query('page') || '1';

  // Only cache the default unfiltered view
  const isFiltered = type || search || page !== '1';
  const cacheKey = `tab:${zoneId}:dns`;

  const mapRecord = (r) => ({
    id: r.id,
    type: r.type,
    name: r.name,
    content: r.content,
    proxied: r.proxied,
    ttl: r.ttl,
    priority: r.priority,
    comment: r.comment,
    tags: r.tags,
    createdOn: r.created_on,
    modifiedOn: r.modified_on,
  });

  if (isFiltered) {
    // Don't cache filtered/paginated results — single page fetch
    try {
      const params = {};
      if (type) params.type = type;
      const name = c.req.query('name');
      if (name) params.name = name;
      if (search) params.name = search;
      params.page = page;
      params.per_page = c.req.query('per_page') || '50';
      params.order = 'type';

      const data = await api(`/zones/${zoneId}/dns_records`, { params });
      if (!data.success) throw new Error('Failed to fetch DNS records');

      return c.json({
        records: data.result.map(mapRecord),
        resultInfo: data.result_info,
        canEdit: hasPermission(zoneConfig, 'dns:write'),
      });
    } catch {
      return c.json({ error: 'Failed to fetch DNS records' }, 500);
    }
  }

  // Unfiltered: fetch ALL pages and cache the full set
  const fetchAllDns = async () => {
    const allRecords = [];
    let pg = 1;
    while (true) {
      const data = await api(`/zones/${zoneId}/dns_records`, {
        params: { page: String(pg), per_page: '100', order: 'type' },
      });
      if (!data.success) throw new Error('Failed to fetch DNS records');
      allRecords.push(...data.result.map(mapRecord));
      const totalPages = data.result_info?.total_pages || 1;
      if (pg >= totalPages) break;
      pg++;
    }
    return {
      records: allRecords,
      resultInfo: { total_count: allRecords.length, total_pages: 1, page: 1, per_page: allRecords.length },
      canEdit: hasPermission(zoneConfig, 'dns:write'),
    };
  };

  return withCache(c, cacheKey, fetchAllDns);
});

/**
 * GET /api/zones/:zoneId/dns/:recordId
 * Get a single DNS record
 */
dnsRoutes.get('/:recordId', async (c) => {
  const zoneId = c.req.param('zoneId');
  const recordId = c.req.param('recordId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'dns:read') && !hasPermission(zoneConfig, 'dns:write')) {
    return c.json({ error: 'No DNS access' }, 403);
  }

  const { api } = userApiClient(c);
  const data = await api(`/zones/${zoneId}/dns_records/${recordId}`);

  if (!data.success) {
    return c.json({ error: 'Record not found', details: data.errors }, 404);
  }

  return c.json({ record: data.result });
});

/**
 * POST /api/zones/:zoneId/dns
 * Create a new DNS record
 */
dnsRoutes.post('/', async (c) => {
  const zoneId = c.req.param('zoneId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'dns:write')) {
    return c.json({ error: 'No permission to create DNS records' }, 403);
  }

  const body = await c.req.json();

  // Validate required fields
  if (!body.type || !body.name || !body.content) {
    return c.json({ error: 'type, name, and content are required' }, 400);
  }

  // Whitelist allowed fields
  const allowed = {
    type: body.type,
    name: body.name,
    content: body.content,
    ttl: body.ttl || 1, // 1 = auto
    proxied: body.proxied ?? false,
    comment: body.comment || '',
    tags: body.tags || [],
  };

  if (body.priority !== undefined) allowed.priority = body.priority;

  const { api } = userApiClient(c);
  const data = await api(`/zones/${zoneId}/dns_records`, {
    method: 'POST',
    body: allowed,
  });

  if (!data.success) {
    return c.json({ error: 'Failed to create record', details: data.errors }, 400);
  }

  return c.json({ record: data.result }, 201);
});

/**
 * PATCH /api/zones/:zoneId/dns/:recordId
 * Update a DNS record
 */
dnsRoutes.patch('/:recordId', async (c) => {
  const zoneId = c.req.param('zoneId');
  const recordId = c.req.param('recordId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'dns:write')) {
    return c.json({ error: 'No permission to edit DNS records' }, 403);
  }

  const body = await c.req.json();

  // Only pass through safe fields
  const updates = {};
  if (body.type !== undefined) updates.type = body.type;
  if (body.name !== undefined) updates.name = body.name;
  if (body.content !== undefined) updates.content = body.content;
  if (body.ttl !== undefined) updates.ttl = body.ttl;
  if (body.proxied !== undefined) updates.proxied = body.proxied;
  if (body.comment !== undefined) updates.comment = body.comment;
  if (body.tags !== undefined) updates.tags = body.tags;
  if (body.priority !== undefined) updates.priority = body.priority;

  const { api } = userApiClient(c);
  const data = await api(`/zones/${zoneId}/dns_records/${recordId}`, {
    method: 'PATCH',
    body: updates,
  });

  if (!data.success) {
    return c.json({ error: 'Failed to update record', details: data.errors }, 400);
  }

  return c.json({ record: data.result });
});

/**
 * DELETE /api/zones/:zoneId/dns/:recordId
 * Delete a DNS record
 */
dnsRoutes.delete('/:recordId', async (c) => {
  const zoneId = c.req.param('zoneId');
  const recordId = c.req.param('recordId');
  const zoneConfig = c.get('zoneConfig');

  if (!hasPermission(zoneConfig, 'dns:write')) {
    return c.json({ error: 'No permission to delete DNS records' }, 403);
  }

  const { api } = userApiClient(c);
  const data = await api(`/zones/${zoneId}/dns_records/${recordId}`, {
    method: 'DELETE',
  });

  if (!data.success) {
    return c.json({ error: 'Failed to delete record', details: data.errors }, 400);
  }

  return c.json({ ok: true });
});

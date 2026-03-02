/**
 * Zone Dashboard — Client Application
 */

const App = {
  state: {
    user: null,
    zones: [],
    activeZone: null,
    activeTab: 'overview',
    dnsRecords: [],
    canEditDns: false,
    securityInsights: {}, // keyed by zoneId
  },

  // ─── API Helper ───
  async api(path, options = {}) {
    const { method = 'GET', body } = options;
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
    };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`/api${path}`, opts);
    const data = await res.json();

    if (res.status === 401) {
      // Don't redirect to login during the login request itself
      if (path !== '/auth/login') this.showLogin();
      throw new Error(data.error || 'Unauthorized');
    }

    if (!res.ok) {
      throw new Error(data.error || `Request failed: ${res.status}`);
    }

    return data;
  },

  // ═══════════════════════════════
  // Initialization
  // ═══════════════════════════════
  async init() {
    this.bindEvents();

    // Check existing session
    try {
      const data = await this.api('/auth/check');
      if (data.authenticated) {
        this.state.user = data;
        this.showDashboard();
        return;
      }
    } catch (e) {
      // No valid session
    }

    this.showLogin();
  },

  bindEvents() {
    // Login form
    document.getElementById('login-form').addEventListener('submit', (e) => {
      e.preventDefault();
      this.handleLogin();
    });

    // Logout
    document.getElementById('logout-btn').addEventListener('click', () => this.handleLogout());

    // Tabs
    document.getElementById('tab-nav').addEventListener('click', (e) => {
      if (e.target.classList.contains('tab')) {
        this.switchTab(e.target.dataset.tab);
      }
    });

    // DNS controls
    document.getElementById('dns-add-btn').addEventListener('click', () => this.openDnsModal());
    document.getElementById('dns-modal-close').addEventListener('click', () => this.closeDnsModal());
    document.getElementById('dns-cancel').addEventListener('click', () => this.closeDnsModal());
    document.getElementById('dns-form').addEventListener('submit', (e) => {
      e.preventDefault();
      this.saveDnsRecord();
    });
    document.querySelector('.modal-backdrop')?.addEventListener('click', () => this.closeDnsModal());

    // DNS search/filter
    document.getElementById('dns-search').addEventListener('input', debounce(() => this.loadDns(), 300));
    document.getElementById('dns-type-filter').addEventListener('change', () => this.loadDns());

    // Analytics range
    document.getElementById('analytics-range').addEventListener('change', () => this.loadAnalytics());

    // Browser back/forward for tab changes
    window.addEventListener('hashchange', () => {
      const tab = (window.location.hash || '').replace('#', '');
      if (tab && this.state.activeZone && tab !== this.state.activeTab) {
        this.switchTab(tab, { updateUrl: false });
      }
    });

    // Browser back/forward for zone changes
    window.addEventListener('popstate', () => {
      const params = new URLSearchParams(window.location.search);
      const zoneId = params.get('zone');
      const tab = (window.location.hash || '').replace('#', '') || 'overview';
      if (zoneId && zoneId !== this.state.activeZone?.id) {
        this.selectZone(zoneId, { tab });
      } else if (zoneId && tab !== this.state.activeTab) {
        this.switchTab(tab, { updateUrl: false });
      }
    });
  },

  // ═══════════════════════════════
  // Auth
  // ═══════════════════════════════
  showLogin() {
    document.getElementById('login-screen').classList.remove('hidden');
    document.getElementById('dashboard-screen').classList.add('hidden');
  },

  async handleLogin() {
    const btn = document.getElementById('login-btn');
    const errorEl = document.getElementById('login-error');
    errorEl.classList.add('hidden');
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Verifying token...';

    try {
      const apiToken = document.getElementById('api-token').value;

      const data = await this.api('/auth/login', {
        method: 'POST',
        body: { apiToken },
      });

      this.state.user = data;
      this.showDashboard();
    } catch (err) {
      errorEl.textContent = err.message || 'Login failed';
      errorEl.classList.remove('hidden');
    } finally {
      btn.disabled = false;
      btn.innerHTML = '<span>Sign in</span>';
    }
  },

  async handleLogout() {
    try {
      await this.api('/auth/logout', { method: 'POST' });
    } catch (e) { /* ignore */ }
    this.state.user = null;
    this.state.activeZone = null;
    history.replaceState(null, '', window.location.pathname);
    this.showLogin();
  },

  // ═══════════════════════════════
  // Dashboard
  // ═══════════════════════════════
  async showDashboard() {
    document.getElementById('login-screen').classList.add('hidden');
    document.getElementById('dashboard-screen').classList.remove('hidden');
    document.getElementById('user-email').textContent = this.state.user.email;

    await this.loadZones();

    // Restore zone + tab from URL
    const params = new URLSearchParams(window.location.search);
    const zoneId = params.get('zone');
    const tab = (window.location.hash || '').replace('#', '') || 'overview';
    if (zoneId && this.state.zones.find(z => z.id === zoneId)) {
      await this.selectZone(zoneId, { tab });
    }
  },

  async loadZones() {
    const listEl = document.getElementById('zone-list');
    listEl.innerHTML = '<div class="loading"><span class="spinner"></span> Loading zones...</div>';

    try {
      const data = await this.api('/zones');
      this.state.zones = data.zones;
      this.state.lastRefreshed = data.lastRefreshed;

      // Fetch security insights — store promise so we can await it later
      this._securityInsightsPromise = this.loadSecurityInsights();

      this.renderZoneList();

      // Auto-select first zone (only if URL doesn't already specify one)
      const urlZone = new URLSearchParams(window.location.search).get('zone');
      if (!urlZone && data.zones.length === 1) {
        this.selectZone(data.zones[0].id);
      }
    } catch (err) {
      listEl.innerHTML = `<div class="loading">Failed to load zones</div>`;
    }
  },

  async refreshZones() {
    const btn = document.getElementById('refresh-zones-btn');
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Refreshing...';
    }

    try {
      const data = await this.api('/zones/refresh', { method: 'POST' });
      this.state.zones = data.zones;
      this.state.lastRefreshed = data.lastRefreshed;
      this.renderZoneList();

      // Re-select active zone if still present
      if (this.state.activeZone) {
        const still = data.zones.find(z => z.id === this.state.activeZone.id);
        if (still) this.state.activeZone = still;
      }
    } catch (err) {
      console.error('Failed to refresh zones:', err.message);
    }
  },

  renderZoneList() {
    const listEl = document.getElementById('zone-list');
    const lastRefreshed = this.state.lastRefreshed
      ? new Date(this.state.lastRefreshed).toLocaleString()
      : 'never';

    listEl.innerHTML = this.state.zones.map(z => {
      const issues = this.state.securityInsights[z.id] || [];
      const hasIssues = issues.length > 0;
      const hasCritical = issues.some(i => i.severity === 'Critical' || i.severity === 'High');
      return `
        <div class="zone-item ${this.state.activeZone?.id === z.id ? 'active' : ''}"
             data-zone-id="${z.id}" onclick="App.selectZone('${z.id}')">
          <div class="zone-dot ${z.status === 'active' ? 'active' : z.status === 'pending' ? 'pending' : 'error'}"></div>
          <div class="zone-info">
            <div class="zone-domain">${z.name}</div>
            <div class="zone-plan">${z.plan || 'Free'}</div>
          </div>
          ${hasIssues ? `<i class="fa-solid fa-triangle-exclamation zone-warning ${hasCritical ? 'critical' : 'moderate'}" title="${issues.length} security issue${issues.length > 1 ? 's' : ''}"></i>` : ''}
        </div>
      `;
    }).join('') + `
      <div class="zone-list-footer">
        <div class="zone-refresh-meta">Updated ${lastRefreshed}</div>
        <button id="refresh-zones-btn" class="btn btn-ghost btn-sm btn-full" onclick="App.refreshZones()">
          <i class="fa-solid fa-arrows-rotate"></i> Refresh Zones
        </button>
      </div>
    `;
  },

  async selectZone(zoneId, opts = {}) {
    const zone = this.state.zones.find(z => z.id === zoneId);
    if (!zone) return;

    this.state.activeZone = zone;
    this.renderZoneList();

    // Show zone content
    document.getElementById('empty-state').classList.add('hidden');
    document.getElementById('zone-content').classList.remove('hidden');

    // Update header
    document.getElementById('zone-name').textContent = zone.name;
    const statusEl = document.getElementById('zone-status');
    statusEl.textContent = zone.paused ? 'Paused' : zone.status;
    statusEl.className = `badge ${zone.paused ? 'paused' : zone.status}`;
    document.getElementById('zone-meta').textContent = `Plan: ${zone.plan || 'Free'} · ID: ${zone.id} · NS: ${(zone.nameServers || []).join(', ')}`;

    // Show/hide tabs based on permissions
    this.updateTabVisibility(zone.permissions);
    this.updateSecurityTabBadge();

    // Update URL
    const tab = opts.tab || 'overview';
    const url = new URL(window.location);
    url.searchParams.set('zone', zoneId);
    url.hash = tab;
    history.pushState(null, '', url);

    // Load tab
    this.switchTab(tab, { updateUrl: false });
  },

  updateTabVisibility(permissions) {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
      const tabName = tab.dataset.tab;
      let visible = true;

      if (tabName === 'dns' && !permissions.includes('dns:read') && !permissions.includes('dns:write')) {
        visible = false;
      }
      if (tabName === 'analytics' && !permissions.includes('analytics:read')) {
        visible = false;
      }
      if (tabName === 'bots' && !permissions.includes('bots:read') && !permissions.includes('bots:write')) {
        visible = false;
      }
      if (tabName === 'ssl' && !permissions.includes('ssl:read') && !permissions.includes('ssl:write')) {
        visible = false;
      }

      tab.style.display = visible ? '' : 'none';
    });
  },

  updateSecurityTabBadge() {
    const tab = document.querySelector('.tab[data-tab="security"]');
    if (!tab) return;
    const zone = this.state.activeZone;
    if (!zone) { tab.innerHTML = 'Security'; return; }

    const zoneIssues = this.state.securityInsights[zone.id] || [];
    const accountIssues = this.state.securityInsights['_account'] || [];
    const issues = [...zoneIssues, ...accountIssues];

    const hasCritical = issues.some(i => i.severity === 'Critical');
    const hasHigh = issues.some(i => i.severity === 'High');
    const hasModerate = issues.some(i => i.severity === 'Moderate');

    if (hasCritical || hasHigh) {
      tab.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="color: var(--danger); margin-right: 0.375rem;"></i>Security';
    } else if (hasModerate) {
      tab.innerHTML = '<i class="fa-solid fa-triangle-exclamation" style="color: var(--warning); margin-right: 0.375rem;"></i>Security';
    } else {
      tab.innerHTML = 'Security';
    }
  },

  // ═══════════════════════════════
  // Tabs
  // ═══════════════════════════════
  switchTab(tabName, opts = {}) {
    this.state.activeTab = tabName;

    // Update hash unless told not to (e.g. selectZone already set it)
    if (opts.updateUrl !== false) {
      const url = new URL(window.location);
      url.hash = tabName;
      history.replaceState(null, '', url);
    }

    // Update tab nav
    document.querySelectorAll('.tab').forEach(t => {
      t.classList.toggle('active', t.dataset.tab === tabName);
    });

    // Update panels
    document.querySelectorAll('.tab-panel').forEach(p => {
      p.classList.toggle('hidden', p.id !== `tab-${tabName}`);
      p.classList.toggle('active', p.id === `tab-${tabName}`);
    });

    // Load tab data
    switch (tabName) {
      case 'overview': this.loadOverview(); break;
      case 'dns': this.loadDns(); break;
      case 'analytics': this.loadAnalytics(); break;
      case 'security': this.loadSecurity(); break;
      case 'bots': this.loadBots(); break;
      case 'ssl': this.loadSsl(); break;
    }
  },

  // ═══════════════════════════════
  // Tab caching helpers
  // ═══════════════════════════════
  updateCachedAt(isoDate) {
    if (isoDate) this.state.zoneCachedAt = isoDate;
    const el = document.getElementById('zone-cached-at');
    if (el && this.state.zoneCachedAt) {
      el.textContent = 'Updated ' + new Date(this.state.zoneCachedAt).toLocaleString();
    }
  },

  async refreshAllTabs() {
    const icon = document.getElementById('zone-refresh-icon');
    if (icon) icon.classList.add('fa-spin');

    const tab = this.state.activeTab;
    try {
      // Refresh the current tab with fresh data
      switch (tab) {
        case 'overview': await this.loadOverview(true); break;
        case 'dns': await this.loadDns(true); break;
        case 'analytics': await this.loadAnalytics(true); break;
        case 'security': await this.loadSecurity(true); break;
        case 'bots': await this.loadBots(true); break;
        case 'ssl': await this.loadSsl(true); break;
      }
      this.updateCachedAt(new Date().toISOString());
    } finally {
      if (icon) icon.classList.remove('fa-spin');
    }
  },

  // ═══════════════════════════════
  // Overview Tab
  // ═══════════════════════════════
  async loadOverview(refresh = false) {
    const container = document.getElementById('overview-stats');
    container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading...</div>';

    try {
      const zone = this.state.activeZone;
      const qs = refresh ? '?refresh=true' : '';
      const [data, dnsData, ruleCounts] = await Promise.all([
        this.api(`/zones/${zone.id}/analytics/summary${qs}`),
        this.api(`/zones/${zone.id}/dns${qs ? qs + '&' : '?'}per_page=1`).catch(() => null),
        this.api(`/zones/${zone.id}/rule-counts${qs}`).catch(() => null),
      ]);

      const dnsCount = dnsData?.resultInfo?.total_count ?? '—';
      const zoneSecIssues = this.state.securityInsights[zone.id] || [];
      const acctSecIssues = this.state.securityInsights['_account'] || [];
      const allSecIssues = [...zoneSecIssues, ...acctSecIssues];
      const securityIssues = allSecIssues.length;
      const hasCriticalOrHigh = allSecIssues.some(i => i.severity === 'Critical' || i.severity === 'High');
      const hasModerate = allSecIssues.some(i => i.severity === 'Moderate');
      const securityColor = hasCriticalOrHigh ? 'text-danger' : hasModerate ? 'text-warning' : '';
      const cacheRules = ruleCounts?.cacheRules ?? '—';
      const securityRules = ruleCounts?.securityRules ?? '—';
      const pageRules = ruleCounts?.pageRules ?? '—';
      this.updateCachedAt(data._cachedAt || ruleCounts?._cachedAt);

      container.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Total Requests</div>
          <div class="stat-value">${formatNumber(data.requests)}</div>
          <div class="stat-sub">Last 24 hours</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Cached</div>
          <div class="stat-value">${formatNumber(data.cachedRequests)}</div>
          <div class="stat-sub">${data.requests ? Math.round(data.cachedRequests / data.requests * 100) : 0}% cache hit</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Bandwidth</div>
          <div class="stat-value">${formatBytes(data.bandwidth)}</div>
          <div class="stat-sub">${formatBytes(data.cachedBandwidth)} cached</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Threats</div>
          <div class="stat-value">${formatNumber(data.threats)}</div>
          <div class="stat-sub">Blocked</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">DNS Records</div>
          <div class="stat-value">${dnsCount}</div>
          <div class="stat-sub">Total records</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Security Issues</div>
          <div class="stat-value ${securityColor}">${securityIssues}</div>
          <div class="stat-sub">${securityIssues > 0 ? 'Action needed' : 'All clear'}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Unique Visitors</div>
          <div class="stat-value">${formatNumber(data.uniqueVisitors)}</div>
          <div class="stat-sub">Last 24 hours</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Page Views</div>
          <div class="stat-value">${formatNumber(data.pageViews)}</div>
          <div class="stat-sub">Last 24 hours</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Cache Rules</div>
          <div class="stat-value">${cacheRules}</div>
          <div class="stat-sub">Active rules</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Security Rules</div>
          <div class="stat-value">${securityRules}</div>
          <div class="stat-sub">WAF custom rules</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Page Rules</div>
          <div class="stat-value">${pageRules}</div>
          <div class="stat-sub">Active rules</div>
        </div>
        ${data.timeseries?.length ? `
          <div class="chart-container">
            <div class="chart-title">Traffic (24h)</div>
            <div class="mini-chart" id="overview-chart">
              ${data.timeseries.map((t, i) => {
                const max = Math.max(...data.timeseries.map(x => x.requests?.all || 0), 1);
                const height = ((t.requests?.all || 0) / max * 100);
                return `<div class="mini-bar" style="height: ${Math.max(height, 2)}%"
                  data-idx="${i}"
                  data-time="${new Date(t.since).toLocaleString()}"
                  data-requests="${formatNumber(t.requests?.all || 0)}"
                  data-cached="${formatNumber(t.requests?.cached || 0)}"
                  data-bandwidth="${formatBytes(t.bandwidth?.all || 0)}"
                  data-threats="${formatNumber(t.threats?.all || 0)}"
                  data-visitors="${formatNumber(t.uniques?.all || 0)}"></div>`;
              }).join('')}
            </div>
            <div id="chart-tooltip" class="chart-tooltip hidden"></div>
          </div>
        ` : ''}
      `;
      this.bindChartTooltip('overview-chart', 'chart-tooltip');
    } catch (err) {
      container.innerHTML = `<div class="loading">Failed to load overview: ${err.message}</div>`;
    }
  },

  bindChartTooltip(chartId, tooltipId) {
    const chart = document.getElementById(chartId);
    const tooltip = document.getElementById(tooltipId);
    if (!chart || !tooltip) return;

    chart.addEventListener('mouseover', (e) => {
      const bar = e.target.closest('.mini-bar');
      if (!bar) return;
      tooltip.innerHTML = `
        <div class="tt-time">${bar.dataset.time}</div>
        <div class="tt-row"><span>Requests</span><strong>${bar.dataset.requests}</strong></div>
        <div class="tt-row"><span>Cached</span><strong>${bar.dataset.cached}</strong></div>
        <div class="tt-row"><span>Bandwidth</span><strong>${bar.dataset.bandwidth}</strong></div>
        <div class="tt-row"><span>Threats</span><strong>${bar.dataset.threats}</strong></div>
        <div class="tt-row"><span>Visitors</span><strong>${bar.dataset.visitors}</strong></div>
      `;
      tooltip.classList.remove('hidden');
    });

    chart.addEventListener('mousemove', (e) => {
      const container = chart.closest('.chart-container');
      const rect = container.getBoundingClientRect();
      const ttRect = tooltip.getBoundingClientRect();
      let left = e.clientX - rect.left + 12;
      // Keep tooltip within container
      if (left + ttRect.width > rect.width - 12) {
        left = e.clientX - rect.left - ttRect.width - 12;
      }
      // Position above the cursor
      const top = e.clientY - rect.top - ttRect.height - 12;
      tooltip.style.left = `${left}px`;
      tooltip.style.top = `${top}px`;
    });

    chart.addEventListener('mouseleave', () => {
      tooltip.classList.add('hidden');
    });
  },

  // ═══════════════════════════════
  // DNS Tab
  // ═══════════════════════════════
  async loadDns(refresh = false) {
    const zone = this.state.activeZone;
    const container = document.getElementById('dns-table-container');
    container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading DNS records...</div>';

    const search = document.getElementById('dns-search').value;
    const type = document.getElementById('dns-type-filter').value;

    try {
      const params = new URLSearchParams();
      if (search) params.set('search', search);
      if (type) params.set('type', type);
      if (refresh) params.set('refresh', 'true');

      const data = await this.api(`/zones/${zone.id}/dns?${params}`);
      this.state.dnsRecords = data.records;
      this.state.canEditDns = data.canEdit;
      this.state.dnsCachedAt = data._cachedAt;

      // Show/hide add button
      const addBtn = document.getElementById('dns-add-btn');
      addBtn.classList.toggle('hidden', !data.canEdit);

      this.renderDnsTable();
    } catch (err) {
      container.innerHTML = `<div class="loading">Failed to load DNS: ${err.message}</div>`;
    }
  },

  renderDnsTable() {
    const container = document.getElementById('dns-table-container');
    const records = this.state.dnsRecords;
    const canEdit = this.state.canEditDns;
    this.updateCachedAt(this.state.dnsCachedAt);

    if (!records.length) {
      container.innerHTML = '<div class="loading">No DNS records found</div>';
      return;
    }

    container.innerHTML = `
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Name</th>
            <th>Content</th>
            <th>Proxy</th>
            <th>TTL</th>
            ${canEdit ? '<th>Actions</th>' : ''}
          </tr>
        </thead>
        <tbody>
          ${records.map(r => `
            <tr>
              <td><span class="dns-type-badge ${r.type}">${r.type}</span></td>
              <td class="mono">${r.name}</td>
              <td class="mono" style="max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escapeHtml(r.content)}">${escapeHtml(r.content)}</td>
              <td>${r.proxied !== undefined ? `<i class="fa-solid fa-cloud proxy-icon ${r.proxied ? 'on' : 'off'}"></i>` : '—'}</td>
              <td class="mono">${r.ttl === 1 ? 'Auto' : formatTtl(r.ttl)}</td>
              ${canEdit ? `
                <td>
                  <div class="actions-cell">
                    <button class="btn-icon" onclick="App.editDnsRecord('${r.id}')" title="Edit">✎</button>
                    <button class="btn-icon danger" onclick="App.deleteDnsRecord('${r.id}')" title="Delete">✕</button>
                  </div>
                </td>
              ` : ''}
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  },

  // ─── DNS Modal ───
  openDnsModal(record = null) {
    const modal = document.getElementById('dns-modal');
    const title = document.getElementById('dns-modal-title');

    if (record) {
      title.textContent = 'Edit DNS Record';
      document.getElementById('dns-record-id').value = record.id;
      document.getElementById('dns-type').value = record.type;
      document.getElementById('dns-name').value = record.name;
      document.getElementById('dns-content').value = record.content;
      document.getElementById('dns-ttl').value = record.ttl;
      document.getElementById('dns-proxied').checked = record.proxied;
      document.getElementById('dns-comment').value = record.comment || '';
    } else {
      title.textContent = 'Add DNS Record';
      document.getElementById('dns-form').reset();
      document.getElementById('dns-record-id').value = '';
    }

    modal.classList.remove('hidden');
  },

  closeDnsModal() {
    document.getElementById('dns-modal').classList.add('hidden');
  },

  editDnsRecord(recordId) {
    const record = this.state.dnsRecords.find(r => r.id === recordId);
    if (record) this.openDnsModal(record);
  },

  async saveDnsRecord() {
    const zone = this.state.activeZone;
    const recordId = document.getElementById('dns-record-id').value;
    const saveBtn = document.getElementById('dns-save');
    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    const body = {
      type: document.getElementById('dns-type').value,
      name: document.getElementById('dns-name').value,
      content: document.getElementById('dns-content').value,
      ttl: parseInt(document.getElementById('dns-ttl').value),
      proxied: document.getElementById('dns-proxied').checked,
      comment: document.getElementById('dns-comment').value,
    };

    try {
      if (recordId) {
        await this.api(`/zones/${zone.id}/dns/${recordId}`, { method: 'PATCH', body });
      } else {
        await this.api(`/zones/${zone.id}/dns`, { method: 'POST', body });
      }

      this.closeDnsModal();
      await this.loadDns();
    } catch (err) {
      alert(`Failed to save: ${err.message}`);
    } finally {
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save Record';
    }
  },

  async deleteDnsRecord(recordId) {
    const record = this.state.dnsRecords.find(r => r.id === recordId);
    if (!confirm(`Delete ${record?.type} record for ${record?.name}?`)) return;

    try {
      await this.api(`/zones/${this.state.activeZone.id}/dns/${recordId}`, { method: 'DELETE' });
      await this.loadDns();
    } catch (err) {
      alert(`Failed to delete: ${err.message}`);
    }
  },

  // ═══════════════════════════════
  // Analytics Tab
  // ═══════════════════════════════
  async loadAnalytics(refresh = false) {
    const zone = this.state.activeZone;
    const container = document.getElementById('analytics-content');
    container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading analytics...</div>';

    const minutes = document.getElementById('analytics-range').value;

    try {
      const sinceDate = new Date(Date.now() - minutes * 60 * 1000).toISOString();
      const untilDate = new Date().toISOString();
      const refreshParam = refresh ? '&refresh=true' : '';
      const data = await this.api(`/zones/${zone.id}/analytics/summary?since=${sinceDate}&until=${untilDate}${refreshParam}`);
      this.updateCachedAt(data._cachedAt);

      container.innerHTML = `
        <div class="stat-card">
          <div class="stat-label">Total Requests</div>
          <div class="stat-value">${formatNumber(data.requests)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Cached Requests</div>
          <div class="stat-value">${formatNumber(data.cachedRequests)}</div>
          <div class="stat-sub">${data.requests ? Math.round(data.cachedRequests / data.requests * 100) : 0}% hit rate</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Bandwidth</div>
          <div class="stat-value">${formatBytes(data.bandwidth)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Cached Bandwidth</div>
          <div class="stat-value">${formatBytes(data.cachedBandwidth)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Threats Blocked</div>
          <div class="stat-value">${formatNumber(data.threats)}</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Unique Visitors</div>
          <div class="stat-value">${formatNumber(data.uniqueVisitors)}</div>
        </div>
        ${data.timeseries?.length ? `
          <div class="chart-container">
            <div class="chart-title">Requests over time</div>
            <div class="mini-chart" id="analytics-chart">
              ${data.timeseries.map((t, i) => {
                const max = Math.max(...data.timeseries.map(x => x.requests?.all || 0), 1);
                const height = ((t.requests?.all || 0) / max * 100);
                return `<div class="mini-bar" style="height: ${Math.max(height, 2)}%"
                  data-idx="${i}"
                  data-time="${new Date(t.since).toLocaleString()}"
                  data-requests="${formatNumber(t.requests?.all || 0)}"
                  data-cached="${formatNumber(t.requests?.cached || 0)}"
                  data-bandwidth="${formatBytes(t.bandwidth?.all || 0)}"
                  data-threats="${formatNumber(t.threats?.all || 0)}"
                  data-visitors="${formatNumber(t.uniques?.all || 0)}"></div>`;
              }).join('')}
            </div>
            <div id="analytics-tooltip" class="chart-tooltip hidden"></div>
          </div>
        ` : ''}
      `;

      this.bindChartTooltip('analytics-chart', 'analytics-tooltip');
    } catch (err) {
      container.innerHTML = `<div class="loading">Failed to load analytics: ${err.message}</div>`;
    }
  },

  // ═══════════════════════════════
  // Security Insights
  // ═══════════════════════════════
  async loadSecurityInsights(refresh = false) {
    try {
      const url = refresh ? '/zones/security-insights?refresh=true' : '/zones/security-insights';
      const data = await this.api(url);
      this.state.securityInsights = data.insights || {};
      this.state.securityCachedAt = data._cachedAt || new Date().toISOString();
      // Re-render zone list to show warning icons + update security tab badge
      this.renderZoneList();
      this.updateSecurityTabBadge();
    } catch (err) {
      console.warn('Failed to load security insights:', err.message);
    }
  },

  async loadSecurity(refresh = false) {
    const zone = this.state.activeZone;
    const container = document.getElementById('security-content');

    if (refresh) {
      container.innerHTML = '<div class="loading"><span class="spinner"></span> Refreshing...</div>';
      await this.loadSecurityInsights(true);
    } else if (!Object.keys(this.state.securityInsights).length && this._securityInsightsPromise) {
      // Wait for the background fetch to complete on first load
      container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading security insights...</div>';
      await this._securityInsightsPromise;
    }

    // Combine zone-specific issues + account-level issues, dedup by issueType
    const zoneIssues = this.state.securityInsights[zone.id] || [];
    const accountIssues = this.state.securityInsights['_account'] || [];
    const seen = new Set();
    const issues = [...zoneIssues, ...accountIssues].filter(issue => {
      if (seen.has(issue.issueType)) return false;
      seen.add(issue.issueType);
      return true;
    });
    this.updateCachedAt(this.state.securityCachedAt);

    if (!issues.length) {
      container.innerHTML = `
        <div class="security-clean">
          <i class="fa-solid fa-shield-check"></i>
          <h3>No Security Issues</h3>
          <p>No active security insights found for this zone.</p>
        </div>
      `;
      return;
    }

    // Sort: Critical > High > Moderate > Low
    const severityOrder = { Critical: 0, High: 1, Moderate: 2, Low: 3 };
    const sorted = [...issues].sort((a, b) => (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4));

    container.innerHTML = `
      <div class="security-header">
        <h3><i class="fa-solid fa-shield-halved"></i> Security Insights</h3>
        <span class="security-count">${issues.length} issue${issues.length > 1 ? 's' : ''}</span>
      </div>
      <div class="security-list">
        ${sorted.map(issue => `
          <div class="security-issue severity-${issue.severity.toLowerCase()}">
            <div class="issue-icon">
              <i class="fa-solid ${severityIcon(issue.severity)}"></i>
            </div>
            <div class="issue-body">
              <div class="issue-top">
                <span class="issue-severity badge-severity ${issue.severity.toLowerCase()}">${issue.severity}</span>
                <span class="issue-type">${formatIssueClass(issue.issueClass)}</span>
              </div>
              ${issue.detectionMethod && !issue.detectionMethod.startsWith('security_center.') ? `<div class="issue-detail">${escapeHtml(issue.detectionMethod)}</div>` : ''}
              ${(() => {
                const rec = resolveRecommendation(issue.issueClass);
                // Use API resolve_text if it's real text (not an i18n key)
                const apiText = issue.resolveText && !issue.resolveText.startsWith('security_center.') ? issue.resolveText : '';
                const text = apiText || rec.text;
                if (!text) return '';
                const zoneName = App.state.activeZone?.name || '';
                const dashLink = rec.path && zoneName
                  ? `https://dash.cloudflare.com/?to=/:account/${zoneName}/${rec.path}`
                  : null;
                if (dashLink) {
                  return `<div class="issue-resolve"><a href="${escapeHtml(dashLink)}" target="_blank" rel="noopener">${escapeHtml(text)}</a></div>`;
                }
                return `<div class="issue-resolve">${escapeHtml(text)}</div>`;
              })()}
              <div class="issue-since">Since ${new Date(issue.since).toLocaleDateString()}</div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  },

  // ═══════════════════════════════
  // SSL / TLS Tab
  // ═══════════════════════════════
  async loadSsl(refresh = false) {
    const zone = this.state.activeZone;
    const container = document.getElementById('ssl-content');
    container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading SSL/TLS settings...</div>';

    try {
      const url = `/zones/${zone.id}/ssl${refresh ? '?refresh=true' : ''}`;
      const data = await this.api(url);
      this.updateCachedAt(data._cachedAt);

      const sslModeLabels = {
        off: 'Off',
        flexible: 'Flexible',
        full: 'Full',
        strict: 'Full (Strict)',
      };

      container.innerHTML = `
        <div class="ssl-settings">
          <div class="ssl-card">
            <div class="ssl-card-info">
              <div class="ssl-card-label">SSL/TLS Encryption Mode</div>
              <div class="ssl-card-desc">Controls how Cloudflare connects to your origin server</div>
            </div>
            <div class="ssl-card-control">
              <select id="ssl-mode-select">
                <option value="off" ${data.sslMode === 'off' ? 'selected' : ''}>Off</option>
                <option value="flexible" ${data.sslMode === 'flexible' ? 'selected' : ''}>Flexible</option>
                <option value="full" ${data.sslMode === 'full' ? 'selected' : ''}>Full</option>
                <option value="strict" ${data.sslMode === 'strict' ? 'selected' : ''}>Full (Strict)</option>
              </select>
            </div>
          </div>

          <div class="ssl-card">
            <div class="ssl-card-info">
              <div class="ssl-card-label">Minimum TLS Version</div>
              <div class="ssl-card-desc">Only allow HTTPS connections from visitors that support the selected TLS version or newer</div>
            </div>
            <div class="ssl-card-control">
              <select id="ssl-min-tls-select">
                <option value="1.0" ${data.minTlsVersion === '1.0' ? 'selected' : ''}>TLS 1.0</option>
                <option value="1.1" ${data.minTlsVersion === '1.1' ? 'selected' : ''}>TLS 1.1</option>
                <option value="1.2" ${data.minTlsVersion === '1.2' ? 'selected' : ''}>TLS 1.2</option>
                <option value="1.3" ${data.minTlsVersion === '1.3' ? 'selected' : ''}>TLS 1.3</option>
              </select>
            </div>
          </div>

          <div class="ssl-card">
            <div class="ssl-card-info">
              <div class="ssl-card-label">TLS 1.3</div>
              <div class="ssl-card-desc">Enable the latest TLS protocol version for improved security and performance</div>
            </div>
            <div class="ssl-card-control">
              <label class="toggle-switch">
                <input type="checkbox" id="ssl-tls13" ${data.tls13 === 'on' || data.tls13 === 'zrt' ? 'checked' : ''}>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div class="ssl-card">
            <div class="ssl-card-info">
              <div class="ssl-card-label">Always Use HTTPS</div>
              <div class="ssl-card-desc">Redirect all requests with scheme "http" to "https". This applies to all HTTP requests to the zone</div>
            </div>
            <div class="ssl-card-control">
              <label class="toggle-switch">
                <input type="checkbox" id="ssl-always-https" ${data.alwaysUseHttps ? 'checked' : ''}>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div class="ssl-card">
            <div class="ssl-card-info">
              <div class="ssl-card-label">Automatic HTTPS Rewrites</div>
              <div class="ssl-card-desc">Automatically rewrite HTTP URLs to HTTPS to avoid mixed content issues and ensure all resources load securely</div>
            </div>
            <div class="ssl-card-control">
              <label class="toggle-switch">
                <input type="checkbox" id="ssl-auto-rewrites" ${data.automaticHttpsRewrites ? 'checked' : ''}>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>
        </div>
      `;

      // Bind events
      document.getElementById('ssl-mode-select').addEventListener('change', async (e) => {
        const select = e.target;
        const original = data.sslMode;
        select.disabled = true;
        try {
          await this.api(`/zones/${zone.id}/ssl/mode`, { method: 'PATCH', body: { value: select.value } });
          showToast('SSL/TLS encryption mode updated');
        } catch (err) {
          select.value = original;
          showToast(`Failed to update SSL mode: ${err.message}`, 'error');
        } finally {
          select.disabled = false;
        }
      });

      document.getElementById('ssl-min-tls-select').addEventListener('change', async (e) => {
        const select = e.target;
        const original = data.minTlsVersion;
        select.disabled = true;
        try {
          await this.api(`/zones/${zone.id}/ssl/min-tls`, { method: 'PATCH', body: { value: select.value } });
          showToast(`Minimum TLS version set to ${select.value}`);
        } catch (err) {
          select.value = original;
          showToast(`Failed to update minimum TLS: ${err.message}`, 'error');
        } finally {
          select.disabled = false;
        }
      });

      document.getElementById('ssl-always-https').addEventListener('change', async (e) => {
        const toggle = e.target;
        toggle.disabled = true;
        try {
          await this.api(`/zones/${zone.id}/ssl/always-https`, { method: 'PATCH', body: { value: toggle.checked } });
          showToast(`Always Use HTTPS ${toggle.checked ? 'enabled' : 'disabled'}`);
        } catch (err) {
          toggle.checked = !toggle.checked;
          showToast(`Failed to update Always Use HTTPS: ${err.message}`, 'error');
        } finally {
          toggle.disabled = false;
        }
      });

      document.getElementById('ssl-tls13').addEventListener('change', async (e) => {
        const toggle = e.target;
        toggle.disabled = true;
        try {
          await this.api(`/zones/${zone.id}/ssl/tls13`, { method: 'PATCH', body: { value: toggle.checked } });
          showToast(`TLS 1.3 ${toggle.checked ? 'enabled' : 'disabled'}`);
        } catch (err) {
          toggle.checked = !toggle.checked;
          showToast(`Failed to update TLS 1.3: ${err.message}`, 'error');
        } finally {
          toggle.disabled = false;
        }
      });

      document.getElementById('ssl-auto-rewrites').addEventListener('change', async (e) => {
        const toggle = e.target;
        toggle.disabled = true;
        try {
          await this.api(`/zones/${zone.id}/ssl/auto-rewrites`, { method: 'PATCH', body: { value: toggle.checked } });
          showToast(`Automatic HTTPS Rewrites ${toggle.checked ? 'enabled' : 'disabled'}`);
        } catch (err) {
          toggle.checked = !toggle.checked;
          showToast(`Failed to update HTTPS Rewrites: ${err.message}`, 'error');
        } finally {
          toggle.disabled = false;
        }
      });

    } catch (err) {
      container.innerHTML = `<div class="loading">Failed to load SSL/TLS settings: ${err.message}</div>`;
    }
  },

  // ═══════════════════════════════
  // Bot Management Tab
  // ═══════════════════════════════
  async loadBots(refresh = false) {
    const zone = this.state.activeZone;
    const container = document.getElementById('bots-content');
    container.innerHTML = '<div class="loading"><span class="spinner"></span> Loading bot management...</div>';

    try {
      const qs = refresh ? '?refresh=true' : '';
      const data = await this.api(`/zones/${zone.id}/bots/config${qs}`);
      const config = data.config;
      const canEdit = data.canEdit;

      this.updateCachedAt(data._cachedAt);

      container.innerHTML = `
        <div class="bot-grid">
          ${botSetting('Bot Fight Mode', 'fight_mode', config.fight_mode, canEdit,
            'Automatically mitigate automated traffic detected as bots')}
          ${botSetting('JavaScript Detection', 'enable_js', config.enable_js, canEdit,
            'Use JavaScript-based detection for additional bot scoring')}
          ${botSetting('WordPress Optimization', 'optimize_wordpress', config.optimize_wordpress, canEdit,
            'Optimize bot management rules for WordPress sites')}
          ${botSetting('Static Resource Protection', 'sbfm_static_resource_protection', config.sbfm_static_resource_protection, canEdit,
            'Protect static resources from bot access')}
          ${botSetting('Auto-Update Model', 'auto_update_model', config.auto_update_model, canEdit,
            'Automatically update the bot detection model')}
        </div>

        <h3 style="margin-bottom: 1rem; font-size: 0.875rem; color: var(--text-secondary);">SBFM Actions</h3>
        <div class="bot-grid">
          ${sbfmSetting('Definitely Automated', 'sbfm_definitely_automated', config.sbfm_definitely_automated, canEdit)}
          ${sbfmSetting('Likely Automated', 'sbfm_likely_automated', config.sbfm_likely_automated, canEdit)}
          ${sbfmSetting('Verified Bots', 'sbfm_verified_bots', config.sbfm_verified_bots, canEdit)}
        </div>
      `;

      // Bind toggle events
      if (canEdit) {
        container.querySelectorAll('.toggle').forEach(toggle => {
          toggle.addEventListener('change', async (e) => {
            const field = e.target.dataset.field;
            const value = e.target.checked;
            try {
              await App.api(`/zones/${zone.id}/bots/config`, {
                method: 'PUT',
                body: { [field]: value },
              });
            } catch (err) {
              e.target.checked = !value; // Revert
              alert(`Failed to update: ${err.message}`);
            }
          });
        });

        container.querySelectorAll('.sbfm-select').forEach(select => {
          select.addEventListener('change', async (e) => {
            const field = e.target.dataset.field;
            const value = e.target.value;
            try {
              await App.api(`/zones/${zone.id}/bots/config`, {
                method: 'PUT',
                body: { [field]: value },
              });
            } catch (err) {
              alert(`Failed to update: ${err.message}`);
            }
          });
        });
      }
    } catch (err) {
      container.innerHTML = `<div class="loading">Failed to load bot config: ${err.message}</div>`;
    }
  },
};

// ═══════════════════════════════
// Helper Functions
// ═══════════════════════════════

function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  const icon = type === 'success' ? 'fa-circle-check' : 'fa-circle-xmark';
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span class="toast-icon"><i class="fa-solid ${icon}"></i></span><span class="toast-message">${message}</span>`;
  container.appendChild(toast);
  setTimeout(() => {
    toast.classList.add('toast-leaving');
    toast.addEventListener('animationend', () => toast.remove());
  }, 3000);
}

function formatNumber(n) {
  if (n === null || n === undefined) return '0';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return n.toLocaleString();
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
}

function formatTtl(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

function debounce(fn, delay) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), delay);
  };
}

function botSetting(label, field, value, canEdit, description) {
  return `
    <div class="bot-setting">
      <div class="bot-setting-header">
        <span class="bot-setting-label">${label}</span>
        <input type="checkbox" class="toggle" data-field="${field}"
          ${value ? 'checked' : ''} ${!canEdit ? 'disabled' : ''}>
      </div>
      <div class="bot-setting-desc">${description}</div>
    </div>
  `;
}

function sbfmSetting(label, field, value, canEdit) {
  return `
    <div class="bot-setting">
      <div class="bot-setting-header">
        <span class="bot-setting-label">${label}</span>
      </div>
      <select class="select-sm sbfm-select" data-field="${field}" ${!canEdit ? 'disabled' : ''}>
        <option value="allow" ${value === 'allow' ? 'selected' : ''}>Allow</option>
        <option value="block" ${value === 'block' ? 'selected' : ''}>Block</option>
        <option value="managed_challenge" ${value === 'managed_challenge' ? 'selected' : ''}>Managed Challenge</option>
      </select>
    </div>
  `;
}

function severityIcon(severity) {
  switch (severity) {
    case 'Critical': return 'fa-circle-exclamation';
    case 'High': return 'fa-triangle-exclamation';
    case 'Moderate': return 'fa-circle-info';
    case 'Low': return 'fa-circle-question';
    default: return 'fa-circle-info';
  }
}

function resolveRecommendation(issueClass) {
  // { text, path } — path is relative to the CF dashboard zone URL
  const recommendations = {
    security_txt_not_enabled:            { text: 'Enable a security.txt file to help researchers report vulnerabilities', path: 'security' },
    ssl_not_enabled:                     { text: 'Enable SSL/TLS to secure traffic between visitors and your site', path: 'ssl-tls' },
    dnssec_not_enabled:                  { text: 'Enable DNSSEC to protect against DNS spoofing attacks', path: 'dns/settings' },
    always_use_https_not_enabled:        { text: 'Enable Always Use HTTPS to redirect all HTTP requests', path: 'ssl-tls/edge-certificates' },
    hsts_not_enabled:                    { text: 'Enable HSTS to enforce secure connections in browsers', path: 'ssl-tls/edge-certificates' },
    tls_1_0_enabled:                     { text: 'Set minimum TLS version to 1.2', path: 'ssl-tls/edge-certificates' },
    tls_1_1_enabled:                     { text: 'Set minimum TLS version to 1.2', path: 'ssl-tls/edge-certificates' },
    no_caa_records:                      { text: 'Add CAA DNS records to control which CAs can issue certificates', path: 'dns/records' },
    insecure_ssl_mode:                   { text: 'Upgrade SSL/TLS encryption mode to Full (Strict)', path: 'ssl-tls' },
    browser_integrity_check_not_enabled: { text: 'Enable Browser Integrity Check to block malicious requests', path: 'security' },
    email_obfuscation_not_enabled:       { text: 'Enable email address obfuscation to prevent scraping', path: 'security' },
    hotlink_protection_not_enabled:      { text: 'Enable hotlink protection to prevent bandwidth theft', path: 'security' },
    dmarc_record_error:                  { text: 'Fix the DMARC DNS record — ensure it starts with v=DMARC1 and has a valid policy (p=reject or p=quarantine)', path: 'dns/records' },
    dmarc_policy_not_enabled:            { text: 'Add a DMARC TXT record on _dmarc, e.g. v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com', path: 'dns/records' },
    dmarc_not_enabled:                   { text: 'Add a DMARC TXT record on _dmarc subdomain to prevent email spoofing', path: 'dns/records' },
    spf_record_not_enabled:              { text: 'Add an SPF TXT record to specify which mail servers can send on behalf of your domain', path: 'dns/records' },
    spf_record_error:                    { text: 'Fix the SPF DNS record — ensure it is a valid TXT record starting with v=spf1', path: 'dns/records' },
    dkim_not_enabled:                    { text: 'Configure DKIM signing for your domain to authenticate outgoing emails', path: 'dns/records' },
    no_waf_managed_rules:                { text: 'Enable WAF Managed Rules to protect against common attacks', path: 'security/waf' },
    javascript_detections_not_enabled:   { text: 'Enable JavaScript Detections in Bot Management', path: 'security/bots' },
    manage_bot_fight_mode:               { text: 'Review Bot Fight Mode settings to detect and mitigate bot traffic', path: 'security/bots' },
    no_block_ai_bots:                    { text: 'Enable Block AI Bots to prevent AI scrapers', path: 'security' },
    no_challenge_ai_bots:                { text: 'Enable AI Labyrinth to challenge AI bots', path: 'security' },
    no_turnstile_enabled:                { text: 'Add a Turnstile widget to protect forms from bots', path: null },
    access_policy_insecure:              { text: 'Review Access policies — overprovisioned or insecure policies detected', path: null },
    mfa_not_enabled:                     { text: 'Enable multi-factor authentication for this account member', path: null },
    polish_not_enabled:                  { text: 'Enable Polish to automatically optimize images', path: 'speed/optimization' },
    argo_smart_routing_not_enabled:      { text: 'Enable Argo Smart Routing for faster traffic routing', path: 'traffic' },
    dmarc:                               { text: 'Add a DMARC TXT record on _dmarc subdomain to prevent email spoofing', path: 'dns/records' },
  };
  return recommendations[issueClass] || { text: 'Review this finding in the Cloudflare dashboard', path: null };
}

function formatIssueClass(issueClass) {
  return (issueClass || '')
    .replace(/_/g, ' ')
    .replace(/\bno\b/gi, 'No')
    .replace(/\b\w/g, c => c.toUpperCase());
}

// ─── Boot ───
document.addEventListener('DOMContentLoaded', () => App.init());

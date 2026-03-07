import { cfApi } from '../api/cloudflare.js';
import { createMimeMessage } from 'mimetext';
import { EmailMessage } from 'cloudflare:email';

const SUPER_ADMIN_ROLE_ID = '33666b9c79b9a5273fc7344ff42f953d';
const FROM_EMAIL = 'reports@5150studios.com.au';

/**
 * Fetch all zones from the account (paginated)
 */
async function fetchAllZones(env) {
  const cronToken = env.CF_CRON_TOKEN;
  const zones = [];
  let page = 1;
  while (true) {
    const data = await cfApi(env, '/zones', {
      params: { 'account.id': env.CF_ACCOUNT_ID, page: String(page), per_page: '50' },
    }, cronToken);
    if (!data.success || !data.result?.length) break;
    for (const z of data.result) {
      zones.push({ id: z.id, name: z.name });
    }
    const totalPages = data.result_info?.total_pages || 1;
    if (page >= totalPages) break;
    page++;
  }
  return zones;
}

/**
 * Fetch security insights, filter to Critical/Moderate, group by zone
 */
async function fetchAndGroupInsights(env, zones) {
  const cronToken = env.CF_CRON_TOKEN;
  const data = await cfApi(env, `/accounts/${env.CF_ACCOUNT_ID}/security-center/insights`, {
    params: { per_page: '100', dismissed: 'false' },
  }, cronToken);

  if (!data.success) {
    console.error('[securityReport] Failed to fetch insights:', data.errors);
    return {};
  }

  const issues = data.result?.issues || [];
  const zoneMap = new Map(zones.map(z => [z.id, z.name]));
  const byZone = {};

  for (const issue of issues) {
    if (issue.severity !== 'Critical' && issue.severity !== 'Moderate') continue;

    const mapped = {
      issueType: issue.issue_type,
      severity: issue.severity,
      subject: issue.subject,
      resolveText: issue.resolve_text,
    };

    const zoneTag = issue.payload?.zone_tag;

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
  }

  // Deduplicate by issueType per zone
  for (const key of Object.keys(byZone)) {
    const seen = new Set();
    byZone[key] = byZone[key].filter(issue => {
      if (seen.has(issue.issueType)) return false;
      seen.add(issue.issueType);
      return true;
    });
  }

  return byZone;
}

/**
 * Fetch super admin email addresses from account members
 */
async function fetchSuperAdminEmails(env) {
  const cronToken = env.CF_CRON_TOKEN;
  const data = await cfApi(env, `/accounts/${env.CF_ACCOUNT_ID}/members`, {}, cronToken);
  if (!data.success) {
    console.error('[securityReport] Failed to fetch members:', data.errors);
    return [];
  }

  return (data.result || [])
    .filter(m => m.roles?.some(r => r.id === SUPER_ADMIN_ROLE_ID))
    .map(m => m.user?.email)
    .filter(Boolean);
}

/**
 * Build severity badge HTML
 */
function severityBadge(severity) {
  const color = severity === 'Critical' ? '#dc2626' : '#f59e0b';
  return `<span style="display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;color:#fff;background:${color};">${severity}</span>`;
}

/**
 * Build HTML email body
 */
function buildEmailHtml(byZone, zoneMap, dashboardBase) {
  let html = `
    <div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:680px;margin:0 auto;padding:20px;">
      <h1 style="font-size:20px;border-bottom:2px solid #e5e7eb;padding-bottom:12px;">Daily Security Report</h1>
  `;

  for (const [zoneId, issues] of Object.entries(byZone)) {
    if (!issues.length) continue;

    const zoneName = zoneId === '_account' ? 'Account-Level Issues' : (zoneMap.get(zoneId) || zoneId);
    const zoneLink = zoneId === '_account'
      ? '#'
      : `${dashboardBase}/?zone=${zoneId}#security`;

    html += `<h2 style="font-size:16px;margin-top:24px;"><a href="${zoneLink}" style="color:#2563eb;text-decoration:none;">${zoneName}</a></h2>`;
    html += `<ul style="list-style:none;padding:0;">`;

    for (const issue of issues) {
      let resolveHtml = '';
      if (issue.resolveText) {
        // If resolve text contains a URL, wrap it
        const urlMatch = issue.resolveText.match(/(https?:\/\/\S+)/);
        if (urlMatch) {
          resolveHtml = `<br><span style="font-size:13px;color:#6b7280;">${issue.resolveText.replace(urlMatch[1], `<a href="${urlMatch[1]}" style="color:#2563eb;">${urlMatch[1]}</a>`)}</span>`;
        } else {
          resolveHtml = `<br><span style="font-size:13px;color:#6b7280;">${issue.resolveText}</span>`;
        }
      }

      html += `<li style="padding:8px 0;border-bottom:1px solid #f3f4f6;">
        ${severityBadge(issue.severity)} <strong>${issue.issueType}</strong>
        ${resolveHtml}
      </li>`;
    }

    html += `</ul>`;
  }

  html += `
      <p style="margin-top:32px;font-size:12px;color:#9ca3af;">Sent by CF Zone Dashboard</p>
    </div>
  `;

  return html;
}

/**
 * Main cron handler
 */
export async function runSecurityReport(env) {
  console.log('[securityReport] Starting daily security report...');

  const zones = await fetchAllZones(env);
  const zoneMap = new Map(zones.map(z => [z.id, z.name]));

  const byZone = await fetchAndGroupInsights(env, zones);

  // Check if there are any issues at all
  const totalIssues = Object.values(byZone).reduce((sum, arr) => sum + arr.length, 0);
  if (totalIssues === 0) {
    console.log('[securityReport] No Critical/Moderate issues found. Skipping email.');
    return;
  }

  console.log(`[securityReport] Found ${totalIssues} issues across ${Object.keys(byZone).length} zones`);

  const adminEmails = await fetchSuperAdminEmails(env);
  if (!adminEmails.length) {
    console.error('[securityReport] No super admin emails found. Skipping.');
    return;
  }

  console.log(`[securityReport] Sending report to: ${adminEmails.join(', ')}`);

  // Use deployed URL if available, fallback to localhost for dev
  const dashboardBase = env.DASHBOARD_URL || 'http://localhost:8787';
  const dateStr = new Date().toLocaleDateString('en-US', {
    weekday: 'short', month: 'short', day: '2-digit', year: 'numeric',
  });
  const subject = `Daily Security Report — ${dateStr}`;
  const htmlBody = buildEmailHtml(byZone, zoneMap, dashboardBase);

  for (const toEmail of adminEmails) {
    try {
      const msg = createMimeMessage();
      msg.setSender({ name: 'CF Zone Dashboard', addr: FROM_EMAIL });
      msg.setRecipient(toEmail);
      msg.setSubject(subject);
      msg.addMessage({ contentType: 'text/html', data: htmlBody });

      const message = new EmailMessage(FROM_EMAIL, toEmail, msg.asRaw());
      await env.REPORT_EMAIL.send(message);
      console.log(`[securityReport] Email sent to ${toEmail}`);
    } catch (err) {
      console.error(`[securityReport] Failed to send to ${toEmail}:`, err.message);
    }
  }
}

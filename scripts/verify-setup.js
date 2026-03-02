#!/usr/bin/env node

/**
 * Verify that the super-admin CF_API_TOKEN is configured correctly.
 *
 * Usage:
 *   CF_API_TOKEN=xxx CF_ACCOUNT_ID=yyy node scripts/verify-setup.js
 *
 * This replaces the old seed-users.js script — user accounts are
 * no longer stored in KV. Authentication is handled via CF API tokens.
 */

const CF_API_BASE = 'https://api.cloudflare.com/client/v4';

async function main() {
  const token = process.env.CF_API_TOKEN;
  const accountId = process.env.CF_ACCOUNT_ID;

  if (!token || !accountId) {
    console.error('Error: CF_API_TOKEN and CF_ACCOUNT_ID environment variables are required.');
    console.error('Usage: CF_API_TOKEN=xxx CF_ACCOUNT_ID=yyy node scripts/verify-setup.js');
    process.exit(1);
  }

  const headers = { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' };

  // 1. Verify token
  console.log('Verifying token...');
  const verifyRes = await fetch(`${CF_API_BASE}/user/tokens/verify`, { headers });
  const verify = await verifyRes.json();

  if (!verify.success || verify.result?.status !== 'active') {
    console.error('Token verification failed:', JSON.stringify(verify.errors));
    process.exit(1);
  }
  console.log('  Token is active.');

  // 2. Get user info
  const userRes = await fetch(`${CF_API_BASE}/user`, { headers });
  const user = await userRes.json();
  console.log(`  Token belongs to: ${user.result?.email}`);

  // 3. List account members
  console.log(`\nAccount members (${accountId}):`);
  const membersRes = await fetch(`${CF_API_BASE}/accounts/${accountId}/members`, { headers });
  const members = await membersRes.json();

  if (!members.success) {
    console.error('  Failed to list members:', JSON.stringify(members.errors));
  } else {
    for (const m of members.result || []) {
      const roles = (m.roles || []).map(r => r.name).join(', ');
      const isSuperAdmin = m.roles?.some(r => r.id === '33666b9c79b9a5273fc7344ff42f953d');
      console.log(`  ${m.user?.email} — ${roles}${isSuperAdmin ? ' [SUPER ADMIN]' : ''}`);
    }
  }

  // 4. Count zones
  const zonesRes = await fetch(`${CF_API_BASE}/zones?account.id=${accountId}&per_page=1`, { headers });
  const zones = await zonesRes.json();
  console.log(`\nTotal zones in account: ${zones.result_info?.total_count || 0}`);

  console.log('\nSetup looks good!');
}

main().catch(err => {
  console.error('Unexpected error:', err.message);
  process.exit(1);
});

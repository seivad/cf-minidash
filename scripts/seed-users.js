#!/usr/bin/env node

/**
 * Seed users into KV for the zone dashboard.
 *
 * Usage:
 *   1. Set your KV namespace ID in wrangler.json
 *   2. Run: npx wrangler kv key put --binding USER_CONFIG "user:mickdavies@me.com" "$(cat user-config.json)"
 *
 *   Or use this script to generate the JSON, then pipe it to wrangler:
 *   node scripts/seed-users.js | npx wrangler kv bulk put --binding USER_CONFIG -
 */

const AUTH_SECRET = '1234567890' // Must match .dev.vars AUTH_SECRET

async function hashPassword(password, secret) {
	// This mimics the Worker's SHA-256 hashing
	// In Node.js 18+ we can use crypto.subtle
	const { subtle } = globalThis.crypto || (await import('node:crypto')).webcrypto
	const encoder = new TextEncoder()
	const data = encoder.encode(password + secret)
	const hashBuffer = await subtle.digest('SHA-256', data)
	const hashArray = Array.from(new Uint8Array(hashBuffer))
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function main() {
	// ─── Define your users and their zone access ───
	const users = [
		{
			id: '62ef826f22e44f59f3a8a63c941f4c07',
			email: 'mickdavies@me.com',
			password: 'changeme123', // Set a real password
			zones: [
				{
					id: '66e81b0a48cc4a981454da9031e8c9fc',
					name: '5150studios.com.au',
					permissions: ['dns:read', 'dns:write', 'analytics:read', 'bots:read', 'bots:write', 'cache:purge'],
				},
			],
		},
		// Add more users as needed:
		// {
		//   email: 'client@example.com',
		//   password: 'their-password',
		//   zones: [
		//     {
		//       id: 'their-zone-id',
		//       name: 'example.com',
		//       permissions: ['dns:read', 'analytics:read'],
		//     },
		//   ],
		// },
	]

	const kvEntries = []

	for (const user of users) {
		const passwordHash = await hashPassword(user.password, AUTH_SECRET)

		kvEntries.push({
			key: `user:${user.email.toLowerCase()}`,
			value: JSON.stringify({
				id: user.id,
				email: user.email.toLowerCase(),
				passwordHash,
				zones: user.zones,
				createdAt: new Date().toISOString(),
			}),
		})
	}

	// Output for wrangler kv bulk put
	console.log(JSON.stringify(kvEntries, null, 2))

	console.error('\n──────────────────────────────────────')
	console.error('To upload to KV, run:')
	console.error('  node scripts/seed-users.js > /tmp/kv-seed.json')
	console.error('  npx wrangler kv bulk put --binding USER_CONFIG /tmp/kv-seed.json')
	console.error('──────────────────────────────────────')
}

main()

# CF Zone Dashboard

A Cloudflare Workers-powered proxy dashboard that gives sub-users access to **only** the zones and features you permit — without exposing the full Cloudflare dashboard.

## Features

- **Zone-scoped access** — users only see their assigned domains
- **DNS management** — full CRUD with search and filtering
- **Analytics** — traffic, cache, threats, visitors overview
- **Bot Management** — view and configure bot settings
- **Permission system** — granular per-user, per-zone permissions
- **No sidebar clutter** — only shows what users have access to

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Create a scoped API Token

Go to [Cloudflare Dashboard → My Profile → API Tokens](https://dash.cloudflare.com/profile/api-tokens) and create a token with:

| Permission | Access |
|---|---|
| Zone > DNS > Edit | For DNS management |
| Zone > Analytics > Read | For analytics |
| Zone > Zone > Read | For zone info |
| Zone > Bot Management > Edit | For bot config |
| Zone > Cache Purge > Purge | For cache purging |

**Scope it to the specific zone(s)** you want to expose.

### 3. Create KV namespace

```bash
npx wrangler kv namespace create USER_CONFIG
```

Copy the returned ID into `wrangler.json`.

### 4. Configure secrets

```bash
# Set the API token (never commit this)
npx wrangler secret put CF_API_TOKEN

# Set a secret for password hashing
npx wrangler secret put AUTH_SECRET
```

Update `wrangler.json` — remove `CF_API_TOKEN` and `AUTH_SECRET` from `vars` 
(they're now secrets).

### 5. Seed users

Edit `scripts/seed-users.js` with your users, zones, and permissions, then:

```bash
# Update AUTH_SECRET in the script to match your secret
node scripts/seed-users.js > /tmp/kv-seed.json
npx wrangler kv bulk put --binding USER_CONFIG /tmp/kv-seed.json
```

### 6. Deploy

```bash
npx wrangler deploy
```

## User Config Schema

Users are stored in KV with the key `user:{email}`:

```json
{
  "email": "user@example.com",
  "passwordHash": "sha256hash",
  "zones": [
    {
      "id": "zone-id-here",
      "name": "example.com",
      "permissions": [
        "dns:read",
        "dns:write",
        "analytics:read",
        "bots:read",
        "bots:write",
        "cache:purge"
      ]
    }
  ]
}
```

### Available Permissions

| Permission | Description |
|---|---|
| `dns:read` | View DNS records |
| `dns:write` | Create, edit, delete DNS records |
| `analytics:read` | View traffic and security analytics |
| `bots:read` | View bot management config |
| `bots:write` | Edit bot management config |
| `cache:purge` | Purge zone cache |

## Authentication Options

The default auth is email + password (hashed with SHA-256). For production, consider:

### Cloudflare Access (recommended)

1. Put the Worker behind [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/applications/)
2. Create an Access policy for allowed emails
3. Modify the auth middleware in `src/index.js` to read the `CF-Access-JWT-Assertion` header

### OAuth

Swap the auth routes for OAuth with Google, GitHub, etc.

## Development

```bash
npx wrangler dev
```

Visit `http://localhost:8787`

## Project Structure

```
cf-zone-dashboard/
├── src/
│   ├── index.js              # Main Worker + Hono router
│   └── api/
│       ├── cloudflare.js     # CF API proxy helper
│       ├── auth.js           # Authentication routes
│       ├── zones.js          # Zone info + cache purge
│       ├── dns.js            # DNS CRUD
│       ├── analytics.js      # Analytics (GraphQL + REST)
│       └── bots.js           # Bot management
├── public/
│   ├── index.html            # Dashboard SPA
│   ├── styles.css            # Styles
│   └── app.js                # Client-side app
├── scripts/
│   └── seed-users.js         # User seeding script
├── wrangler.json             # Wrangler config
└── package.json
```
# cf-minidash

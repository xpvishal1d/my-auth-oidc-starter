# my-auth

A PostgreSQL + Drizzle + Express OpenID Connect / OAuth 2.0 authorization server starter.

## What is included

- OIDC discovery: `/.well-known/openid-configuration`
- JWKS: `/jwks.json`
- Authorization code flow with required PKCE (`S256`)
- `/token` for authorization_code and refresh_token grants
- `/userinfo`
- `/revoke`
- `/introspect`
- login / signup UI
- Postgres sessions
- hashed auth codes and refresh tokens
- refresh token rotation
- JWT ID token + JWT access token
- client registration endpoint for internal use

## Prerequisites

- Node.js 22+
- pnpm
- Docker + Docker Compose

## Setup

1. Copy environment file:

```bash
cp .env.example .env
```

2. Start Postgres:

```bash
docker compose up -d postgres
```

3. Install dependencies:

```bash
pnpm install
```

4. Generate RSA signing keys:

```bash
pnpm keygen
```

5. Create tables in Postgres:

```bash
pnpm db:push
```

6. Start the server:

```bash
pnpm dev
```

## Discovery endpoints

- `GET http://localhost:3000/.well-known/openid-configuration`
- `GET http://localhost:3000/jwks.json`

## Register a client

Use the admin API key from `.env`.

```bash
curl -X POST http://localhost:3000/admin/clients \
  -H "x-admin-key: change-this-admin-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-service-app",
    "redirectUris": ["http://localhost:4000/callback"],
    "scopes": ["openid", "profile", "email", "offline_access"],
    "isPublic": false
  }'
```

Save the returned `client_id` and `client_secret` in `my-service-app`.

## Authorization request example

```text
GET /authorize?
  response_type=code
  &client_id=client_xxx
  &redirect_uri=http://localhost:4000/callback
  &scope=openid%20profile%20email%20offline_access
  &state=random-state
  &nonce=random-nonce
  &code_challenge=...
  &code_challenge_method=S256
```

## Token exchange example

Send the authorization code from your backend:

```bash
curl -X POST http://localhost:3000/token \
  -u client_xxx:client_secret_here \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=AUTH_CODE" \
  --data-urlencode "redirect_uri=http://localhost:4000/callback" \
  --data-urlencode "code_verifier=THE_VERIFIER"
```

## Userinfo

```bash
curl http://localhost:3000/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

## Revoke token

```bash
curl -X POST http://localhost:3000/revoke \
  -u client_xxx:client_secret_here \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=TOKEN_TO_REVOKE" \
  --data-urlencode "token_type_hint=refresh_token"
```

## Notes

This starter follows the core OIDC / OAuth 2.0 patterns, but for a public Internet-facing identity provider you should still add MFA, audit logging, stricter password policy, consent UI, key rotation, and a dedicated session store.

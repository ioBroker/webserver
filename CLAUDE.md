# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`@iobroker/webserver` is a TypeScript library (not a standalone adapter) for ioBroker adapters that provides HTTP/HTTPS server creation with automatic SSL/TLS certificate management, OAuth2 authentication, Keycloak SSO integration, and access control headers.

## Commands

```bash
npm run build        # Compile TypeScript: tsc -b tsconfig.build.json → build/
npm run lint         # ESLint on src/
```

There is no test suite configured. CI only runs linting.

## Architecture

All source lives in `src/`, compiled output goes to `build/`. The public API is exported from `src/index.ts`.

### Core Components

- **WebServer** (`src/lib/webServer.ts`) — Creates HTTP or HTTPS servers. Accepts an Express app and ioBroker adapter instance. For HTTPS, builds SNI contexts from ioBroker certificate collections with automatic reload on certificate changes.

- **CertificateManager** (`src/lib/certificateManager.ts`) — Reads/writes SSL certificate collections from ioBroker's `system.certificates` object. Supports subscribing to live certificate updates.

- **ACME challenge** (`src/lib/acmeChallenge.ts`) — Answers `GET /.well-known/acme-challenge/<token>` from the tokens the acme adapter publishes in `acme.*.info.httpChallenges`, so it no longer has to stop the adapter holding port 80. `WebServer` wraps the app with it by default (`acmeChallenge: false` opts out); `acmeChallengeMiddleware()` is the same for adapters building their own server. Only a published token is answered — anything else falls through to the app, so no application route is shadowed.

- **OAuth2Model** (`src/lib/oauth2-model.ts`) — Implements `oauth2-server`'s `RefreshTokenModel` interface. Handles password-based auth with brute-force protection (escalating delays), multiple token extraction methods (Bearer, query param, cookie, Basic Auth), and session management via ioBroker's storage API. Access tokens default to 1 hour, refresh tokens to 30 days.

- **OAuth2 Server** (`src/lib/oauth2.ts`) — Express route factory (`createOAuth2Server`) that wires up `/oauth/token`, `/sso`, `/sso-callback`, and `/logout` endpoints. Keycloak SSO uses JWT verification with JWKS. With `authorizationCode: true` it additionally wires up the authorization code flow below.

- **Authorization Code Flow** (`src/lib/oauth2-authcode.ts`) — Browser-based authorization code flow with PKCE (S256 only), plus RFC 8414 discovery, RFC 7591 dynamic client registration and RFC 7009 revocation. Deliberately **not** built on `oauth2-server`: that package is at 3.1.1 and has no PKCE support, which MCP clients require. Token issuance still goes through `OAuth2Model.generateTokens()`, so the resulting tokens are indistinguishable from password-grant tokens apart from their client/resource binding. Renders its own dependency-free login and consent pages.

- **Client Store** (`src/lib/oauth2-clients.ts`) — Persists registered OAuth2 clients as ioBroker objects under `<adapter.namespace>.oauth.clients.*` (sessions would expire). Validates redirect URIs: `https:` anywhere, `http:` only on loopback, private-use schemes for native apps.

- **Security Checker** (`src/lib/securityChecker.ts`) — `checkPublicIP()` validates a server port is not publicly accessible by querying the host's public IP and attempting a connection.

### Key Design Points

- The library expects an `ioBroker.Adapter` instance passed into constructors; types come from `@iobroker/types`.
- `express` is a **peer** concern — only `@types/express` is a devDependency, there is no runtime dependency on it. Anything needing request bodies must use `readRequestBody()` from `src/lib/utils.ts`, which falls back to reading the stream when the host adapter installed no body parser.
- Route order in `createOAuth2Server` matters: discovery/registration/revocation are registered **before** `app.use(model.authorize)` so they stay public, and `/oauth/authorize` **after** it so `req.user` is already resolved from the `access_token` cookie.
- TypeScript strict mode is enabled. Target is ES2018, module system is CommonJS.
- The package has an override for `type-is@2.0.1` due to a conflict with body-parser.
- Releases use `@alcalzone/release-script` triggered by git tags (v-prefixed semver). The release script runs `npm run build` before committing.

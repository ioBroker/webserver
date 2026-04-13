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

- **OAuth2Model** (`src/lib/oauth2-model.ts`) — Implements `oauth2-server`'s `RefreshTokenModel` interface. Handles password-based auth with brute-force protection (escalating delays), multiple token extraction methods (Bearer, query param, cookie, Basic Auth), and session management via ioBroker's storage API. Access tokens default to 1 hour, refresh tokens to 30 days.

- **OAuth2 Server** (`src/lib/oauth2.ts`) — Express route factory (`createOAuth2Server`) that wires up `/oauth/token`, `/sso`, `/sso-callback`, and `/logout` endpoints. Keycloak SSO uses JWT verification with JWKS.

- **Security Checker** (`src/lib/securityChecker.ts`) — `checkPublicIP()` validates a server port is not publicly accessible by querying the host's public IP and attempting a connection.

### Key Design Points

- The library expects an `ioBroker.Adapter` instance passed into constructors; types come from `@iobroker/types`.
- TypeScript strict mode is enabled. Target is ES2018, module system is CommonJS.
- The package has an override for `type-is@2.0.1` due to a conflict with body-parser.
- Releases use `@alcalzone/release-script` triggered by git tags (v-prefixed semver). The release script runs `npm run build` before committing.

# Webserver for ioBroker adapters

## Description

This module provides a webserver, which automatically takes care of
certificate handling using the ioBroker certificates.

## How-To

Install via `npm i @iobroker/webserver`.

Use the webserver in your ioBroker adapter as the following:

-   TypeScript:

```typescript
import { WebServer } from '@iobroker/webserver';

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

-   JavaScript:

```javascript
const { WebServer } = require('@iobroker/webserver');

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

And so you can use `CertificateManager` that is used in the WebServer already:

-   TypeScript:

```typescript
import { CertificateManager } from '@iobroker/webserver';

// Not required for server
const certManager = new CertificateManager({ adapter });

// get all collections
const collections = await certManager.getAllCollections();
```

-   JavaScript:

```javascript
const { CertificateManager } = require('@iobroker/webserver');

// Not required for server
const certManager = new CertificateManager({ adapter });

// get all collections
const collections = await certManager.getAllCollections();
```

## ACME HTTP-01 challenges

A certificate authority validates an HTTP-01 challenge by fetching `http://<domain>/.well-known/acme-challenge/<token>` on port 80. Path and port are fixed by RFC 8555, so on a host with a single public IP that request lands on whichever adapter holds port 80 - usually `web` or `admin`. The `acme` adapter used to take that port over for the duration of an order, stopping the adapter that had it.

`WebServer` answers those requests itself instead. The `acme` adapter publishes its tokens in `acme.<instance>.info.httpChallenges` and the lookup happens in front of the app, before any authentication, because the CA is anonymous:

```typescript
// Nothing to do - this is on by default
const webServer = new WebServer({ app, adapter, secure: true });

// Opt out and keep /.well-known/acme-challenge/ entirely to the app
const webServer = new WebServer({ app, adapter, secure: true, acmeChallenge: false });
```

Only a request whose token is actually published is answered here; everything else is passed on to the app untouched, so nothing the app serves on that path is shadowed.

An adapter that builds its server without `WebServer` can mount the same lookup itself, before any authentication middleware:

```typescript
import { acmeChallengeMiddleware } from '@iobroker/webserver';

app.use(acmeChallengeMiddleware(adapter));
```

`serveAcmeChallenge(adapter, req, res)` is the same thing for a plain `http.RequestListener`; it resolves to `true` when it answered the request.

## CORS / access control

`accessControl` puts the CORS headers in front of the app, so every answer carries them:

```typescript
const webServer = new WebServer({
    app,
    adapter,
    secure: true,
    accessControl: {
        // A literal origin, `*`, or a function picking one per request
        accessControlAllowOrigin: origin => origin,
        accessControlAllowMethods: 'GET,PUT,POST,DELETE,OPTIONS',
        accessControlAllowHeaders: 'Content-Type, Authorization',
        accessControlAllowCredentials: true,
        accessControlMaxAge: 600,
    },
});
```

Doing it here rather than as an Express middleware matters when the app registers routes that answer without calling `next()`: an `app.use()` added after `createOAuth2Server()` never sees `POST /oauth/token`, so that answer would go out without any CORS header. A concrete origin is sent together with `Vary: Origin`; `*` is not.

`accessControlRequestHeaders` and `accessControlRequestMethod` are deprecated - those are request headers a browser sends in a preflight and never did anything on a response. They now only fill in for `accessControlAllowHeaders` / `accessControlAllowMethods`.

## OAuth2 support
You can activate the OAuth2 support for the webserver. To do this, add the following code after the server is initialized:

```typescript
// ... initialization of the webserver        
this.webServer.app.use(cookieParser());
this.webServer.app.use(bodyParser.urlencoded({ extended: true }));
this.webServer.app.use(bodyParser.json());
this.webServer.app.use(bodyParser.text());

// Install oauth2 server (Only this line is required)
createOAuth2Server(this, { app: this.webServer.app, secure: this.config.secure, withSession: true });

// Old authentication method
this.webServer.app.use(
    session({
        secret: this.secret,
        saveUninitialized: true,
        resave: true,
        cookie: { maxAge: (parseInt(this.config.ttl as string, 10) || 3600) * 1000, httpOnly: false }, // default TTL
        // @ts-expect-error missing typing
        store: this.store!,
    }),
);
```

If you want to completely disable old authentication method, the code should looks like:
```typescript
// ... initialization of the webserver        
this.webServer.app.use(cookieParser());
this.webServer.app.use(bodyParser.urlencoded({ extended: true }));
this.webServer.app.use(bodyParser.json());
this.webServer.app.use(bodyParser.text());

// Install oauth2 server (Only this line is required)
createOAuth2Server(this, { app: this.webServer.app, secure: this.config.secure });
```

Login with OAuth2 is available under `/oauth/token` URL:

```http
POST /oauth/token HTTP/1.1
Host: IP:PORT
Content-Type: application/x-www-form-urlencoded
Data: grant_type=password&username=<user>&password=<password>&client_id=ioBroker&stayloggedin=<false/true>
```
`stayloggedin=true` means that the token will be stored in the browser and will be used for the next requests and is optional.

The answer is like:
```json
{
    "access_token": "21f89e3eee32d3af08a71c1cc44ec72e0e3014a9",
    "expires_in": 3600,
    "refresh_token": "66d35faa5d53ca8242cfe57367210e76b7ffded7",
    "refresh_token_expires_in": "600000",
    "token_type": "Bearer"
}
```          

Refresh token is available under `/oauth/token` URL:

```http
POST /oauth/token HTTP/1.1
Host: IP:PORT
Content-Type: application/x-www-form-urlencoded
Data: grant_type=refresh_token&refresh_token=<REFRESH_TOKEN>&client_id=ioBroker&stayloggedin=<false/true>
```

The answer is the same as for the login but with new tokens.

## Authorization code flow with PKCE

The password grant above requires the client to handle the user's credentials. Clients that run
outside your control — MCP clients such as Claude Desktop, or any "connect your account" integration —
must not do that. For them the webserver can additionally offer the browser-based **authorization
code flow with PKCE** (RFC 7636), including dynamic client registration (RFC 7591), authorization
server metadata (RFC 8414), resource indicators (RFC 8707) and token revocation (RFC 7009).

It is **opt-in**, because it exposes a browser-facing login page and — unless disabled — an open
registration endpoint:

```typescript
createOAuth2Server(this, {
    app: this.webServer.app,
    secure: this.config.secure,
    // Enable the browser-based flow
    authorizationCode: true,
    // Externally reachable base URL. REQUIRED behind a reverse proxy: the URLs published in the
    // discovery document must be the ones the client can actually reach.
    baseUrl: 'https://iobroker.example.com',
    // Optional: pin the name shown on the login and consent pages
    productName: 'ioBroker',
    // Optional: require clients to be registered by hand instead of via RFC 7591
    dynamicClientRegistration: false,
    // Optional: how many clients to keep before the oldest dynamic ones are pruned (default 100)
    maxClients: 100,
});
```

This adds the following endpoints:

| Endpoint                                      | Purpose                                                        |
|-----------------------------------------------|----------------------------------------------------------------|
| `GET /.well-known/oauth-authorization-server` | Discovery document (RFC 8414)                                  |
| `POST /oauth/register`                        | Dynamic client registration (RFC 7591), can be disabled        |
| `GET /oauth/authorize`                        | Login and consent page                                         |
| `POST /oauth/authorize`                       | Login and consent submission                                   |
| `POST /oauth/token`                           | Also accepts `grant_type=authorization_code`                   |
| `POST /oauth/revoke`                          | Token revocation (RFC 7009)                                    |

Notes:

- **PKCE is mandatory.** Only `code_challenge_method=S256` is accepted; there are no client secrets,
  every client is a public client.
- **Only registered redirect URIs are accepted**, compared byte-for-byte. Plain `http:` is allowed
  only for loopback addresses (RFC 8252 §7.3), so native apps can use an ephemeral local port.
- **Users who are already signed in** (an `access_token` cookie from the web UI) only see the consent
  step, not another login form.
- **`resource` (RFC 8707) is bound to the token.** `OAuth2Model.getTokenInfo(accessToken)` returns
  the stored record including `aud` and `clientId`, so a resource server can reject tokens that were
  issued for something else. The binding survives a refresh.
- **HTTPS is required** for anything but localhost — the flow runs through the user's browser, and
  clients refuse plain `http:` for remote hosts.
- Registered clients are stored as ioBroker objects under `<adapter.namespace>.oauth.clients.*`.

Client registration:

```http
POST /oauth/register HTTP/1.1
Content-Type: application/json

{ "client_name": "Claude", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"] }
```

Token exchange:

```http
POST /oauth/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<CODE>&code_verifier=<VERIFIER>&client_id=<CLIENT_ID>&redirect_uri=<REDIRECT_URI>
```

## Changelog

<!--
  Placeholder for the next version (at the beginning of the line):
  ### **WORK IN PROGRESS**
-->
### **WORK IN PROGRESS**
- (@GermanBluefox) The `access_token` cookie of a "stay logged in" login gets its lifetime as `Max-Age` (relative to the browser clock) instead of `Expires` (an absolute date from the server clock): a server with a wrong time handed out cookies the browser dropped at once

### 3.0.1 (2026-08-26)
- (@GermanBluefox) HTTPS servers built from a certificate collection now also send the issuing chain from `collection.chain`. Only the leaf was sent before, so clients that do not already know the intermediate - `curl` and most non-browser HTTP clients - failed with `unable to get local issuer certificate`
- (@GermanBluefox) `accessControl`: `accessControlAllowOrigin` now also accepts a function, so the allowed origin can be picked per request (`origin => origin` reflects it back)
- (@GermanBluefox) `accessControl`: added `accessControlMaxAge`, and a concrete allowed origin is now sent together with `Vary: Origin`
- (@GermanBluefox) `accessControl`: `accessControlRequestHeaders` and `accessControlRequestMethod` are deprecated. They are request headers a browser sends in a preflight and had no effect as response headers; they now serve as a fallback for `accessControlAllowHeaders` / `accessControlAllowMethods`

### 3.0.0 (2026-08-26)
- (@GermanBluefox) Fixed the OAuth2 consent page dropping the authorization response in Chromium and WebKit: `form-action` also applies to the redirect that follows the form POST, so the client's callback origin is now part of the policy. Clicking "Allow" appeared to do nothing and a second click reported "Request expired"
- (@GermanBluefox) The login and consent forms now post to a relative URL, so the flow also works when the server is reverse-proxied under a path prefix
- (@GermanBluefox) An unexpected error in an OAuth2 endpoint no longer escapes as an unhandled rejection (which terminates the host adapter); it is logged and answered with an error page
- (@GermanBluefox) `WebServer` now answers ACME HTTP-01 challenges published by the acme adapter, so it no longer has to be stopped to free port 80 (opt out via `acmeChallenge: false`)
- (@GermanBluefox) Exported `acmeChallengeMiddleware` and `serveAcmeChallenge` for adapters that build their server themselves
- (@GermanBluefox) **BREAKING:** Updated `jwks-rsa` to 4.x. It depends on the ESM-only jose 6, so the minimal Node.js version is now 20.19 (or 22.12 / 23+)

### 2.0.1 (2026-08-04)
- (@GermanBluefox) Added the OAuth2 authorization code flow with PKCE, dynamic client registration, authorization server metadata and token revocation (opt-in via `authorizationCode: true`)
- (@GermanBluefox) Tokens can now be bound to a client and a resource (RFC 8707); the binding survives a refresh
- (@GermanBluefox) `/oauth/token` no longer requires the host adapter to install a body parser

### 1.4.0 (2026-04-13)
- (@GermanBluefox) Fixed possible errors
- (@GermanBluefox) Updated packages

### 1.3.3 (2026-02-12)
- (@GermanBluefox) Added missing types for the acme adapter

### 1.3.1 (2025-06-17)
- (@foxriver76) Implemented (for now - inofficial) Keycloack SSO support

### 1.2.8 (2025-04-29)

- (@GermanBluefox) Corrected time to live for the access token

### 1.2.7 (2025-04-21)

- (@GermanBluefox) Corrected a problem with authentication, as type-is was too old.

### 1.2.6 (2025-04-01)

- (@GermanBluefox) Changed the order of authentications. Basic authentication will be checked as the last one.
- (@GermanBluefox) Added the setting to disable basic authentication

### 1.2.4 (2025-03-25)
  
- (@GermanBluefox) Added the possibility to give tokens for internal use (like node-red)

### 1.2.0 (2025-03-05)

-   (@GermanBluefox) Added the log output for invalid password in OAuth2
-   (@GermanBluefox) A minimal Node.js version is 16 (Not breaking, as no one uses node 14)
-   (@GermanBluefox) Updated TypeScript to 5.8

### 1.1.7 (2025-02-27)

-   (@GermanBluefox) Added support for OAuth2 authentication with brute force

### 1.0.8 (2025-02-07)

-   (@GermanBluefox) Updated packages and typing

### 1.0.6 (2024-09-14)

-   (@GermanBluefox) Added access control options for server
-   (@GermanBluefox) Used `@iobroker/eslint-config` for linting

### 1.0.3 (2023-10-16)

-   (@GermanBluefox) Extend the security checker with the pattern detection and custom URL

### 1.0.1 (2023-10-11)

-   (@GermanBluefox) Changed the error text of the security checker

### 1.0.0 (2023-10-11)

-   (@GermanBluefox) added the security checker

### 0.3.7 (2023-09-24)

-   (raintonr) Fix contexts for SNICallback ([#3](https://github.com/ioBroker/webserver/issues/3)).

### 0.3.6 (2023-07-07)

-   (@GermanBluefox) Update packages

### 0.3.4 (2023-03-27)

-   (@GermanBluefox) Corrected small error with CA certificate

### 0.3.3 (2023-03-24)

-   (@GermanBluefox) Added check of the cert files

### 0.3.1 (2023-03-20)

-   (@GermanBluefox) Corrected error with `getCertificatesAsync`

### 0.3.0 (2023-03-20)

-   (@GermanBluefox) Added support for user-configured certificates for fallback

### 0.2.1 (2023-03-20)

-   (@GermanBluefox) Rename `Webserver` to `WebServer`

### 0.1.0 (2023-03-13)

-   (foxriver76) initial release based on https://github.com/ioBroker/ioBroker.js-controller/pull/2104 by @raintonr

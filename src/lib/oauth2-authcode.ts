import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { Express, Request, Response } from 'express';

import type { OAuth2Model } from './oauth2-model';
import { ClientRegistrationError, type OAuth2ClientStore } from './oauth2-clients';
import { oauthTokenToResponse, readRequestBody } from './utils';

/** How long an authorization code stays valid. Codes are single-use, so this only needs to cover the redirect. */
const CODE_TTL_SEC = 60;
/** How long the user has to complete login and consent. */
const REQUEST_TTL_SEC = 600;

/** Session key prefix for pending authorization requests. */
const REQUEST_PREFIX = 'oauthreq:';
/** Session key prefix for issued authorization codes. */
const CODE_PREFIX = 'oauthcode:';

/**
 * An authorization request that passed validation and is waiting for the user to log in and consent.
 * Kept server-side so none of the validated parameters can be tampered with between the two steps.
 */
interface PendingAuthRequest {
    clientId: string;
    clientName: string;
    redirectUri: string;
    state?: string;
    codeChallenge: string;
    scope?: string;
    resource?: string;
    /** Set once the request is tied to an authenticated ioBroker user. */
    user?: string;
}

/** An issued authorization code, redeemable exactly once at the token endpoint. */
interface StoredAuthCode {
    clientId: string;
    redirectUri: string;
    codeChallenge: string;
    user: string;
    scope?: string;
    resource?: string;
}

export interface AuthorizationCodeFlowOptions {
    /** The Express app the endpoints are registered on. */
    app: Express;
    /** The OAuth2 model providing user verification and token issuance. */
    model: OAuth2Model;
    /** Storage for registered clients. */
    clientStore: OAuth2ClientStore;
    /**
     * Externally reachable base URL of this server, without a trailing slash, e.g.
     * `https://iobroker.example.com`. Required behind a reverse proxy: the URLs published in the
     * discovery document must be the ones the client can actually reach. When omitted, the URL is
     * derived from the request, which is only correct for directly exposed servers.
     */
    baseUrl?: string | ((req: Request) => string);
    /** Allow clients to register themselves via RFC 7591. Enabled by default. */
    dynamicClientRegistration?: boolean;
    /** Name shown on the login and consent pages. Defaults to "ioBroker". */
    productName?: string;
}

/**
 * Escape a string for inclusion in HTML text or a double-quoted attribute.
 *
 * @param text The raw text
 */
function escapeHtml(text: string): string {
    return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

/**
 * Read a query parameter that may legitimately appear more than once (e.g. `resource`).
 * Only the first occurrence is used; anything that is not a string is ignored.
 *
 * @param value The raw value taken from `req.query`
 */
function firstValue(value: unknown): string | undefined {
    if (typeof value === 'string') {
        return value;
    }
    if (Array.isArray(value) && typeof value[0] === 'string') {
        return value[0];
    }
    return undefined;
}

/**
 * Build the CSP `form-action` source list that lets the browser follow the authorization response.
 *
 * The consent form posts back to us, but the answer to that POST is a redirect to the client's
 * callback. Chromium and WebKit apply `form-action` to that redirect as well (Firefox does not), so
 * a bare `'self'` makes them drop the response: the code is issued and then thrown away, and the
 * user is left on the consent page. The redirect URI was validated against the client's registration
 * before the page was rendered, so naming its origin here does not widen what the form can reach.
 *
 * @param redirectUri The verified redirect URI of the pending request
 */
function formActionSources(redirectUri: string): string {
    let parsed: URL;
    try {
        parsed = new URL(redirectUri);
    } catch {
        // Unparseable URIs are rejected at registration time, so this cannot happen for a pending
        // request — fall back to the strictest policy rather than guess.
        return "'self'";
    }
    // Native apps get their callback on a private-use scheme (`myapp://cb`), for which there is no
    // origin; those are allowed by scheme instead.
    const client = parsed.origin && parsed.origin !== 'null' ? parsed.origin : parsed.protocol;
    return `'self' ${client}`;
}

/**
 * Compare two strings without leaking their contents through timing differences.
 *
 * @param a First value
 * @param b Second value
 */
function safeEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'utf8');
    const bufB = Buffer.from(b, 'utf8');
    if (bufA.length !== bufB.length) {
        return false;
    }
    return timingSafeEqual(bufA, bufB);
}

/**
 * Implements the OAuth2 authorization code flow with PKCE (RFC 7636), dynamic client registration
 * (RFC 7591) and authorization server metadata (RFC 8414) on top of an existing {@link OAuth2Model}.
 *
 * This is deliberately not built on `oauth2-server`: that package (3.x) has no PKCE support, and
 * MCP clients require it. Token issuance still goes through the model, so access and refresh tokens
 * are indistinguishable from those issued by the password grant.
 */
export class AuthorizationCodeFlow {
    private readonly adapter: ioBroker.Adapter;
    private readonly model: OAuth2Model;
    private readonly clientStore: OAuth2ClientStore;
    private readonly options: AuthorizationCodeFlowOptions;
    private readonly productName: string;

    /**
     * @param adapter ioBroker adapter used for session storage and logging
     * @param options Flow options
     */
    constructor(adapter: ioBroker.Adapter, options: AuthorizationCodeFlowOptions) {
        this.adapter = adapter;
        this.model = options.model;
        this.clientStore = options.clientStore;
        this.options = options;
        this.productName = options.productName || 'ioBroker';
    }

    /**
     * Register the endpoints that must be reachable without authentication: the discovery document
     * and — when enabled — dynamic client registration.
     *
     * Must be called *before* the app-wide `authorize` middleware so these routes stay public.
     */
    registerPublicRoutes(): void {
        const app = this.options.app;

        app.get('/.well-known/oauth-authorization-server', (req: Request, res: Response): void => {
            const baseUrl = this.getBaseUrl(req);
            res.set('Cache-Control', 'public, max-age=300');
            res.json({
                issuer: baseUrl,
                authorization_endpoint: `${baseUrl}/oauth/authorize`,
                token_endpoint: `${baseUrl}/oauth/token`,
                registration_endpoint:
                    this.options.dynamicClientRegistration === false ? undefined : `${baseUrl}/oauth/register`,
                revocation_endpoint: `${baseUrl}/oauth/revoke`,
                response_types_supported: ['code'],
                grant_types_supported: ['authorization_code', 'refresh_token'],
                code_challenge_methods_supported: ['S256'],
                token_endpoint_auth_methods_supported: ['none'],
            });
        });

        if (this.options.dynamicClientRegistration !== false) {
            app.post('/oauth/register', (req: Request, res: Response): void => {
                this.guard(res, this.handleRegister(req, res), true);
            });
        }

        app.post('/oauth/revoke', (req: Request, res: Response): void => {
            this.guard(res, this.handleRevoke(req, res), true);
        });
    }

    /**
     * Handle `POST /oauth/revoke` (RFC 7009), so a client can drop its tokens when the user
     * disconnects it. Per the RFC an unknown token is not an error — the caller's goal is met either
     * way, and reporting it would let anyone probe which tokens exist.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    private async handleRevoke(req: Request, res: Response): Promise<void> {
        res.set('Cache-Control', 'no-store');

        let body: Record<string, any>;
        try {
            body = await readRequestBody(req);
        } catch {
            res.status(400).json({ error: 'invalid_request' });
            return;
        }

        const value = typeof body.token === 'string' ? body.token : '';
        if (!value) {
            res.status(400).json({ error: 'invalid_request', error_description: 'token is required' });
            return;
        }

        // The hint is only an optimisation, so it is ignored: `revokeTokenPair` accepts either kind
        // and drops the access and refresh token together (RFC 7009 §2.1).
        const revoked = await this.model.revokeTokenPair(value);
        if (revoked) {
            this.adapter.log.debug('Revoked an OAuth2 token pair on client request');
        }

        res.status(200).end();
    }

    /**
     * Register the endpoints that need to know whether the browser is already logged in.
     *
     * Must be called *after* the app-wide `authorize` middleware, which populates `req.user` from an
     * `access_token` cookie — otherwise an already logged-in user would be asked for the password again.
     */
    registerAuthorizeRoutes(): void {
        const app = this.options.app;

        app.get('/oauth/authorize', (req: Request, res: Response): void => {
            this.guard(res, this.handleAuthorizeStart(req, res), false);
        });

        app.post('/oauth/authorize', (req: Request, res: Response): void => {
            this.guard(res, this.handleAuthorizeSubmit(req, res), false);
        });
    }

    /**
     * Determine the externally reachable base URL. Behind a reverse proxy the request-derived value
     * is wrong unless the host app enabled `trust proxy`, which is why {@link AuthorizationCodeFlowOptions.baseUrl}
     * exists.
     *
     * @param req The incoming request
     */
    private getBaseUrl(req: Request): string {
        const configured =
            typeof this.options.baseUrl === 'function' ? this.options.baseUrl(req) : this.options.baseUrl;
        if (configured) {
            return configured.replace(/\/+$/, '');
        }
        return `${req.protocol}://${req.get('host') || 'localhost'}`;
    }

    // ----- Dynamic client registration (RFC 7591) -----

    /**
     * Handle `POST /oauth/register`.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    private async handleRegister(req: Request, res: Response): Promise<void> {
        res.set('Cache-Control', 'no-store');

        let body: Record<string, any>;
        try {
            body = await readRequestBody(req);
        } catch (e) {
            res.status(400).json({ error: 'invalid_client_metadata', error_description: (e as Error).message });
            return;
        }

        try {
            const client = await this.clientStore.register(body, { dynamic: true });
            this.adapter.log.info(
                `Registered OAuth2 client "${client.client_name || client.client_id}" (${client.client_id})`,
            );
            res.status(201).json({
                client_id: client.client_id,
                client_id_issued_at: client.client_id_issued_at,
                client_name: client.client_name,
                redirect_uris: client.redirect_uris,
                grant_types: client.grant_types,
                response_types: client.response_types,
                token_endpoint_auth_method: client.token_endpoint_auth_method,
                scope: client.scope,
            });
        } catch (e) {
            if (e instanceof ClientRegistrationError) {
                this.adapter.log.warn(`Rejected OAuth2 client registration: ${e.message}`);
                res.status(400).json({ error: e.code, error_description: e.message });
                return;
            }
            this.adapter.log.error(`OAuth2 client registration failed: ${(e as Error).message}`);
            res.status(500).json({ error: 'invalid_client_metadata', error_description: (e as Error).message });
        }
    }

    // ----- Authorization endpoint -----

    /**
     * Handle `GET /oauth/authorize`: validate the request, then show either the login form or the
     * consent page.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    private async handleAuthorizeStart(req: Request, res: Response): Promise<void> {
        const query = req.query as Record<string, unknown>;

        const clientId = firstValue(query.client_id);
        if (!clientId) {
            this.sendErrorPage(res, 400, 'Missing client_id', 'The authorization request has no client_id.');
            return;
        }

        const client = await this.clientStore.get(clientId);
        if (!client) {
            this.sendErrorPage(
                res,
                400,
                'Unknown client',
                'This application is not registered with this ioBroker installation.',
            );
            return;
        }

        // Resolving the redirect URI must happen before any error can be reported back to the client:
        // redirecting to an unvalidated URI would turn this endpoint into an open redirector.
        const requestedRedirect = firstValue(query.redirect_uri);
        let redirectUri: string;
        if (requestedRedirect) {
            if (!client.redirect_uris.includes(requestedRedirect)) {
                this.sendErrorPage(
                    res,
                    400,
                    'Invalid redirect_uri',
                    'The requested callback address is not registered for this application.',
                );
                return;
            }
            redirectUri = requestedRedirect;
        } else if (client.redirect_uris.length === 1) {
            redirectUri = client.redirect_uris[0];
        } else {
            this.sendErrorPage(
                res,
                400,
                'Missing redirect_uri',
                'This application has several registered callback addresses, so the request must name one.',
            );
            return;
        }

        const state = firstValue(query.state);

        const responseType = firstValue(query.response_type);
        if (responseType !== 'code') {
            this.redirectWithError(res, redirectUri, 'unsupported_response_type', 'only "code" is supported', state);
            return;
        }

        const codeChallenge = firstValue(query.code_challenge);
        const codeChallengeMethod = firstValue(query.code_challenge_method);
        if (!codeChallenge) {
            this.redirectWithError(res, redirectUri, 'invalid_request', 'code_challenge is required (PKCE)', state);
            return;
        }
        if (codeChallengeMethod !== 'S256') {
            this.redirectWithError(res, redirectUri, 'invalid_request', 'code_challenge_method must be S256', state);
            return;
        }

        const pending: PendingAuthRequest = {
            clientId: client.client_id,
            clientName: client.client_name || client.client_id,
            redirectUri,
            state,
            codeChallenge,
            scope: firstValue(query.scope),
            resource: firstValue(query.resource),
            user: (req as Request & { user?: string }).user,
        };

        const requestId = randomBytes(32).toString('base64url');
        await this.setSession(`${REQUEST_PREFIX}${requestId}`, REQUEST_TTL_SEC, pending);

        this.sendAuthorizePage(res, requestId, pending);
    }

    /**
     * Handle `POST /oauth/authorize`: the login form submission, the consent decision, or both in
     * sequence.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    private async handleAuthorizeSubmit(req: Request, res: Response): Promise<void> {
        let body: Record<string, any>;
        try {
            body = await readRequestBody(req);
        } catch (e) {
            this.sendErrorPage(res, 400, 'Bad request', (e as Error).message);
            return;
        }

        const requestId = typeof body.request_id === 'string' ? body.request_id : '';
        const pending = requestId ? await this.getSession<PendingAuthRequest>(`${REQUEST_PREFIX}${requestId}`) : null;
        if (!pending) {
            this.sendErrorPage(
                res,
                400,
                'Request expired',
                'This authorization request is no longer valid. Please start again from the application.',
            );
            return;
        }

        const action = typeof body.action === 'string' ? body.action : '';

        if (action === 'deny') {
            await this.destroySession(`${REQUEST_PREFIX}${requestId}`);
            this.redirectWithError(
                res,
                pending.redirectUri,
                'access_denied',
                'the user denied the request',
                pending.state,
            );
            return;
        }

        if (action === 'login') {
            const username = typeof body.username === 'string' ? body.username : '';
            const password = typeof body.password === 'string' ? body.password : '';
            const user = await this.model.getUser(username, password);
            if (!user) {
                // Keep the pending request alive so the user can retry without restarting the flow.
                this.sendAuthorizePage(res, requestId, pending, 'Wrong user name or password.');
                return;
            }
            pending.user = user.id as string;
            await this.setSession(`${REQUEST_PREFIX}${requestId}`, REQUEST_TTL_SEC, pending);
            // Logging in is not consenting — show the consent step now that we know who is asking.
            this.sendAuthorizePage(res, requestId, pending);
            return;
        }

        if (action !== 'allow') {
            this.sendAuthorizePage(res, requestId, pending);
            return;
        }

        if (!pending.user) {
            this.sendAuthorizePage(res, requestId, pending, 'Please log in first.');
            return;
        }

        // Consent given: issue the code and hand control back to the client.
        await this.destroySession(`${REQUEST_PREFIX}${requestId}`);

        const code = randomBytes(32).toString('base64url');
        const stored: StoredAuthCode = {
            clientId: pending.clientId,
            redirectUri: pending.redirectUri,
            codeChallenge: pending.codeChallenge,
            user: pending.user,
            scope: pending.scope,
            resource: pending.resource,
        };
        await this.setSession(`${CODE_PREFIX}${code}`, CODE_TTL_SEC, stored);

        this.adapter.log.info(
            `Issued OAuth2 authorization code for client "${pending.clientName}" and user "${pending.user}"`,
        );

        const target = new URL(pending.redirectUri);
        target.searchParams.set('code', code);
        if (pending.state !== undefined) {
            target.searchParams.set('state', pending.state);
        }
        res.redirect(target.toString());
    }

    // ----- Token endpoint (authorization_code grant) -----

    /**
     * Redeem an authorization code for tokens. Called from the `/oauth/token` route when the request
     * carries `grant_type=authorization_code`.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    async handleTokenRequest(req: Request, res: Response): Promise<void> {
        res.set('Cache-Control', 'no-store');
        res.set('Pragma', 'no-cache');

        let body: Record<string, any>;
        try {
            body = await readRequestBody(req);
        } catch (e) {
            res.status(400).json({ error: 'invalid_request', error_description: (e as Error).message });
            return;
        }

        const code = typeof body.code === 'string' ? body.code : '';
        const codeVerifier = typeof body.code_verifier === 'string' ? body.code_verifier : '';
        const redirectUri = typeof body.redirect_uri === 'string' ? body.redirect_uri : '';
        const clientId = typeof body.client_id === 'string' ? body.client_id : '';

        if (!code) {
            res.status(400).json({ error: 'invalid_request', error_description: 'code is required' });
            return;
        }
        if (!codeVerifier) {
            res.status(400).json({ error: 'invalid_request', error_description: 'code_verifier is required (PKCE)' });
            return;
        }
        if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(codeVerifier)) {
            res.status(400).json({ error: 'invalid_grant', error_description: 'malformed code_verifier' });
            return;
        }

        const stored = await this.getSession<StoredAuthCode>(`${CODE_PREFIX}${code}`);
        // Authorization codes are single-use: drop it before doing anything else, so a replayed or
        // concurrently redeemed code cannot yield a second token.
        await this.destroySession(`${CODE_PREFIX}${code}`);

        if (!stored) {
            res.status(400).json({
                error: 'invalid_grant',
                error_description: 'unknown or expired authorization code',
            });
            return;
        }

        if (clientId && clientId !== stored.clientId) {
            res.status(400).json({ error: 'invalid_grant', error_description: 'client_id does not match the code' });
            return;
        }
        if (redirectUri && redirectUri !== stored.redirectUri) {
            res.status(400).json({ error: 'invalid_grant', error_description: 'redirect_uri does not match the code' });
            return;
        }

        const challenge = createHash('sha256').update(codeVerifier).digest('base64url');
        if (!safeEqual(challenge, stored.codeChallenge)) {
            this.adapter.log.warn(
                `Rejected OAuth2 token request: PKCE verification failed for client ${stored.clientId}`,
            );
            res.status(400).json({ error: 'invalid_grant', error_description: 'PKCE verification failed' });
            return;
        }

        // RFC 8707: when the client repeats the resource here it must be the one it was authorized for.
        const requestedResource = typeof body.resource === 'string' ? body.resource : undefined;
        if (requestedResource && stored.resource && requestedResource !== stored.resource) {
            res.status(400).json({ error: 'invalid_target', error_description: 'resource does not match the code' });
            return;
        }

        const token = await this.model.generateTokens(stored.user, {
            clientId: stored.clientId,
            aud: stored.resource,
            scope: stored.scope,
        });

        this.adapter.log.debug(`Issued OAuth2 tokens for user "${stored.user}" via authorization code grant`);

        res.json({ ...oauthTokenToResponse(token), scope: stored.scope });
    }

    // ----- Session helpers -----

    /**
     * @param id Session key
     * @param ttl Time to live in seconds
     * @param data Payload to store
     */
    private setSession(id: string, ttl: number, data: Record<string, any>): Promise<void> {
        return new Promise((resolve, reject) =>
            this.adapter.setSession(id, ttl, data, err => (err ? reject(err) : resolve())),
        );
    }

    /**
     * @param id Session key
     */
    private getSession<T>(id: string): Promise<T | null> {
        return new Promise(resolve => this.adapter.getSession(id, (data: unknown) => resolve((data as T) || null)));
    }

    /**
     * @param id Session key
     */
    private async destroySession(id: string): Promise<void> {
        try {
            await this.adapter.destroySession(id);
        } catch {
            // A code that is already gone is exactly the state we wanted.
        }
    }

    // ----- Rendering -----

    /**
     * Redirect back to the client with an OAuth2 error (RFC 6749 §4.1.2.1). Only ever called with a
     * redirect URI that was verified against the client's registration.
     *
     * @param res The response to write to
     * @param redirectUri Verified redirect URI
     * @param error OAuth2 error code
     * @param description Human-readable detail
     * @param state The client's `state` value, echoed back unchanged
     */
    private redirectWithError(
        res: Response,
        redirectUri: string,
        error: string,
        description: string,
        state?: string,
    ): void {
        const target = new URL(redirectUri);
        target.searchParams.set('error', error);
        target.searchParams.set('error_description', description);
        if (state !== undefined) {
            target.searchParams.set('state', state);
        }
        res.redirect(target.toString());
    }

    /**
     * Answer an unexpected rejection from a route handler instead of letting it escape.
     *
     * These handlers are started from synchronous Express callbacks, so a rejection nobody catches
     * is an unhandled rejection — which terminates the host adapter's process on current Node
     * versions, and leaves the request hanging either way.
     *
     * @param res The response to write to
     * @param handler The already started handler
     * @param json Whether this endpoint answers with JSON rather than an HTML page
     */
    private guard(res: Response, handler: Promise<void>, json: boolean): void {
        handler.catch((e: Error) => {
            this.adapter.log.error(`OAuth2 request failed: ${e.message}`);
            if (res.headersSent) {
                return;
            }
            if (json) {
                res.status(500).json({ error: 'server_error' });
            } else {
                this.sendErrorPage(
                    res,
                    500,
                    'Server error',
                    'This request could not be processed. Please start again from the application.',
                );
            }
        });
    }

    /**
     * Render the login form or the consent page, depending on whether the request already knows its user.
     *
     * @param res The response to write to
     * @param requestId Identifier of the pending request; doubles as CSRF token
     * @param pending The pending authorization request
     * @param error Optional error message to show above the form
     */
    private sendAuthorizePage(res: Response, requestId: string, pending: PendingAuthRequest, error?: string): void {
        const clientName = escapeHtml(pending.clientName);
        const errorBlock = error ? `<p class="error">${escapeHtml(error)}</p>` : '';

        const body = pending.user
            ? `<h1>Allow access?</h1>
        <p><strong>${clientName}</strong> is asking for access to your ${escapeHtml(this.productName)} installation.</p>
        <dl>
            <dt>Signed in as</dt><dd>${escapeHtml(pending.user)}</dd>
            ${pending.resource ? `<dt>Resource</dt><dd>${escapeHtml(pending.resource)}</dd>` : ''}
        </dl>
        <p class="hint">The application will be able to act with the permissions of this user.</p>
        ${errorBlock}
        <form method="post" action="authorize">
            <input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
            <div class="buttons">
                <button type="submit" name="action" value="deny" class="secondary">Deny</button>
                <button type="submit" name="action" value="allow" class="primary">Allow</button>
            </div>
        </form>`
            : `<h1>Sign in</h1>
        <p><strong>${clientName}</strong> is asking for access to your ${escapeHtml(this.productName)} installation.</p>
        ${errorBlock}
        <form method="post" action="authorize">
            <input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
            <label for="username">User name</label>
            <input type="text" id="username" name="username" autocomplete="username" autofocus required>
            <label for="password">Password</label>
            <input type="password" id="password" name="password" autocomplete="current-password" required>
            <div class="buttons">
                <button type="submit" name="action" value="deny" class="secondary">Cancel</button>
                <button type="submit" name="action" value="login" class="primary">Sign in</button>
            </div>
        </form>`;

        res.set('Cache-Control', 'no-store');
        res.set(
            'Content-Security-Policy',
            `default-src 'none'; style-src 'unsafe-inline'; form-action ${formActionSources(pending.redirectUri)}`,
        );
        res.status(200).send(this.htmlPage('Authorize', body));
    }

    /**
     * Render a terminal error page for problems that must not be reported back to the client
     * application (unknown client, bad redirect URI, expired request).
     *
     * @param res The response to write to
     * @param status HTTP status code
     * @param title Short headline
     * @param message Explanation shown to the user
     */
    private sendErrorPage(res: Response, status: number, title: string, message: string): void {
        res.set('Cache-Control', 'no-store');
        res.status(status).send(this.htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`));
    }

    /**
     * Wrap page content in the shared, dependency-free HTML shell.
     *
     * @param title Document title
     * @param content Already escaped HTML body
     */
    private htmlPage(title: string, content: string): string {
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} – ${escapeHtml(this.productName)}</title>
<style>
:root { color-scheme: light dark; --bg: #f5f5f5; --card: #fff; --fg: #202020; --muted: #666; --line: #d8d8d8; --accent: #3399cc; }
@media (prefers-color-scheme: dark) {
  :root { --bg: #1a1a1a; --card: #242424; --fg: #e8e8e8; --muted: #9a9a9a; --line: #3a3a3a; }
}
* { box-sizing: border-box; }
body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 24px;
       background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
main { width: 100%; max-width: 420px; background: var(--card); border: 1px solid var(--line); border-radius: 10px; padding: 28px; }
h1 { margin: 0 0 16px; font-size: 20px; font-weight: 600; }
p { margin: 0 0 16px; }
.hint, dt { color: var(--muted); font-size: 13px; }
dl { margin: 0 0 16px; padding: 12px; background: var(--bg); border-radius: 6px; }
dt { margin-bottom: 2px; }
dd { margin: 0 0 8px; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px; word-break: break-all; }
dd:last-child { margin-bottom: 0; }
.error { padding: 10px 12px; border-radius: 6px; background: #c0392b1a; color: #c0392b; font-size: 14px; }
label { display: block; margin-bottom: 4px; font-size: 13px; color: var(--muted); }
input[type=text], input[type=password] { width: 100%; margin-bottom: 14px; padding: 9px 11px; border: 1px solid var(--line);
       border-radius: 6px; background: var(--bg); color: var(--fg); font-size: 15px; }
input:focus { outline: 2px solid var(--accent); outline-offset: -1px; }
.buttons { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
button { padding: 9px 18px; border-radius: 6px; border: 1px solid var(--line); font-size: 14px; cursor: pointer; }
button.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
button.secondary { background: transparent; color: var(--fg); }
</style>
</head>
<body><main>${content}</main></body>
</html>`;
    }
}

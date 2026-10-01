import { createHash, randomBytes } from 'node:crypto';

import type { Request, Response, Express, NextFunction } from 'express';
import OAuth2Server, { Request as OAuthRequest, Response as OAuthResponse, type Token } from 'oauth2-server';
import { verify, type JwtHeader, type SigningKeyCallback, type JwtPayload } from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';

import { OAuth2Model } from './oauth2-model';
import { AuthorizationCodeFlow } from './oauth2-authcode';
import { OAuth2ClientStore } from './oauth2-clients';
import { oauthTokenToResponse, readRequestBody } from './utils';

export interface CookieOptions {
    /** Convenient option for setting the expiry time relative to the current time in **milliseconds**. */
    maxAge?: number | undefined;
    /** Indicates if the cookie should be signed. */
    signed?: boolean | undefined;
    /** Expiry date of the cookie in GMT. If not specified or set to 0, create a session cookie. */
    expires?: Date | undefined;
    /** Flags the cookie to be accessible only by the web server. */
    httpOnly?: boolean | undefined;
    /** Path for the cookie. Defaults to “/”. */
    path?: string | undefined;
    /** Domain name for the cookie. Defaults to the domain name of the app. */
    domain?: string | undefined;
    /** Marks the cookie to be used with HTTPS only. */
    secure?: boolean | undefined;
    /** A synchronous function used for cookie value encoding. Defaults to encodeURIComponent. */
    encode?: ((val: string) => string) | undefined;
    /** Value of the “SameSite” Set-Cookie attribute. */
    sameSite?: boolean | 'lax' | 'strict' | 'none' | undefined;
    /** Value of the “Priority” Set-Cookie attribute. */
    priority?: 'low' | 'medium' | 'high';
    /** Marks the cookie to use partitioned storage. */
    partitioned?: boolean | undefined;
}

/** Answer of the token endpoint of the identity provider */
interface OidcTokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: 'Bearer';
    /** Used to retrieve the {@link JwtFullPayload} */
    id_token: string;
    'not-before-policy': number;
    session_state: string;
    scope: string;
}

/**
 * Retrieved by decoding the JWT {@link OidcTokenResponse.id_token}
 * The `sub` attribute is used to identify a user in `common.externalAuthentication.oidc.sub`
 */
interface JwtFullPayload extends Required<JwtPayload> {
    /** Value that was sent with the authorization request, it proves the token belongs to this login */
    nonce?: string;
    auth_time: number;
    typ: string;
    azp: string;
    sid: string;
    at_hash: string;
    acr: string;
    email_verified: boolean;
    name: string;
    preferred_username: string;
    given_name: string;
    family_name: string;
    email: string;
}

/** Configuration of the OpenID Connect identity provider that is used for the single sign-on */
export interface OidcConfig {
    /**
     * Issuer URL of the identity provider, e.g. `https://keycloak.example.com/realms/iobroker`.
     * The endpoints are read from its discovery document, so no provider-specific paths are needed.
     */
    issuer: string;
    /** Client ID that is registered at the identity provider for this installation */
    clientId: string;
    /** Secret of a confidential client. Empty for a public client, which authenticates with PKCE instead. */
    clientSecret?: string;
    /** Scopes to ask for, default `openid profile email` */
    scope?: string;
}

/** The parts of the discovery document of the identity provider that are used here */
interface OidcDiscovery {
    issuer: string;
    authorization_endpoint: string;
    token_endpoint: string;
    jwks_uri: string;
}

/** A login that was started and waits for the identity provider to call back */
interface PendingLogin {
    /** Where the browser goes afterwards. Already checked to point at this server. */
    redirectUrl: string;
    /** `login` signs a user in, `register` connects an existing ioBroker user with the identity */
    method: 'login' | 'register';
    /** ioBroker user to connect, only used by `register` */
    user?: string;
    /** PKCE code verifier, only for a public client */
    codeVerifier?: string;
    /** Must come back in the ID token, so a token of another login cannot be replayed here */
    nonce: string;
    /** The `redirect_uri` that was sent along, the token request has to repeat it unchanged */
    redirectUri: string;
    /** Point in time after which the entry is thrown away */
    expires: number;
}

/** A login that is not finished within this time is forgotten */
const PENDING_LOGIN_TTL_MS = 10 * 60 * 1000;

/**
 * Encode as base64url, the form the OAuth2 and OIDC specifications ask for
 *
 * @param buffer bytes to encode
 */
function base64url(buffer: Buffer): string {
    return buffer.toString('base64url');
}

/**
 * One configured OpenID Connect identity provider.
 *
 * The endpoints are not written into the code but read from the discovery document of the issuer,
 * so every provider that follows the standard works: Keycloak, Authentik, Auth0, Entra ID, ...
 */
class OidcProvider {
    private readonly adapter: ioBroker.Adapter;

    private readonly config: OidcConfig;

    /** The discovery document is read once and kept. A failed attempt is not cached. */
    private discovery: Promise<OidcDiscovery> | null = null;

    private jwks: JwksClient | null = null;

    /** Logins that were started, by the opaque state that the identity provider gets */
    private readonly pending = new Map<string, PendingLogin>();

    constructor(adapter: ioBroker.Adapter, config: OidcConfig) {
        this.adapter = adapter;
        this.config = config;
    }

    /** Scopes that are requested */
    get scope(): string {
        return this.config.scope || 'openid profile email';
    }

    /** True if the client authenticates with its own secret instead of PKCE */
    get isConfidential(): boolean {
        return !!this.config.clientSecret;
    }

    /** Read the discovery document of the issuer */
    async getDiscovery(): Promise<OidcDiscovery> {
        this.discovery ||= (async (): Promise<OidcDiscovery> => {
            const url = `${this.config.issuer.replace(/\/$/, '')}/.well-known/openid-configuration`;
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`Cannot read "${url}": ${response.status}`);
            }
            const doc = (await response.json()) as OidcDiscovery;
            if (!doc.issuer || !doc.authorization_endpoint || !doc.token_endpoint || !doc.jwks_uri) {
                throw new Error(`"${url}" is not a valid OpenID Connect discovery document`);
            }
            this.adapter.log.debug(`SSO: using the identity provider "${doc.issuer}"`);
            return doc;
        })().catch((e: Error) => {
            // The provider may have been down for a moment, so the next login tries again
            this.discovery = null;
            throw e;
        });

        return this.discovery;
    }

    /** Keys of the issuer, used to check the signature of an ID token */
    private async getJwks(): Promise<JwksClient> {
        const discovery = await this.getDiscovery();
        this.jwks ||= new JwksClient({ jwksUri: discovery.jwks_uri, cache: true, rateLimit: true });
        return this.jwks;
    }

    /**
     * Remember a started login and give back the opaque `state` for the identity provider.
     * Nothing about the login travels through the browser, so none of it can be tampered with.
     *
     * @param login the login that was just started
     */
    createPending(login: Omit<PendingLogin, 'expires'>): string {
        const now = Date.now();
        for (const [key, entry] of this.pending) {
            if (entry.expires <= now) {
                this.pending.delete(key);
            }
        }

        const state = base64url(randomBytes(24));
        this.pending.set(state, { ...login, expires: now + PENDING_LOGIN_TTL_MS });
        return state;
    }

    /**
     * Take a started login out of the list. Every state works exactly once.
     *
     * @param state the state that came back from the identity provider
     */
    takePending(state: string): PendingLogin | undefined {
        const entry = this.pending.get(state);
        this.pending.delete(state);

        return entry && entry.expires > Date.now() ? entry : undefined;
    }

    /**
     * Build the address the browser is sent to for the login
     *
     * @param login the login that was started
     * @param state the opaque state of that login
     */
    async getAuthorizationUrl(login: PendingLogin, state: string): Promise<string> {
        const discovery = await this.getDiscovery();

        const params = new URLSearchParams({
            client_id: this.config.clientId,
            response_type: 'code',
            scope: this.scope,
            redirect_uri: login.redirectUri,
            state,
            nonce: login.nonce,
        });

        if (login.codeVerifier) {
            params.set('code_challenge', base64url(createHash('sha256').update(login.codeVerifier).digest()));
            params.set('code_challenge_method', 'S256');
        }

        return `${discovery.authorization_endpoint}${discovery.authorization_endpoint.includes('?') ? '&' : '?'}${params.toString()}`;
    }

    /**
     * Exchange the code of the callback for the tokens
     *
     * @param code the code the identity provider sent to the callback
     * @param login the login this code belongs to
     */
    async exchangeCode(code: string, login: PendingLogin): Promise<OidcTokenResponse> {
        const discovery = await this.getDiscovery();

        const body = new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: login.redirectUri,
            client_id: this.config.clientId,
        });

        if (this.config.clientSecret) {
            body.set('client_secret', this.config.clientSecret);
        } else if (login.codeVerifier) {
            body.set('code_verifier', login.codeVerifier);
        }

        const response = await fetch(discovery.token_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body,
        });

        if (!response.ok) {
            throw new Error(`Token request to "${discovery.token_endpoint}" failed with status ${response.status}`);
        }

        return (await response.json()) as OidcTokenResponse;
    }

    /**
     * Check the signature and the content of an ID token and give back its claims
     *
     * @param idToken the ID token out of the token answer
     * @param nonce the value that was sent with the authorization request
     */
    async verifyIdToken(idToken: string, nonce: string): Promise<JwtFullPayload> {
        const discovery = await this.getDiscovery();
        const jwks = await this.getJwks();

        const getKey = (header: JwtHeader, callback: SigningKeyCallback): void => {
            jwks.getSigningKey(header.kid, (err, key) => {
                if (err) {
                    return callback(err);
                }
                if (!key) {
                    return callback(new Error('Key is undefined'));
                }
                callback(null, key.getPublicKey());
            });
        };

        const payload = await new Promise<JwtFullPayload>((resolve, reject) => {
            verify(
                idToken,
                getKey,
                {
                    algorithms: ['RS256', 'RS384', 'RS512', 'PS256', 'ES256', 'ES384'],
                    issuer: discovery.issuer,
                    audience: this.config.clientId,
                },
                (err, decoded) => {
                    if (err) {
                        return reject(new Error(`Token verification failed: ${err.message}`));
                    }
                    resolve(decoded as JwtFullPayload);
                },
            );
        });

        if (payload.nonce !== nonce) {
            throw new Error('Token verification failed: the nonce does not belong to this login');
        }

        return payload;
    }
}

/**
 * Create an OAuth2 server on the given Express app.
 *
 * @param adapter The adapter instance
 * @param options Options
 * @param options.app The Express app
 * @param options.secure Whether the connection is secure (default: false)
 * @param options.accessLifetime Access token expiration in seconds (default: 1 hour)
 * @param options.refreshLifetime Refresh token expiration in seconds (default: 30 days)
 * @param options.noBasicAuth Do not allow basic authentication
 * @param options.loginPage The login page URL (default: empty and someone else will handle the login). It could be a function too
 * @param options.authorizationCode Enable the browser-based authorization code flow with PKCE (default: disabled)
 * @param options.baseUrl Externally reachable base URL, required behind a reverse proxy
 * @param options.dynamicClientRegistration Let clients register themselves via RFC 7591 (default: enabled with the authorization code flow)
 * @param options.maxClients Maximum number of registered clients before the oldest dynamic ones are pruned
 * @param options.productName Name shown on the login and consent pages (default: "ioBroker")
 * @param options.oidc Identity provider for the single sign-on. Without it, `/sso` does not exist.
 */
export function createOAuth2Server(
    adapter: ioBroker.Adapter,
    options: {
        app: Express;
        secure?: boolean;
        accessLifetime?: number;
        refreshLifetime?: number;
        noBasicAuth?: boolean;
        loginPage?: string | ((req: Request) => string);
        authorizationCode?: boolean;
        baseUrl?: string | ((req: Request) => string);
        dynamicClientRegistration?: boolean;
        maxClients?: number;
        productName?: string;
        oidc?: OidcConfig;
    },
): OAuth2Model {
    const model = new OAuth2Model(adapter, {
        accessLifetime: options.accessLifetime,
        refreshLifeTime: options.refreshLifetime,
        noBasicAuth: options.noBasicAuth,
    });

    const oauth = new OAuth2Server({
        model,
        requireClientAuthentication: { password: false, refresh_token: false },
    });

    // The authorization code flow is opt-in: it opens a browser-facing login and, unless disabled,
    // an open registration endpoint, so no existing installation should get it by surprise.
    const authCodeFlow = options.authorizationCode
        ? new AuthorizationCodeFlow(adapter, {
              app: options.app,
              model,
              clientStore: new OAuth2ClientStore(adapter, { maxClients: options.maxClients }),
              baseUrl: options.baseUrl,
              dynamicClientRegistration: options.dynamicClientRegistration,
              productName: options.productName,
          })
        : null;

    // Discovery, registration and revocation must stay reachable without credentials, so they are
    // registered before the app-wide `authorize` middleware below.
    authCodeFlow?.registerPublicRoutes();

    // The single sign-on only exists when an identity provider is configured. Without it, the two
    // routes are not registered at all instead of answering with a half-working login.
    const oidc = options.oidc?.issuer && options.oidc.clientId ? new OidcProvider(adapter, options.oidc) : null;

    if (oidc) {
        /**
         * Start a login at the identity provider.
         *
         * @param req request with `redirectUrl`, `method` and, for `register`, the ioBroker `user`
         * @param res response that sends the browser to the identity provider
         */
        const handleSsoStart = async (req: Request, res: Response): Promise<void> => {
            const query = req.query as { redirectUrl?: string; method?: string; user?: string };
            const ownOrigin = `${req.protocol}://${req.get('host')}`;

            // The browser is sent to this address after the login, so it has to stay on this server.
            // Without the check, the route would be an open redirect for anybody who can call it.
            let redirectUrl: string;
            try {
                const target = new URL(query.redirectUrl || '/', ownOrigin);
                if (target.origin !== new URL(ownOrigin).origin) {
                    throw new Error('foreign origin');
                }
                redirectUrl = target.href;
            } catch {
                adapter.log.error(`SSO: refused to redirect to "${query.redirectUrl}"`);
                res.status(400).send('Invalid redirectUrl');
                return;
            }

            const method = query.method === 'register' ? 'register' : 'login';
            if (method === 'register' && !query.user) {
                adapter.log.error('SSO: a register request without a user');
                res.status(400).send('Missing user');
                return;
            }

            const login: PendingLogin = {
                redirectUrl,
                method,
                user: query.user,
                nonce: base64url(randomBytes(16)),
                // A public client has no secret, it proves with PKCE that the code belongs to it
                codeVerifier: oidc.isConfidential ? undefined : base64url(randomBytes(32)),
                redirectUri: `${ownOrigin}/sso-callback`,
                expires: 0,
            };

            const state = oidc.createPending(login);

            try {
                res.redirect(await oidc.getAuthorizationUrl(login, state));
            } catch (e) {
                adapter.log.error(`SSO: cannot reach the identity provider: ${(e as Error).message}`);
                res.status(502).send('Cannot reach the identity provider');
            }
        };

        /**
         * Take the answer of the identity provider and either sign the user in or connect the
         * identity with an existing ioBroker user.
         *
         * @param req request with the `code` and the `state` of the started login
         * @param res response that sends the browser back where it came from
         */
        const handleSsoCallback = async (req: Request, res: Response): Promise<void> => {
            const query = req.query as { code?: string; state?: string; error?: string };

            const login = query.state ? oidc.takePending(query.state) : undefined;
            if (!login) {
                // Either somebody called the route directly, or the login took too long
                adapter.log.error('SSO: unknown or expired state');
                res.status(400).send('Invalid state parameter');
                return;
            }

            if (!query.code) {
                adapter.log.error(`SSO: the identity provider sent no code: ${query.error || 'unknown reason'}`);
                res.redirect(login.redirectUrl);
                return;
            }

            let tokenData: OidcTokenResponse;
            let jwtVerifiedPayload: JwtFullPayload;
            try {
                tokenData = await oidc.exchangeCode(query.code, login);
                jwtVerifiedPayload = await oidc.verifyIdToken(tokenData.id_token, login.nonce);
            } catch (e) {
                adapter.log.error(`SSO: ${(e as Error).message}`);
                res.redirect(login.redirectUrl);
                return;
            }

            if (login.method === 'login') {
                const objView = await adapter.getObjectViewAsync('system', 'user', {
                    startkey: 'system.user.',
                    endkey: 'system.user.\u9999',
                });

                const item = objView.rows.find(
                    // @ts-expect-error needs to be allowed explicitly
                    item => item.value.common?.externalAuthentication?.oidc?.sub === jwtVerifiedPayload.sub,
                );

                if (!item) {
                    // The identity is not connected with any ioBroker user. Users are never created
                    // here, an administrator has to connect them first.
                    adapter.log.warn(
                        `SSO: no ioBroker user is connected with the identity "${jwtVerifiedPayload.sub}"`,
                    );
                    res.redirect(login.redirectUrl);
                    return;
                }

                try {
                    const oauthToken = await model.generateTokens(item.id);
                    const responseToken = oauthTokenToResponse(oauthToken);

                    const redirectUrl = new URL(login.redirectUrl);
                    redirectUrl.search = new URLSearchParams({
                        ssoLoginResponse: JSON.stringify(responseToken),
                    }).toString();

                    res.cookie('access_token', responseToken.access_token).redirect(redirectUrl.toString());
                    return;
                } catch (e) {
                    adapter.log.error(`Could not get oauth token: ${(e as Error).message}`);
                }

                res.redirect(login.redirectUrl);
                return;
            }

            // Connect the identity with an existing ioBroker user
            if (!login.user) {
                adapter.log.error('SSO: Invalid state - expected register method with user');
                res.redirect(login.redirectUrl);
                return;
            }

            const userObj = await adapter.getForeignObjectAsync(`system.user.${login.user}`);
            if (!userObj) {
                adapter.log.error(`SSO: No existing user object for user "${login.user}"`);
                res.redirect(login.redirectUrl);
                return;
            }

            userObj.common.externalAuthentication ??= {};
            userObj.common.externalAuthentication.oidc = { sub: jwtVerifiedPayload.sub };
            await adapter.extendForeignObjectAsync(`system.user.${login.user}`, userObj);

            const redirectUrl = new URL(login.redirectUrl);
            redirectUrl.search = `id_token=${tokenData.id_token}`;
            res.redirect(redirectUrl.toString());
        };

        options.app.get('/sso', (req: Request, res: Response): void => void handleSsoStart(req, res));
        options.app.get('/sso-callback', (req: Request, res: Response): void => void handleSsoCallback(req, res));
    }

    // Post token.
    options.app.post('/oauth/token', (req: Request, res: Response) => {
        void handleTokenRequest(req, res);
    });

    /**
     * Dispatch a token request to the matching grant. The body is read up front because the grant
     * type decides where the request goes, and not every host adapter installs a body parser.
     *
     * @param req The incoming request
     * @param res The response to write to
     */
    async function handleTokenRequest(req: Request, res: Response): Promise<void> {
        if (authCodeFlow) {
            try {
                // Hand the parsed body back to Express so `oauth2-server` finds it below.
                req.body = await readRequestBody(req);
            } catch (e) {
                res.status(400).json({ error: 'invalid_request', error_description: (e as Error).message });
                return;
            }

            if (req.body?.grant_type === 'authorization_code') {
                await authCodeFlow.handleTokenRequest(req, res);
                return;
            }
        }

        const request = new OAuthRequest(req);

        const response = new OAuthResponse(res);
        await oauth
            .token(request, response)
            .then((token: Token): void => {
                // save access token and refresh token in cookies with expiration time and flags HTTPOnly, Secure.
                const cookieOptions: CookieOptions = {
                    httpOnly: true, // Makes the cookie inaccessible to client-side JavaScript
                    secure: options.secure, // Only send cookie over HTTPS in production
                    // expires: token.accessTokenExpiresAt, // Cookie will expire in X hour
                    sameSite: 'strict', // Prevents the browser from sending this cookie along with cross-site requests (optional)
                };

                // Without a lifetime the cookie ends with the browser session. With "stay logged in" it lives as
                // long as the access token. `maxAge` is relative to the clock of the browser; `expires` would be
                // an absolute date from the server clock, and a server with a wrong time (a board without a
                // real-time clock before NTP kicks in) would hand out cookies the browser drops at once.
                if (req.body.stayloggedin === 'true' && token.accessTokenExpiresAt) {
                    cookieOptions.maxAge = Math.max(0, token.accessTokenExpiresAt.getTime() - Date.now());
                }

                // Store the access token in a cookie named "access_token"
                res.cookie('access_token', token.accessToken, cookieOptions);

                res.json(oauthTokenToResponse(token));
            })
            .catch((err: any): void => {
                res.status(err.code || 500).json(err);
            });
    }

    options.app.get('/logout', (req: Request, res: Response, next: NextFunction): void => {
        let accessToken = req.headers.cookie?.split(';').find(c => c.trim().startsWith('access_token='));
        if (accessToken) {
            accessToken = accessToken.split('=')[1];
        } else if (req.query.token) {
            accessToken = req.query.token as string;
        } else if (req.headers.authorization?.startsWith('Bearer ')) {
            accessToken = req.headers.authorization.substring(7);
        }

        if (accessToken) {
            void adapter.getSession(`a:${accessToken}`, (obj: ioBroker.Session | null): void => {
                res.clearCookie('access_token');

                if (obj) {
                    void adapter.destroySession(`a:${obj.aToken}`);
                    void adapter.destroySession(`r:${obj.rToken}`);
                }
                // the answer will be sent in other middleware
                if (options.loginPage) {
                    if (typeof options.loginPage === 'function') {
                        res.redirect(options.loginPage(req));
                    } else {
                        res.redirect(options.loginPage);
                    }
                } else {
                    next();
                }
            });
        } else {
            res.clearCookie('access_token');

            // the answer will be sent in other middleware
            if (options.loginPage) {
                if (typeof options.loginPage === 'function') {
                    res.redirect(options.loginPage(req));
                } else {
                    res.redirect(options.loginPage);
                }
            } else {
                next();
            }
        }
    });

    options.app.use(model.authorize);

    // Registered after `authorize` so `req.user` is already filled from an `access_token` cookie:
    // a user who is signed in to the web UI only has to confirm, not to log in again.
    authCodeFlow?.registerAuthorizeRoutes();

    return model;
}

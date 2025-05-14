import type { Request, Response, Express, NextFunction } from 'express';
import OAuth2Server, { Request as OAuthRequest, Response as OAuthResponse, type Token } from 'oauth2-server';
import { type InternalStorageToken, OAuth2Model } from './oauth2-model';
import { verify, type JwtHeader, type SigningKeyCallback, type JwtPayload } from 'jsonwebtoken';
import { JwksClient } from 'jwks-rsa';
import { oauthTokenToResponse, SSO_PASSWORD } from './utils';

export interface CookieOptions {
    /** Convenient option for setting the expiry time relative to the current time in **milliseconds**. */
    maxAge?: number | undefined;
    /** Indicates if the cookie should be signed. */
    signed?: boolean | undefined;
    /** Expiry date of the cookie in GMT. If not specified or set to 0, creates a session cookie. */
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

/** The base state query attribute for SSO */
type SsoBaseState = {
    /** Url to redirect too, after SSO has been performed */
    redirectUrl: string;
};

/** The state query attribute for SSO */
type SsoState = SsoBaseState &
    (
        | {
              /** If this is a register request */
              method: 'register';
              /** Register requests have the name of the ioBroker user to register */
              user: string;
          }
        | {
              /** If this is a login request */
              method: 'login';
          }
    );

/** Query parameters in the SSO callback */
interface SsoCallbackQuery {
    /** Code to exchange for token */
    code: string;
    /** SsoState as parseable string */
    state: string;
}

interface OidcTokenResponse {
    access_token: string;
    refresh_token: string;
    token_type: 'Bearer';
    /** Used to retrieve the JwtFullPayload */
    id_token: string;
    'not-before-policy': number;
    session_state: string;
    scope: string;
}

interface JwtFullPayload extends Required<JwtPayload> {
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

/** Keycloak ioBroker realm */
const KEYCLOAK_ISSUER = 'https://keycloak.heusinger-it.duckdns.org/realms/iobroker-local';
/** The client for local authentication */
const KEYCLOAK_CLIENT_ID = 'iobroker-local-auth';

const jwksClient = new JwksClient({
    jwksUri: `${KEYCLOAK_ISSUER}/protocol/openid-connect/certs`,
    cache: true,
    rateLimit: true,
});

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

    options.app.get('/sso', (req: Request<any, any, any, SsoState>, res: Response): void => {
        const scope = 'openid email';
        const { redirectUrl, method } = req.query;

        let user = '';

        if (req.query.method === 'register') {
            user = req.query.user;
        }

        const redirectUri = `${req.protocol}://${req.get('host')}/sso-callback`;
        const authUrl = `${KEYCLOAK_ISSUER}/protocol/openid-connect/auth?client_id=${KEYCLOAK_CLIENT_ID}&response_type=code&scope=${scope}&redirect_uri=${redirectUri}&state=${encodeURIComponent(JSON.stringify({ method, redirectUrl, user }))}`;

        res.redirect(authUrl);
    });

    options.app.get<string>('/sso-callback', async (req: Request, res): Promise<void> => {
        const { code, state } = req.query as unknown as SsoCallbackQuery;

        const thisHost = `${req.protocol}://${req.get('host')}`;
        const stateObj: SsoState = JSON.parse(decodeURIComponent(state));

        /**
         * Get key from Keycloak
         *
         * @param header JWT header
         * @param callback the callback function
         */
        const getKey = (header: JwtHeader, callback: SigningKeyCallback): void => {
            jwksClient.getSigningKey(header.kid, (err, key) => {
                if (err) {
                    return callback(err);
                }

                if (!key) {
                    return callback(new Error('Key is undefined'));
                }

                const signingKey = key.getPublicKey();
                callback(null, signingKey);
            });
        };

        /**
         * Verify the given JWT token
         *
         * @param idToken the jwt token to verify
         */
        const verifyIdToken = async (idToken: string): Promise<JwtFullPayload> => {
            return new Promise((resolve, reject) => {
                verify(
                    idToken,
                    getKey,
                    {
                        algorithms: ['RS256'],
                        issuer: KEYCLOAK_ISSUER,
                        audience: KEYCLOAK_CLIENT_ID,
                    },
                    (err, decoded) => {
                        if (err) {
                            return reject(new Error(`Token verification failed: ${err.message}`));
                        }
                        resolve(decoded as JwtFullPayload);
                    },
                );
            });
        };

        const tokenUrl = `${KEYCLOAK_ISSUER}/protocol/openid-connect/token`;

        let tokenData: OidcTokenResponse;
        let jwtVerifiedPayload: JwtFullPayload;

        try {
            const tokenResponse = await fetch(tokenUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    code,
                    redirect_uri: `${thisHost}/sso-callback`,
                    client_id: KEYCLOAK_CLIENT_ID,
                }),
            });

            tokenData = await tokenResponse.json();
            jwtVerifiedPayload = await verifyIdToken(tokenData.id_token);

            adapter.log.debug(JSON.stringify(jwtVerifiedPayload));
        } catch (e) {
            adapter.log.error(`Error getting token: ${(e as Error).message}`);
            return res.redirect(stateObj.redirectUrl);
        }

        if (stateObj.method === 'login') {
            const objView = await adapter.getObjectViewAsync('system', 'user', {
                startkey: 'system.user.',
                endkey: 'system.user.\u9999',
            });

            const item = objView.rows.find(
                // @ts-expect-error needs to be allowed explicitly
                item => item.value.common?.externalAuthentication?.oidc?.sub === jwtVerifiedPayload.sub,
            );

            if (!item) {
                // no user connected to the SSO
                return res.redirect(stateObj.redirectUrl);
            }

            const username = item.id;

            try {
                const params = new URLSearchParams({
                    grant_type: 'password',
                    username,
                    password: SSO_PASSWORD,
                    client_id: 'ioBroker',
                });

                const request = new OAuthRequest({
                    method: 'POST',
                    headers: {
                        'content-type': 'application/x-www-form-urlencoded',
                        'content-length': Buffer.byteLength(params.toString()).toString(),
                    },
                    body: Object.fromEntries(params.entries()),
                    query: {},
                });

                const response = new OAuthResponse(res);
                const oauthToken = await oauth.token(request, response);
                const responseToken = oauthTokenToResponse(oauthToken);

                const redirectUrl = new URL(stateObj.redirectUrl);
                redirectUrl.search = new URLSearchParams({
                    ssoLoginResponse: JSON.stringify(responseToken),
                }).toString();

                return void res.cookie('access_token', responseToken.access_token).redirect(redirectUrl.toString());
            } catch (e) {
                adapter.log.error(`Could not get oauth token: ${(e as Error).message}`);
            }

            return res.redirect(stateObj.redirectUrl);
        }

        // user connection flow
        const userObj = await adapter.getForeignObjectAsync(`system.user.${stateObj.user}`);

        if (!userObj) {
            adapter.log.error(`SSO: No existing user object for user "${stateObj.user}"`);
            return res.redirect(stateObj.redirectUrl);
        }

        // @ts-expect-error needs to be allowed explicitly
        userObj.common.externalAuthentication ??= {};
        // @ts-expect-error needs to be allowed explicitly
        userObj.common.externalAuthentication.oidc = { sub: jwtVerifiedPayload.sub };
        await adapter.extendForeignObjectAsync(`system.user.${stateObj.user}`, userObj);

        const redirectUrl = new URL(stateObj.redirectUrl);
        redirectUrl.search = `id_token=${tokenData.id_token}`;
        res.redirect(redirectUrl.toString());
    });

    // Post token.
    options.app.post('/oauth/token', (req: Request, res: Response) => {
        const request = new OAuthRequest(req);

        if (request.body.password === SSO_PASSWORD) {
            const error = new Error('SSO password used on standard login');
            adapter.log.error(error.message);
            return res.status(500).json(error);
        }

        const response = new OAuthResponse(res);
        oauth
            .token(request, response)
            .then((token: Token): void => {
                // save access token and refresh token in cookies with expiration time and flags HTTPOnly, Secure.
                const cookieOptions: CookieOptions = {
                    httpOnly: true, // Makes the cookie inaccessible to client-side JavaScript
                    secure: options.secure, // Only send cookie over HTTPS in production
                    // expires: token.accessTokenExpiresAt, // Cookie will expire in X hour
                    sameSite: 'strict', // Prevents the browser from sending this cookie along with cross-site requests (optional)
                };

                // If expires omitted or set to 0, the cookie will expire at the end of the session (when the browser closes).
                if (req.body.stayloggedin === 'true') {
                    cookieOptions.expires = token.accessTokenExpiresAt;
                }

                // Store the access token in a cookie named "access_token"
                res.cookie('access_token', token.accessToken, cookieOptions);

                res.json(oauthTokenToResponse(token));
            })
            .catch((err: any): void => {
                res.status(err.code || 500).json(err);
            });
    });

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
            void adapter.getSession(`a:${accessToken}`, (obj: InternalStorageToken): void => {
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

    return model;
}

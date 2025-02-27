import type { Request, Response, Express, NextFunction } from 'express';
import OAuth2Server, { Request as OAuthRequest, Response as OAuthResponse, type Token } from 'oauth2-server';
import { type InternalStorageToken, OAuth2Model } from './oauth2-model';

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

/**
 * Create an OAuth2 server on the given Express app.
 *
 * @param adapter The adapter instance
 * @param options Options
 * @param options.app The Express app
 * @param options.secure Whether the connection is secure (default: false)
 * @param options.accessLifetime Access token expiration in seconds (default: 1 hour)
 * @param options.refreshLifetime Refresh token expiration in seconds (default: 30 days)
 * @param options.loginPage The login page URL (default: empty and someone else will handle the login). It could be a function too
 */
export function createOAuth2Server(
    adapter: ioBroker.Adapter,
    options: {
        app: Express;
        secure?: boolean;
        accessLifetime?: number;
        refreshLifetime?: number;
        loginPage?: string | ((req: Request) => string);
    },
): void {
    const model = new OAuth2Model(adapter, {
        secure: options.secure,
        accessLifetime: options.accessLifetime,
        refreshLifeTime: options.refreshLifetime,
    });

    const oauth = new OAuth2Server({
        model,
        requireClientAuthentication: { password: false, refresh_token: false },
    });

    // Post token.
    options.app.post('/oauth/token', (req: Request, res: Response) => {
        const request = new OAuthRequest(req);
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

                res.json({
                    access_token: token.accessToken,
                    token_type: 'Bearer',
                    expires_in: Math.floor((token.accessTokenExpiresAt!.getTime() - Date.now()) / 1000),
                    refresh_token: token.refreshToken,
                    refresh_token_expires_in: Math.floor((token.refreshTokenExpiresAt!.getTime() - Date.now()) / 1000),
                });
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
}

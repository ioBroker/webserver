import type { Request, Response, Express, NextFunction } from 'express';
import OAuth2Server, { Request as OAuthRequest, Response as OAuthResponse, type Token } from 'oauth2-server';
import { OAuth2Model } from './oauth2-model';

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
    /**
     * Value of the “SameSite” Set-Cookie attribute.
     *
     * @link https://tools.ietf.org/html/draft-ietf-httpbis-cookie-same-site-00#section-4.1.1.
     */
    sameSite?: boolean | 'lax' | 'strict' | 'none' | undefined;
    /**
     * Value of the “Priority” Set-Cookie attribute.
     *
     * @link https://datatracker.ietf.org/doc/html/draft-west-cookie-priority-00#section-4.3
     */
    priority?: 'low' | 'medium' | 'high';
    /** Marks the cookie to use partitioned storage. */
    partitioned?: boolean | undefined;
}

export function createOAuth2Server(
    adapter: ioBroker.Adapter,
    options: {
        app: Express;
        secure?: boolean;
        accessLifetime?: number;
        refreshLifetime?: number;
        withSession?: boolean;
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

                res.json(token);
            })
            .catch((err: any): void => {
                res.status(err.code || 500).json(err);
            });
    });

    options.app.get('/logout', (_req: Request, res: Response, next: NextFunction): void => {
        res.clearCookie('access_token');
        res.clearCookie('refresh_token');
        // the answer will be sent in other middleware
        if (options.withSession) {
            next();
        } else {
            res.redirect('/login/index.html');
        }
    });

    options.app.use(model.authorize);
}

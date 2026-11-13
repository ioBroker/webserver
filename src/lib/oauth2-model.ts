import { randomBytes, createHash } from 'node:crypto';
import {
    type Client,
    type Falsey,
    type RefreshTokenModel,
    type Token,
    type PartialToken,
    type User,
    type RefreshToken,
    type Scope,
} from 'oauth2-server';

import type { NextFunction, Request, Response } from 'express';

import { SecondFactor, shortUserName } from './totp';

/** Extra properties bound to a token beyond the user it belongs to. */
export interface TokenBinding {
    /** ID of the OAuth2 client the token is issued to */
    clientId?: string;
    /** Resource the token is valid for (RFC 8707) */
    aud?: string;
    /** Granted scope */
    scope?: string;
}

// ----- OAuth2Model Class -----
// This class implements the model methods required by oauth2-server.
export class OAuth2Model implements RefreshTokenModel {
    // Token lifetimes in seconds
    private readonly accessTokenLifetime: number = 60 * 60; // 1 hour
    private readonly refreshTokenLifetime: number = 60 * 60 * 24 * 30; // 30 days
    private readonly noBasicAuth: boolean; // Do not allow basic auth
    private adapter: ioBroker.Adapter;
    private bruteForce: Record<string, { errors: number; time: number }> = {};
    /** One-time keys for `getUser` of logins whose password and code were checked already */
    private readonly preAuthorized = new Map<string, { user: string; expires: number }>();
    /** Two-factor authentication with an authenticator app */
    readonly secondFactor: SecondFactor;

    /**
     * Create an OAuth2model
     *
     * @param adapter ioBroker adapter
     * @param options Options
     * @param options.accessLifetime Access token expiration in seconds
     * @param options.refreshLifeTime Refresh token expiration in seconds
     * @param options.noBasicAuth Do not allow basic authentication
     */
    constructor(
        adapter: ioBroker.Adapter,
        options?: {
            accessLifetime?: number;
            refreshLifeTime?: number;
            noBasicAuth?: boolean;
        },
    ) {
        this.adapter = adapter;
        this.accessTokenLifetime = options?.accessLifetime || this.accessTokenLifetime;
        this.refreshTokenLifetime = options?.refreshLifeTime || this.refreshTokenLifetime;
        this.noBasicAuth = options?.noBasicAuth || false;
        this.secondFactor = new SecondFactor(adapter);
    }

    getAccessToken = async (bearerToken: string): Promise<Token | Falsey> => {
        const token = await this.getTokenInfo(bearerToken);
        if (!token) {
            return null;
        }

        return {
            accessToken: token.aToken,
            accessTokenExpiresAt: new Date(token.aExp),
            client: {
                id: 'ioBroker',
                grants: ['password', 'refresh_token'],
                accessTokenLifetime: this.accessTokenLifetime,
                refreshTokenLifetime: this.refreshTokenLifetime,
            },
            user: {
                id: token.user,
                // Carried along so a refresh keeps the binding, and so resource servers can read it.
                clientId: token.clientId,
                aud: token.aud,
                scope: token.scope,
            },
        };
    };

    /**
     * Read the stored record of an access token, including the client and resource it is bound to.
     * Resource servers use this to verify that a token was actually issued for them.
     *
     * @param bearerToken The access token to look up
     */
    getTokenInfo = async (bearerToken: string): Promise<ioBroker.Session | null> => {
        return new Promise<ioBroker.Session | null>(resolve => this.adapter.getSession(`a:${bearerToken}`, resolve));
    };

    /**
     * Get client.
     */
    getClient = (_clientId: string, _clientSecret: string): Promise<Client | Falsey> => {
        // Just now we do not check the client secret as only one client is allowed
        return Promise.resolve({
            id: 'ioBroker',
            grants: ['password', 'refresh_token'],
            accessTokenLifetime: this.accessTokenLifetime,
            refreshTokenLifetime: this.refreshTokenLifetime,
        });
    };

    authorize = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
        const _req: Request & { user?: string } = req;

        // Check if the user is logged in
        if (!_req.user) {
            // If authenticated by token in a query like /blabla?token=ACCESS_TOKEN
            if (_req.query.token) {
                const token = await this.getAccessToken(_req.query.token as string);
                if (token) {
                    _req.user = token.user.id;
                }
            }
            // If authenticated by Authorization header {headers: authorization: "Bearer ACCESS_TOKEN"}
            if (!_req.user && _req.headers?.authorization?.startsWith('Bearer ')) {
                const token = await this.getAccessToken(_req.headers.authorization.substring(7));
                if (token) {
                    _req.user = token.user.id;
                } else {
                    res.status(401).send('Unauthorized');
                    return;
                }
            }
            // If authentication by access token in a cookie
            if (!_req.user && _req.headers?.cookie) {
                // If authenticated by cookie, like {headers: {cookie: "access_token=ACCESS_TOKEN"}}
                const cookies = _req.headers.cookie.split(';').map(c => c.trim().split('='));
                const tokenCookie = cookies.find(c => c[0] === 'access_token');
                if (tokenCookie) {
                    const token = await this.getAccessToken(tokenCookie[1]);
                    if (token) {
                        _req.user = token.user.id;
                    }
                }
            }
            if (!_req.user && _req.query.user && _req.query.pass) {
                // If authenticated by a query like /blabla?user=USER&pass=PASS
                const user = await this.getUser(_req.query.user as string, _req.query.pass as string);
                if (user) {
                    _req.user = user.id;
                } else {
                    res.status(401).send('Unauthorized');
                    return;
                }
            }
            if (!_req.user && !this.noBasicAuth && _req.headers?.authorization?.startsWith('Basic ')) {
                // If authenticated by Basic Auth
                const base64 = _req.headers.authorization.substring(6);
                const data = Buffer.from(base64, 'base64').toString('utf8');
                const parts = data.split(':');
                const username = parts.shift() || '';
                const pass = parts.join(':');
                const user = await this.getUser(username, pass);
                if (user) {
                    _req.user = user.id;
                } else {
                    res.status(401).send('Unauthorized');
                    return;
                }
            }
        }

        next();
    };

    /**
     * Issue a fresh access/refresh token pair for a user.
     *
     * @param userName The ioBroker user name (without the `system.user.` prefix)
     * @param binding Optional client/resource binding for tokens issued through the authorization code grant
     */
    generateTokens = async (userName: string, binding?: TokenBinding): Promise<Token> => {
        const accessToken = createHash('sha1').update(randomBytes(256)).digest('hex');
        const refreshToken = createHash('sha1').update(randomBytes(256)).digest('hex');
        const accessTokenExpiresAt = new Date(Date.now() + this.accessTokenLifetime * 1000);
        const refreshTokenExpiresAt = new Date(Date.now() + this.refreshTokenLifetime * 1000);

        // userName is short and already checked

        const result: PartialToken = {
            accessToken: accessToken,
            accessTokenExpiresAt: accessTokenExpiresAt,
            refreshToken: refreshToken,
            refreshTokenExpiresAt: refreshTokenExpiresAt,
        };

        const user: User = {
            id: userName,
            clientId: binding?.clientId,
            aud: binding?.aud,
            scope: binding?.scope,
        };

        await this.saveToken(
            result,
            {
                id: 'ioBroker',
                grants: ['password', 'refresh_token'],
                accessTokenLifetime: this.accessTokenLifetime,
                refreshTokenLifetime: this.refreshTokenLifetime,
            },
            user,
        );

        return {
            accessToken: result.accessToken,
            accessTokenExpiresAt: result.accessTokenExpiresAt,
            refreshToken: result.refreshToken,
            refreshTokenExpiresAt: result.refreshTokenExpiresAt,
            user,
            client: {
                id: 'ioBroker',
                grants: ['password', 'refresh_token'],
                accessTokenLifetime: this.accessTokenLifetime,
                refreshTokenLifetime: this.refreshTokenLifetime,
            },
        };
    };

    /**
     * Get refresh token.
     */
    getRefreshToken = async (bearerToken: string): Promise<RefreshToken | Falsey> => {
        const token = await new Promise<ioBroker.Session | null>(resolve =>
            this.adapter.getSession(`r:${bearerToken}`, resolve),
        );
        if (!token) {
            return null;
        }

        return {
            refreshToken: token.rToken,
            refreshTokenExpiresAt: new Date(token.rExp),
            client: {
                id: 'ioBroker',
                grants: ['password', 'refresh_token'],
                accessTokenLifetime: this.accessTokenLifetime,
                refreshTokenLifetime: this.refreshTokenLifetime,
            },
            user: {
                id: token.user,
                // oauth2-server hands this same object to `saveToken`, which is how a refreshed
                // token inherits the client and resource binding of the token it replaces.
                clientId: token.clientId,
                aud: token.aud,
                scope: token.scope,
            },
        };
    };

    /**
     * Minutes the user still has to wait after too many wrong attempts, or 0
     *
     * @param key user name as returned by `shortUserName`
     */
    private getBlockedMinutes(key: string): number {
        const entry = this.bruteForce[key];
        if (!entry || entry.errors <= 4) {
            return 0;
        }
        const passed = Date.now() - entry.time;
        // 5-6 errors: 1 minute, 7-9: 3 minutes, 10-14: 10 minutes, then 1 hour
        const wait = entry.errors < 7 ? 60_000 : entry.errors < 10 ? 180_000 : entry.errors < 15 ? 600_000 : 3_600_000;
        return passed < wait ? Math.max(1, Math.ceil((wait - passed) / 60_000)) : 0;
    }

    private countFailure(key: string): number {
        this.bruteForce[key] ||= { errors: 0, time: 0 };
        this.bruteForce[key].time = Date.now();
        this.bruteForce[key].errors++;
        return this.bruteForce[key].errors;
    }

    /**
     * Check a login with the password and, if the user has switched it on, the code of the second factor.
     * A wrong password and a wrong code both count for the brute force protection; the counter is only
     * reset after the whole login succeeded, so a known password does not allow guessing codes endlessly.
     *
     * @param username the user name as typed
     * @param password the password
     * @param otp code from the authenticator app or a backup code. `undefined` means that the client cannot
     *   send a code at all (basic authentication, password in the URL): a user with two-factor authentication
     *   cannot log in that way. An empty code means: ask for it.
     */
    checkLogin = async (
        username: string,
        password: string,
        otp?: string | null,
    ): Promise<{ user: string } | { error: 'invalid' | 'otp_required' | 'otp_invalid'; user?: string }> => {
        const key = shortUserName(username);
        const minutes = this.getBlockedMinutes(key);
        if (minutes) {
            this.adapter.log.warn(
                `Too many errors for "${username}". Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`,
            );
            return { error: 'invalid' };
        }

        const result = await new Promise<{ success: boolean; user: string }>(resolve =>
            this.adapter.checkPassword(username, password, (success: boolean, user: string): void =>
                resolve({ success, user }),
            ),
        );
        if (!result.success) {
            const errors = this.countFailure(key);
            this.adapter.log.warn(`Invalid password for ${username}. Wrong attempts: ${errors}`);
            return { error: 'invalid' };
        }
        const user = shortUserName(result.user || username);

        if (await this.secondFactor.isEnabled(user)) {
            if (otp === undefined) {
                this.adapter.log.warn(
                    `The user "${user}" uses two-factor authentication and cannot log in with the password alone (basic authentication or password in the URL)`,
                );
                return { error: 'invalid' };
            }
            if (!otp) {
                // The password was right, so this is no failed attempt: the client asks for the code now
                return { error: 'otp_required', user };
            }
            if (!(await this.secondFactor.verify(user, otp))) {
                const errors = this.countFailure(key);
                this.adapter.log.warn(`Invalid two-factor code for ${username}. Wrong attempts: ${errors}`);
                return { error: 'otp_invalid' };
            }
        }

        delete this.bruteForce[key];
        return { user };
    };

    /**
     * Check only the second factor, for logins that checked the password in an earlier step
     * (the login page of the authorization code flow, the login form of web). Wrong codes count for the
     * brute force protection like wrong passwords.
     *
     * @param user the user whose password was checked already
     * @param otp code from the authenticator app or a backup code
     */
    verifySecondFactor = async (user: string, otp: string): Promise<boolean> => {
        const key = shortUserName(user);
        const minutes = this.getBlockedMinutes(key);
        if (minutes) {
            this.adapter.log.warn(
                `Too many errors for "${user}". Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`,
            );
            return false;
        }
        if (!(await this.secondFactor.verify(key, otp || ''))) {
            const errors = this.countFailure(key);
            this.adapter.log.warn(`Invalid two-factor code for ${user}. Wrong attempts: ${errors}`);
            return false;
        }
        delete this.bruteForce[key];
        return true;
    };

    /**
     * A one-time key that `getUser` accepts instead of the password of this user. The token endpoint checks
     * the password and the code itself and hands over with this key to `oauth2-server`, which only knows
     * user name and password.
     *
     * @param user the user that is logged in
     */
    preAuthorize(user: string): string {
        const now = Date.now();
        for (const [key, entry] of this.preAuthorized) {
            if (entry.expires < now) {
                this.preAuthorized.delete(key);
            }
        }
        const key = randomBytes(32).toString('hex');
        this.preAuthorized.set(key, { user: shortUserName(user), expires: now + 30_000 });
        return key;
    }

    /**
     * Get user. Called by `oauth2-server` for the password grant and by `authorize` for basic authentication
     * and a password in the URL. Only the token endpoint can ask for a code, so a user with two-factor
     * authentication gets in here only with a key from `preAuthorize`.
     */
    getUser = async (username: string, password: string): Promise<User | Falsey> => {
        const pre = typeof password === 'string' ? this.preAuthorized.get(password) : undefined;
        if (pre) {
            this.preAuthorized.delete(password);
            return pre.expires >= Date.now() && pre.user === shortUserName(username) ? { id: pre.user } : null;
        }

        const result = await this.checkLogin(username, password);
        return 'user' in result ? { id: result.user } : null;
    };

    /**
     * Save token.
     */
    saveToken = async (token: PartialToken, client: Client, user: User): Promise<Token | Falsey> => {
        const data: Token = {
            accessToken: token.accessToken,
            accessTokenExpiresAt: token.accessTokenExpiresAt,
            refreshToken: token.refreshToken,
            refreshTokenExpiresAt: token.refreshTokenExpiresAt,
            user,
            client,
        };

        const accessTokenTtl = token.accessTokenExpiresAt
            ? Math.floor((token.accessTokenExpiresAt.getTime() - Date.now()) / 1000)
            : this.accessTokenLifetime;
        const refreshTokenTtl = token.refreshTokenExpiresAt
            ? Math.floor((token.refreshTokenExpiresAt.getTime() - Date.now()) / 1000)
            : this.refreshTokenLifetime;

        const internalToken: ioBroker.Session = {
            aToken: token.accessToken,
            aExp: token.accessTokenExpiresAt
                ? token.accessTokenExpiresAt.getTime()
                : Date.now() + this.accessTokenLifetime * 1000,
            rToken: token.refreshToken || '',
            rExp: token.refreshTokenExpiresAt
                ? token.refreshTokenExpiresAt.getTime()
                : Date.now() + this.refreshTokenLifetime * 1000,
            user: user.id,
            // Present when the token comes from the authorization code grant, either directly or
            // through a refresh — `getRefreshToken` passes the binding along on the user object.
            clientId: user.clientId,
            aud: user.aud,
            scope: user.scope,
        };

        await Promise.all([
            new Promise<void>((resolve, reject) =>
                this.adapter.setSession(`a:${data.accessToken}`, accessTokenTtl, internalToken, err =>
                    err ? reject(err) : resolve(),
                ),
            ),
            new Promise<void>((resolve, reject) =>
                this.adapter.setSession(`r:${data.refreshToken!}`, refreshTokenTtl, internalToken, err =>
                    err ? reject(err) : resolve(),
                ),
            ),
        ]);

        return data;
    };

    /**
     * Revoke an access or refresh token together with its counterpart.
     *
     * {@link revokeToken} can only drop the side it was handed, but both sessions store the full pair,
     * so a single token value is enough to invalidate the whole grant — which is what RFC 7009
     * revocation and "disconnect this app" need.
     *
     * @param token Either the access or the refresh token
     * @returns Whether a matching token was found
     */
    revokeTokenPair = async (token: string): Promise<boolean> => {
        const stored =
            (await new Promise<ioBroker.Session | null>(resolve => this.adapter.getSession(`a:${token}`, resolve))) ||
            (await new Promise<ioBroker.Session | null>(resolve => this.adapter.getSession(`r:${token}`, resolve)));

        if (!stored) {
            return false;
        }

        if (stored.aToken) {
            await this.adapter.destroySession(`a:${stored.aToken}`);
        }
        if (stored.rToken) {
            await this.adapter.destroySession(`r:${stored.rToken}`);
        }
        return true;
    };

    revokeToken = async (token: RefreshToken | Token): Promise<boolean> => {
        if (token.refreshToken) {
            await this.adapter.destroySession(`r:${token.refreshToken}`);
        }
        if (token.accessToken) {
            await this.adapter.destroySession(`a:${token.accessToken}`);
        }
        return true;
    };

    verifyScope = (_token: Token, _scope: Scope): Promise<boolean> => {
        return Promise.resolve(true);
    };

    /**
     * Issue a new access token for internal usage.
     * E.g., node-red needs to access objects for Select ID dialog
     *
     * @param obj Message object
     */
    processMessage(obj: ioBroker.Message): boolean {
        if (obj.command === 'internalToken') {
            // Make this option adjustable
            const adapter = obj.from.replace('system.adapter.', '').replace(/\.\d+$/, '');
            if (
                (this.adapter.config as Record<string, Record<string, string>>).allowInternalAccess?.[adapter] ||
                !(this.adapter.config as Record<string, Record<string, string>>).allowInternalAccess
            ) {
                const accessTokenTtl = Date.now() + 3_600_000;

                const internalToken: ioBroker.Session = {
                    aToken: Buffer.from(randomBytes(32)).toString('base64'),
                    aExp: accessTokenTtl,
                    rToken: '',
                    rExp: 0,
                    user:
                        (this.adapter.config as Record<string, Record<string, string>>).allowInternalAccess?.[
                            adapter
                        ] || 'admin',
                };

                void this.adapter.setSession(`a:${internalToken.aToken}`, 3_600, internalToken, err => {
                    if (obj.callback) {
                        this.adapter.sendTo(
                            obj.from,
                            obj.command,
                            err
                                ? { error: err }
                                : {
                                      access_token: internalToken.aToken,
                                      token_type: 'Bearer',
                                      expires_in: 3_600,
                                      refresh_token: '',
                                      refresh_token_expires_in: 0,
                                  },
                            obj.callback,
                        );
                    }
                });
            } else {
                this.adapter.log.warn(`Unknown message ${JSON.stringify(obj)}`);
                if (obj.callback) {
                    this.adapter.sendTo(obj.from, obj.command, { error: 'not allowed' }, obj.callback);
                }
            }
            return true;
        }
        return false;
    }
}

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

// We must save both tokens, as by logout we must revoke both
export interface InternalStorageToken {
    /** Access token */
    aToken: string;
    /** According refresh token */
    rToken: string;
    /** Expiration time of the access token */
    aExp: number;
    /** Expiration time of the refresh token */
    rExp: number;
    /** User ID */
    user: string;
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
    }

    getAccessToken = async (bearerToken: string): Promise<Token | Falsey> => {
        const token = await new Promise<InternalStorageToken | null>(resolve =>
            this.adapter.getSession(`a:${bearerToken}`, resolve),
        );
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
            },
        };
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
            // If authenticated by token in query like /blabla?token=ACCESS_TOKEN
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
            // If authentication by access token in cookie
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
                // If authenticated by query like /blabla?user=USER&pass=PASS
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

    generateTokens = async (userName: string): Promise<Token> => {
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

        await this.saveToken(
            result,
            {
                id: 'ioBroker',
                grants: ['password', 'refresh_token'],
                accessTokenLifetime: this.accessTokenLifetime,
                refreshTokenLifetime: this.refreshTokenLifetime,
            },
            { id: userName },
        );

        return {
            accessToken: result.accessToken,
            accessTokenExpiresAt: result.accessTokenExpiresAt,
            refreshToken: result.refreshToken,
            refreshTokenExpiresAt: result.refreshTokenExpiresAt,
            user: { id: userName },
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
        const token = await new Promise<InternalStorageToken | null>(resolve =>
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
            },
        };
    };

    /**
     * Get user.
     */
    getUser = async (username: string, password: string): Promise<User | Falsey> => {
        const now = Date.now();
        if (this.bruteForce[username]?.errors > 4) {
            let minutes = now - this.bruteForce[username].time;
            if (this.bruteForce[username].errors < 7) {
                if (now - this.bruteForce[username].time < 60_000) {
                    minutes = 1;
                } else {
                    minutes = 0;
                }
            } else if (this.bruteForce[username].errors < 10) {
                if (now - this.bruteForce[username].time < 180_000) {
                    minutes = Math.ceil((180_000 - minutes) / 60000);
                } else {
                    minutes = 0;
                }
            } else if (this.bruteForce[username].errors < 15) {
                if (now - this.bruteForce[username].time < 600_000) {
                    minutes = Math.ceil((60_0000 - minutes) / 60_000);
                } else {
                    minutes = 0;
                }
            } else if (now - this.bruteForce[username].time < 3_600_000) {
                minutes = Math.ceil((3_600_000 - minutes) / 60_000);
            } else {
                minutes = 0;
            }

            if (minutes) {
                this.adapter.log.warn(
                    `Too many errors for "${username}". Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`,
                );
                return null;
            }
        }

        const result = await new Promise<{ success: boolean; user: string }>(resolve =>
            this.adapter.checkPassword(username, password, (success: boolean, user: string): void =>
                resolve({ success, user }),
            ),
        );
        if (!result.success) {
            this.bruteForce[username] = this.bruteForce[username] || { errors: 0 };
            this.bruteForce[username].time = new Date().getTime();
            this.bruteForce[username].errors++;
            this.adapter.log.warn(
                `Invalid password for ${username}. Wrong attempts: ${this.bruteForce[username].errors}`,
            );
            return null;
        }
        if (this.bruteForce[username]) {
            delete this.bruteForce[username];
        }
        return {
            id: result.user.replace(/^system\.user\./, ''),
        };
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

        const accessTokenTtl = Math.floor((token.accessTokenExpiresAt!.getTime() - Date.now()) / 1000);
        const refreshTokenTtl = Math.floor((token.refreshTokenExpiresAt!.getTime() - Date.now()) / 1000);

        const internalToken: InternalStorageToken = {
            aToken: token.accessToken,
            aExp: token.accessTokenExpiresAt!.getTime(),
            rToken: token.refreshToken!,
            rExp: token.refreshTokenExpiresAt!.getTime(),
            user: user.id,
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

                const internalToken: InternalStorageToken = {
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

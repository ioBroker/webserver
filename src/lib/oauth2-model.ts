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
import { randomBytes, createHash } from 'node:crypto';

interface InternalToken {
    token: string;
    exp: number;
    user: string;
}

function generateRandomToken(): string {
    const bytes = randomBytes(256);
    return createHash('sha1').update(bytes).digest('hex');
}

// ----- OAuth2Model Class -----
// This class implements the model methods required by oauth2-server.
export class OAuth2Model implements RefreshTokenModel {
    // Token lifetimes in seconds
    private readonly accessTokenLifetime: number = 60 * 60; // 1 hour
    private readonly refreshTokenLifetime: number = 60 * 60 * 24 * 30; // 30 days
    private adapter: ioBroker.Adapter;
    private readonly secure: boolean;

    /**
     * Create a OAuth2model
     *
     * @param adapter ioBroker adapter
     * @param options Options
     * @param options.accessLifetime Access token expiration in seconds
     * @param options.refreshLifeTime Refresh token expiration in seconds
     * @param options.secure Secured connection
     */
    constructor(
        adapter: ioBroker.Adapter,
        options?: {
            accessLifetime?: number;
            refreshLifeTime?: number;
            secure?: boolean;
        },
    ) {
        this.adapter = adapter;
        this.secure = options?.secure || false;
        this.accessTokenLifetime = options?.accessLifetime || this.accessTokenLifetime;
        this.refreshTokenLifetime = options?.refreshLifeTime || this.refreshTokenLifetime;
    }

    getAccessToken = async (bearerToken: string): Promise<Token | Falsey> => {
        const token = await new Promise<InternalToken | null>(resolve =>
            this.adapter.getSession(`a:${bearerToken}`, resolve),
        );
        if (!token) {
            return null;
        }

        return {
            accessToken: token.token,
            accessTokenExpiresAt: new Date(token.exp),
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
            if (_req.headers?.authorization?.startsWith('Bearer ')) {
                const token = await this.getAccessToken(_req.headers.authorization.substring(7));
                if (token) {
                    _req.user = token.user.id;
                } else {
                    res.status(401).send('Unauthorized');
                    return;
                }
            } else if (_req.headers.cookie) {
                const cookies = _req.headers.cookie.split(';').map(c => c.trim().split('='));
                const tokenCookie = cookies.find(c => c[0] === 'access_token');
                if (tokenCookie) {
                    const token = await this.getAccessToken(tokenCookie[1]);
                    if (token) {
                        _req.user = token.user.id;
                    } else {
                        // Try to get the refresh token
                        const refreshTokenCookie = cookies.find(c => c[0] === 'refresh_token');
                        if (refreshTokenCookie) {
                            const refreshToken = await this.getRefreshToken(refreshTokenCookie[1]);
                            if (refreshToken) {
                                // Update the access token
                                const newToken = await this.saveToken(
                                    {
                                        accessToken: generateRandomToken(),
                                        accessTokenExpiresAt: new Date(Date.now() + this.accessTokenLifetime * 1000),
                                        refreshToken: generateRandomToken(),
                                        refreshTokenExpiresAt: new Date(Date.now() + this.refreshTokenLifetime * 1000),
                                    },
                                    refreshToken.client,
                                    refreshToken.user,
                                );

                                if (newToken) {
                                    // Set the new access token in cookie
                                    res.cookie('refresh_token', newToken.refreshToken, {
                                        httpOnly: true, // Makes the cookie inaccessible to client-side JavaScript
                                        secure: this.secure, // Only send cookie over HTTPS
                                        expires: newToken.refreshTokenExpiresAt, // Cookie will expire in X hour
                                        sameSite: 'strict', // Prevents the browser from sending this cookie along with cross-site requests (optional)
                                    });
                                    res.cookie('access_token', newToken.accessToken, {
                                        httpOnly: true, // Makes the cookie inaccessible to client-side JavaScript
                                        secure: this.secure, // Only send cookie over HTTPS
                                        expires: newToken.refreshTokenExpiresAt, // Cookie will expire in X hour
                                        sameSite: 'strict', // Prevents the browser from sending this cookie along with cross-site requests (optional)
                                    });
                                    _req.user = newToken.user.id;
                                }
                            }
                        }
                    }
                }
            }
        }

        next();
    };

    /**
     * Get refresh token.
     */
    getRefreshToken = async (bearerToken: string): Promise<RefreshToken | Falsey> => {
        const token = await new Promise<InternalToken | null>(resolve =>
            this.adapter.getSession(`r:${bearerToken}`, resolve),
        );
        if (!token) {
            return null;
        }

        return {
            refreshToken: token.token,
            refreshTokenExpiresAt: new Date(token.exp),
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
        const result = await new Promise<{ success: boolean; user: string }>(resolve =>
            this.adapter.checkPassword(username, password, (success: boolean, user: string): void =>
                resolve({ success, user }),
            ),
        );
        if (!result.success) {
            return null;
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

        const internalAccessToken: InternalToken = {
            token: token.accessToken,
            exp: token.accessTokenExpiresAt!.getTime(),
            user: user.id,
        };
        const internalRefreshToken: InternalToken = {
            token: token.refreshToken!,
            exp: token.refreshTokenExpiresAt!.getTime(),
            user: user.id,
        };

        await Promise.all([
            new Promise<void>((resolve, reject) =>
                this.adapter.setSession(`a:${data.accessToken}`, accessTokenTtl, internalAccessToken, err =>
                    err ? reject(err) : resolve(),
                ),
            ),
            new Promise<void>((resolve, reject) =>
                this.adapter.setSession(`r:${data.refreshToken!}`, refreshTokenTtl, internalRefreshToken, err =>
                    err ? reject(err) : resolve(),
                ),
            ),
        ]);

        return data;
    };

    revokeToken = async (token: RefreshToken | Token): Promise<boolean> => {
        if (token.refreshToken) {
            await this.adapter.destroySession(`r:${token.refreshToken}`);
        } else if (token.accessToken) {
            await this.adapter.destroySession(`a:${token.accessToken}`);
        }
        return true;
    };

    verifyScope = (_token: Token, _scope: Scope): Promise<boolean> => {
        return Promise.resolve(true);
    };
}

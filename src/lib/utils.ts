import type OAuth2Server from 'oauth2-server';

interface IobrokerOauthResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    refresh_token?: string;
    refresh_token_expires_in: number;
}

/**
 * Convert oauth2 token to JSON response
 *
 * @param token the created OAuth token
 */
export function oauthTokenToResponse(token: OAuth2Server.Token): IobrokerOauthResponse {
    return {
        access_token: token.accessToken,
        token_type: 'Bearer',
        expires_in: Math.floor((token.accessTokenExpiresAt!.getTime() - Date.now()) / 1000),
        refresh_token: token.refreshToken,
        refresh_token_expires_in: Math.floor((token.refreshTokenExpiresAt!.getTime() - Date.now()) / 1000),
    };
}

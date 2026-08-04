import type OAuth2Server from 'oauth2-server';
import type { Request } from 'express';

/** Upper bound for a request body we parse ourselves. */
const MAX_BODY_SIZE = 64 * 1024;

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
        expires_in: token.accessTokenExpiresAt
            ? Math.floor((token.accessTokenExpiresAt.getTime() - Date.now()) / 1000)
            : 0,
        refresh_token: token.refreshToken,
        refresh_token_expires_in: token.refreshTokenExpiresAt
            ? Math.floor((token.refreshTokenExpiresAt.getTime() - Date.now()) / 1000)
            : 0,
    };
}

/**
 * Read and parse a request body without depending on a body parser being installed.
 *
 * Adapters differ in whether they install `body-parser` globally, so an already parsed body is used
 * when there is one, and the stream is read directly otherwise. Supports `application/json` and
 * `application/x-www-form-urlencoded`.
 *
 * @param req The incoming request
 * @returns The parsed body; an empty object when there is none
 */
export async function readRequestBody(req: Request): Promise<Record<string, any>> {
    const existing: unknown = req.body;

    if (Buffer.isBuffer(existing)) {
        return parseBody(existing.toString('utf8'), req.headers['content-type']);
    }
    if (typeof existing === 'string') {
        return parseBody(existing, req.headers['content-type']);
    }
    if (existing && typeof existing === 'object' && Object.keys(existing).length) {
        return existing as Record<string, any>;
    }
    if (req.readableEnded) {
        // A body parser already consumed the stream — an empty result is the real result.
        return (existing as Record<string, any>) || {};
    }

    const raw = await new Promise<string>((resolve, reject) => {
        let data = '';
        let size = 0;
        req.setEncoding('utf8');
        req.on('data', (chunk: string) => {
            size += Buffer.byteLength(chunk, 'utf8');
            if (size > MAX_BODY_SIZE) {
                reject(new Error('Request body too large'));
                req.destroy();
                return;
            }
            data += chunk;
        });
        req.on('end', () => resolve(data));
        req.on('error', reject);
    });

    return parseBody(raw, req.headers['content-type']);
}

/**
 * Parse a raw request body according to its content type.
 *
 * @param raw The raw body text
 * @param contentType The `Content-Type` header value
 */
function parseBody(raw: string, contentType?: string): Record<string, any> {
    if (!raw) {
        return {};
    }

    const type = (contentType || '').split(';')[0].trim().toLowerCase();
    if (type === 'application/json') {
        try {
            const parsed: unknown = JSON.parse(raw);
            return parsed && typeof parsed === 'object' ? (parsed as Record<string, any>) : {};
        } catch {
            return {};
        }
    }

    const result: Record<string, string> = {};
    for (const [key, value] of new URLSearchParams(raw).entries()) {
        result[key] = value;
    }
    return result;
}

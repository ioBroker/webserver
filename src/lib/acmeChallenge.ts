/*
 * Serves ACME HTTP-01 challenges on behalf of the acme adapter.
 *
 * The CA fetches `http://<domain>/.well-known/acme-challenge/<token>` on port
 * 80 - path and port are fixed by RFC 8555 - so on a host with a single public
 * IP that request lands on whatever adapter holds port 80, normally web or
 * admin. The acme adapter used to take the port over for the duration of an
 * order, stopping the adapter that had it, which costs a short outage and can
 * leave that adapter stopped if the order throws
 * (https://github.com/iobroker-community-adapters/ioBroker.acme/issues/85).
 *
 * Instead the acme adapter publishes its tokens in a state and whoever already
 * holds the port answers from there. Nothing is stopped, no port has to be
 * free, and it works across the hosts of a multihost installation.
 *
 * The lookup has to happen before any authentication - the CA is anonymous -
 * which is why this sits in front of the app rather than in a route.
 */

import type { IncomingMessage, ServerResponse } from 'node:http';

/** Path the CA requests. Reserved for ACME by RFC 8615, so nothing else owns it. */
export const ACME_CHALLENGE_PREFIX = '/.well-known/acme-challenge/';

/**
 * Where the acme adapter publishes. The instance number is not fixed and two
 * instances may be ordering at once, so every match is consulted.
 */
export const ACME_CHALLENGE_STATE_PATTERN = 'acme.*.info.httpChallenges';

/**
 * RFC 8555 tokens are base64url. Anything else is rejected before it can reach
 * a lookup, which keeps this unauthenticated path from turning arbitrary URLs
 * into database reads.
 */
export const ACME_TOKEN_REGEX = /^[A-Za-z0-9_-]{16,128}$/;

/** One entry of the published token map, keyed by token. */
export interface PublishedAcmeChallenge {
    /** Served verbatim as the response body: `token.thumbprint` */
    keyAuthorization: string;
    /** ms epoch after which the entry must be treated as gone */
    expires: number;
}

/**
 * Pick the challenge token out of a request URL, if it is one at all.
 *
 * @param url the raw request URL
 * @returns the token, or null when this request is not an ACME challenge
 */
export function acmeChallengeToken(url: string | undefined): string | null {
    if (!url || !url.startsWith(ACME_CHALLENGE_PREFIX)) {
        return null;
    }
    // A query string is not part of the token; the CA sends none, but a probe
    // or a proxy might.
    const token = url.slice(ACME_CHALLENGE_PREFIX.length).split(/[?#]/)[0];
    return ACME_TOKEN_REGEX.test(token) ? token : null;
}

/**
 * Look a token up in what the acme adapter currently publishes.
 *
 * Read on demand rather than kept in a subscription cache: the adapter
 * publishes a token and has the CA validate it immediately afterwards, so a
 * cache would race with the order it is meant to serve. The path is only hit a
 * handful of times per certificate.
 *
 * @param adapter the ioBroker adapter
 * @param token the token from the request URL
 * @returns the key authorization to answer with, or null
 */
export async function findAcmeChallenge(adapter: ioBroker.Adapter, token: string): Promise<string | null> {
    const states = await adapter.getForeignStatesAsync(ACME_CHALLENGE_STATE_PATTERN);
    const now = Date.now();

    for (const [id, state] of Object.entries(states || {})) {
        if (!state || typeof state.val !== 'string') {
            continue;
        }
        let published: Record<string, PublishedAcmeChallenge>;
        try {
            published = JSON.parse(state.val);
        } catch {
            adapter.log.warn(`Ignoring "${id}": published ACME challenges are not valid JSON`);
            continue;
        }
        const entry = published?.[token];
        if (entry && typeof entry.keyAuthorization === 'string' && entry.expires > now) {
            return entry.keyAuthorization;
        }
    }
    return null;
}

/**
 * Answer an ACME HTTP-01 challenge request.
 *
 * Answers only when the token is actually published. Anything else - a request
 * that is not a challenge, an unknown token, a states DB that cannot be read -
 * is reported as unhandled so the caller passes it on. Nothing an application
 * serves on that path is ever shadowed by this.
 *
 * @param adapter the ioBroker adapter
 * @param req the incoming request
 * @param res the response to write to
 * @returns true when the request was answered here
 */
export async function serveAcmeChallenge(
    adapter: ioBroker.Adapter,
    req: IncomingMessage,
    res: ServerResponse,
): Promise<boolean> {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
        return false;
    }
    const token = acmeChallengeToken(req.url);
    if (!token) {
        return false;
    }

    let keyAuthorization: string | null;
    try {
        keyAuthorization = await findAcmeChallenge(adapter, token);
    } catch (e: any) {
        adapter.log.warn(`Could not read published ACME challenges: ${e.message}`);
        return false;
    }

    if (!keyAuthorization) {
        adapter.log.debug(`No ACME challenge published for token ${token}`);
        return false;
    }

    res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': Buffer.byteLength(keyAuthorization),
        // A token is valid once and briefly - no cache in between may keep it.
        'Cache-Control': 'no-store',
    });
    res.end(req.method === 'HEAD' ? undefined : keyAuthorization);
    adapter.log.info(`Answered ACME HTTP-01 challenge for token ${token}`);
    return true;
}

/**
 * The same as express middleware, for an adapter that builds its server itself
 * instead of through `WebServer`.
 *
 * Mount it before any authentication:
 * `app.use(acmeChallengeMiddleware(adapter))`
 *
 * @param adapter the ioBroker adapter
 */
export function acmeChallengeMiddleware(
    adapter: ioBroker.Adapter,
): (req: IncomingMessage, res: ServerResponse, next: (err?: any) => void) => void {
    return (req, res, next) => {
        serveAcmeChallenge(adapter, req, res).then(served => {
            if (!served) {
                next();
            }
        }, next);
    };
}

const assert = require('node:assert');
const http = require('node:http');
const { generateKeyPairSync, createHash } = require('node:crypto');

const express = require('express');
const jwt = require('jsonwebtoken');

const { createOAuth2Server } = require('../build/lib/oauth2');

const CLIENT_ID = 'iobroker-test';
const CLIENT_SECRET = 'a-confidential-secret';
const USER_SUB = 'abc-123-sub';

/**
 * An identity provider that behaves like a real one: it publishes a discovery document and its keys,
 * hands out a code and exchanges that code for an ID token it signs itself.
 */
class FakeIdentityProvider {
    constructor() {
        const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
        this.jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };
        this.privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' });

        this.issuer = '';
        /** Query of the last call of the authorization endpoint */
        this.lastAuthQuery = null;
        /** Body of the last call of the token endpoint */
        this.lastTokenBody = null;
        /** Codes that were handed out and not used yet */
        this.codes = new Map();
        /** Claims that are put into the next ID token on top of the standard ones */
        this.extraClaims = {};

        this.server = http.createServer((req, res) => this.#handle(req, res));
    }

    async start() {
        await new Promise(resolve => this.server.listen(0, '127.0.0.1', resolve));
        this.issuer = `http://127.0.0.1:${this.server.address().port}`;
        return this.issuer;
    }

    async stop() {
        await new Promise(resolve => this.server.close(resolve));
    }

    #handle(req, res) {
        const url = new URL(req.url, this.issuer);

        if (url.pathname === '/.well-known/openid-configuration') {
            res.setHeader('content-type', 'application/json');
            res.end(
                JSON.stringify({
                    issuer: this.issuer,
                    authorization_endpoint: `${this.issuer}/auth`,
                    token_endpoint: `${this.issuer}/token`,
                    jwks_uri: `${this.issuer}/jwks`,
                }),
            );
            return;
        }

        if (url.pathname === '/jwks') {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ keys: [this.jwk] }));
            return;
        }

        if (url.pathname === '/auth') {
            this.lastAuthQuery = Object.fromEntries(url.searchParams);
            const code = `code-${Math.random().toString(36).slice(2)}`;
            this.codes.set(code, {
                nonce: url.searchParams.get('nonce'),
                challenge: url.searchParams.get('code_challenge'),
            });
            const back = new URL(url.searchParams.get('redirect_uri'));
            back.searchParams.set('code', code);
            back.searchParams.set('state', url.searchParams.get('state'));
            res.writeHead(302, { location: back.href }).end();
            return;
        }

        if (url.pathname === '/token' && req.method === 'POST') {
            let body = '';
            req.on('data', chunk => (body += chunk));
            req.on('end', () => {
                const params = new URLSearchParams(body);
                this.lastTokenBody = Object.fromEntries(params);

                const entry = this.codes.get(params.get('code'));
                if (!entry) {
                    res.writeHead(400).end('unknown code');
                    return;
                }
                this.codes.delete(params.get('code'));

                // A public client has to prove with PKCE that the code belongs to it
                if (entry.challenge) {
                    const verifier = params.get('code_verifier') || '';
                    if (createHash('sha256').update(verifier).digest('base64url') !== entry.challenge) {
                        res.writeHead(400).end('bad PKCE verifier');
                        return;
                    }
                }

                const idToken = jwt.sign({ sub: USER_SUB, nonce: entry.nonce, ...this.extraClaims }, this.privatePem, {
                    algorithm: 'RS256',
                    keyid: 'test-key',
                    issuer: this.issuer,
                    audience: CLIENT_ID,
                    expiresIn: '5m',
                });

                res.setHeader('content-type', 'application/json');
                res.end(
                    JSON.stringify({
                        access_token: 'a',
                        refresh_token: 'r',
                        token_type: 'Bearer',
                        id_token: idToken,
                    }),
                );
            });
            return;
        }

        res.writeHead(404).end('not found');
    }
}

/**
 * The parts of an adapter that the single sign-on uses
 *
 * @param linkedUsers user ID to the `sub` of the identity it is connected with
 */
function createAdapter(linkedUsers) {
    const logged = [];

    return {
        logged,
        namespace: 'admin.0',
        log: {
            debug: m => logged.push(['debug', m]),
            info: m => logged.push(['info', m]),
            warn: m => logged.push(['warn', m]),
            error: m => logged.push(['error', m]),
        },
        getObjectViewAsync: async () => ({
            rows: Object.entries(linkedUsers).map(([id, sub]) => ({
                id,
                value: { common: { externalAuthentication: { oidc: { sub } } } },
            })),
        }),
        getForeignObjectAsync: async id => ({
            _id: id,
            type: 'user',
            common: { name: id.split('.').pop() },
            native: {},
        }),
        extendForeignObjectAsync: async (id, obj) => {
            linkedUsers[id] = obj.common.externalAuthentication.oidc.sub;
        },
    };
}

/**
 * An express app with the OAuth2 server on it
 *
 * @param adapter the adapter the server works with
 * @param oidc the identity provider configuration, or undefined for no single sign-on
 */
async function startApp(adapter, oidc) {
    const app = express();
    const model = createOAuth2Server(adapter, { app, oidc });

    // Issuing a real token needs the object database, which is not what these tests are about
    model.generateTokens = async userId => ({
        accessToken: `access-for-${userId}`,
        refreshToken: 'refresh',
        accessTokenExpiresAt: new Date(Date.now() + 3_600_000),
        refreshTokenExpiresAt: new Date(Date.now() + 7_200_000),
        client: { id: 'ioBroker' },
        user: { id: userId },
    });

    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });

    return {
        base: `http://127.0.0.1:${server.address().port}`,
        stop: () => new Promise(resolve => server.close(resolve)),
    };
}

describe('single sign-on with OpenID Connect', function () {
    this.timeout(20_000);

    /** @type {FakeIdentityProvider} */
    let idp;
    let issuer;

    before(async () => {
        idp = new FakeIdentityProvider();
        issuer = await idp.start();
    });

    after(async () => {
        await idp.stop();
    });

    describe('without a configuration', () => {
        it('does not offer the routes at all', async () => {
            const app = await startApp(createAdapter({}), undefined);
            try {
                const res = await fetch(`${app.base}/sso?method=login&redirectUrl=${app.base}/`, {
                    redirect: 'manual',
                });
                assert.strictEqual(res.status, 404);
            } finally {
                await app.stop();
            }
        });

        it('ignores a configuration without a client ID', async () => {
            const app = await startApp(createAdapter({}), { issuer, clientId: '' });
            try {
                const res = await fetch(`${app.base}/sso`, { redirect: 'manual' });
                assert.strictEqual(res.status, 404);
            } finally {
                await app.stop();
            }
        });
    });

    describe('with a configured identity provider', () => {
        let app;
        let linkedUsers;
        let adapter;

        /**
         * Walk through a complete login: start it, let the identity provider answer and come back
         *
         * @param query query for `/sso`
         */
        async function runFlow(query) {
            const start = await fetch(`${app.base}/sso?${query}`, { redirect: 'manual' });
            assert.strictEqual(start.status, 302, `/sso answered with ${start.status}`);

            const auth = await fetch(start.headers.get('location'), { redirect: 'manual' });
            assert.strictEqual(auth.status, 302, `the identity provider answered with ${auth.status}`);

            return fetch(auth.headers.get('location'), { redirect: 'manual' });
        }

        beforeEach(async () => {
            linkedUsers = {};
            adapter = createAdapter(linkedUsers);
            app = await startApp(adapter, { issuer, clientId: CLIENT_ID });
        });

        afterEach(async () => {
            await app.stop();
        });

        it('connects an existing ioBroker user with the identity', async () => {
            const res = await runFlow(
                `method=register&user=admin&redirectUrl=${encodeURIComponent(`${app.base}/#tab-users`)}`,
            );

            assert.strictEqual(linkedUsers['system.user.admin'], USER_SUB);
            assert.strictEqual(res.status, 302);
            assert.ok(
                res.headers.get('location').includes('id_token='),
                `the ID token is handed back: ${res.headers.get('location')}`,
            );
        });

        it('signs a connected user in', async () => {
            linkedUsers['system.user.admin'] = USER_SUB;

            const res = await runFlow(`method=login&redirectUrl=${encodeURIComponent(`${app.base}/#tab-intro`)}`);

            assert.strictEqual(res.status, 302);
            assert.ok(
                res.headers.get('location').includes('ssoLoginResponse'),
                `the token is handed back: ${res.headers.get('location')}`,
            );
            assert.ok(
                (res.headers.get('set-cookie') || '').includes('access_token=access-for-system.user.admin'),
                `the cookie is set: ${res.headers.get('set-cookie')}`,
            );
        });

        it('signs nobody in for an identity that belongs to no ioBroker user', async () => {
            const res = await runFlow(`method=login&redirectUrl=${encodeURIComponent(`${app.base}/#tab-intro`)}`);

            assert.ok(!(res.headers.get('location') || '').includes('ssoLoginResponse'));
            assert.ok(
                adapter.logged.some(([level, m]) => level === 'warn' && m.includes('no ioBroker user is connected')),
                `it is written to the log: ${JSON.stringify(adapter.logged)}`,
            );
        });

        it('asks for the scopes and sends a nonce', async () => {
            await runFlow(`method=login&redirectUrl=${encodeURIComponent(`${app.base}/`)}`);

            assert.strictEqual(idp.lastAuthQuery.scope, 'openid profile email');
            assert.ok(idp.lastAuthQuery.nonce, 'a nonce is sent along');
            assert.strictEqual(idp.lastAuthQuery.response_type, 'code');
            assert.strictEqual(idp.lastAuthQuery.client_id, CLIENT_ID);
        });

        it('uses PKCE for a public client', async () => {
            await runFlow(`method=login&redirectUrl=${encodeURIComponent(`${app.base}/`)}`);

            assert.strictEqual(idp.lastAuthQuery.code_challenge_method, 'S256');
            assert.ok(idp.lastAuthQuery.code_challenge, 'a challenge is sent along');
            assert.ok(idp.lastTokenBody.code_verifier, 'the verifier is sent to the token endpoint');
            assert.ok(!idp.lastTokenBody.client_secret, 'a public client has no secret to send');
        });

        it('refuses a redirect to a foreign host', async () => {
            const res = await fetch(`${app.base}/sso?method=login&redirectUrl=https://evil.example.com/`, {
                redirect: 'manual',
            });

            assert.strictEqual(res.status, 400);
        });

        it('refuses a state it did not hand out', async () => {
            const res = await fetch(`${app.base}/sso-callback?code=x&state=made-up`, { redirect: 'manual' });

            assert.strictEqual(res.status, 400);
        });

        it('accepts a state only once', async () => {
            const start = await fetch(
                `${app.base}/sso?method=login&redirectUrl=${encodeURIComponent(`${app.base}/`)}`,
                {
                    redirect: 'manual',
                },
            );
            const state = new URL(start.headers.get('location')).searchParams.get('state');

            const auth = await fetch(start.headers.get('location'), { redirect: 'manual' });
            await fetch(auth.headers.get('location'), { redirect: 'manual' });

            const again = await fetch(`${app.base}/sso-callback?code=whatever&state=${encodeURIComponent(state)}`, {
                redirect: 'manual',
            });

            assert.strictEqual(again.status, 400);
        });

        it('refuses a register request without a user', async () => {
            const res = await fetch(`${app.base}/sso?method=register&redirectUrl=${encodeURIComponent(app.base)}`, {
                redirect: 'manual',
            });

            assert.strictEqual(res.status, 400);
        });
    });

    describe('with a confidential client', () => {
        it('sends the client secret instead of a PKCE verifier', async () => {
            const linkedUsers = { 'system.user.admin': USER_SUB };
            const app = await startApp(createAdapter(linkedUsers), {
                issuer,
                clientId: CLIENT_ID,
                clientSecret: CLIENT_SECRET,
                scope: 'openid email',
            });

            try {
                const start = await fetch(
                    `${app.base}/sso?method=login&redirectUrl=${encodeURIComponent(`${app.base}/`)}`,
                    { redirect: 'manual' },
                );
                const auth = await fetch(start.headers.get('location'), { redirect: 'manual' });
                await fetch(auth.headers.get('location'), { redirect: 'manual' });

                assert.strictEqual(idp.lastAuthQuery.scope, 'openid email', 'the configured scopes are used');
                assert.ok(!idp.lastAuthQuery.code_challenge, 'a confidential client needs no PKCE');
                assert.strictEqual(idp.lastTokenBody.client_secret, CLIENT_SECRET);
            } finally {
                await app.stop();
            }
        });
    });

    describe('with an identity provider that cannot be reached', () => {
        it('answers with 502 instead of sending the browser nowhere', async () => {
            const app = await startApp(createAdapter({}), {
                issuer: 'http://127.0.0.1:1/not-there',
                clientId: CLIENT_ID,
            });

            try {
                const res = await fetch(`${app.base}/sso?method=login&redirectUrl=${encodeURIComponent(app.base)}`, {
                    redirect: 'manual',
                });

                assert.strictEqual(res.status, 502);
            } finally {
                await app.stop();
            }
        });
    });
});

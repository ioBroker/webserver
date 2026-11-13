const assert = require('node:assert');

const { createHash, randomBytes } = require('node:crypto');

const express = require('express');

const { createOAuth2Server } = require('../build/lib/oauth2');
const { base32Decode, base32Encode, hotp, totpStep, findTotpStep } = require('../build/lib/totp');

const PASSWORDS = { admin: 'admin-pass', bob: 'bob-pass', eve: 'eve-pass' };

/**
 * The parts of an adapter that the login and the two-factor authentication use: users with passwords,
 * an object database, the session database and an encryption that is good enough for a test
 */
function createAdapter() {
    const logged = [];
    const sessions = new Map();
    const objects = {
        'system.group.administrator': {
            _id: 'system.group.administrator',
            type: 'group',
            common: { name: 'Administrator', members: ['system.user.admin'] },
            native: {},
        },
    };
    for (const name of Object.keys(PASSWORDS)) {
        objects[`system.user.${name}`] = {
            _id: `system.user.${name}`,
            type: 'user',
            common: { name, enabled: true },
            native: {},
        };
    }

    return {
        logged,
        objects,
        namespace: 'admin.0',
        log: {
            debug: m => logged.push(['debug', m]),
            info: m => logged.push(['info', m]),
            warn: m => logged.push(['warn', m]),
            error: m => logged.push(['error', m]),
        },
        checkPassword: (user, password, callback) => {
            const name = user.replace(/^system\.user\./, '').toLowerCase();
            callback(PASSWORDS[name] === password, `system.user.${name}`);
        },
        getForeignObjectAsync: async id => (objects[id] ? JSON.parse(JSON.stringify(objects[id])) : null),
        setForeignObjectAsync: async (id, obj) => {
            objects[id] = JSON.parse(JSON.stringify(obj));
            return { id };
        },
        getObjectListAsync: async ({ startkey, endkey }) => ({
            rows: Object.keys(objects)
                .filter(id => id >= startkey && id <= endkey)
                .map(id => ({ id, value: objects[id] })),
        }),
        delForeignObjectAsync: async id => {
            delete objects[id];
        },
        encrypt: value => `enc:${Buffer.from(value).toString('base64')}`,
        decrypt: value => Buffer.from(value.replace(/^enc:/, ''), 'base64').toString(),
        setSession: (id, _ttl, data, callback) => {
            sessions.set(id, data);
            callback?.();
        },
        getSession: (id, callback) => callback(sessions.get(id) || null),
        destroySession: (id, callback) => {
            sessions.delete(id);
            callback?.();
        },
    };
}

async function startApp(adapter, options = {}) {
    const app = express();
    app.use(express.urlencoded({ extended: false }));
    createOAuth2Server(adapter, { app, ...options });
    app.get('/protected', (req, res) => res.json({ user: req.user || null }));

    const server = await new Promise(resolve => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    return {
        base: `http://127.0.0.1:${server.address().port}`,
        stop: () => new Promise(resolve => server.close(resolve)),
    };
}

/** Code of the authenticator app for a secret, `offset` steps from now */
function codeFor(secret, offset = 0) {
    return hotp(base32Decode(secret), totpStep() + offset);
}

describe('two-factor authentication (TOTP)', function () {
    describe('the algorithm', () => {
        it('gives the values of RFC 6238', () => {
            const key = Buffer.from('12345678901234567890');
            assert.strictEqual(base32Encode(key), 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
            // test vectors of RFC 6238, appendix B, for SHA-1
            assert.strictEqual(hotp(key, Math.floor(59 / 30), 8), '94287082');
            assert.strictEqual(hotp(key, Math.floor(1111111109 / 30), 8), '07081804');
            assert.strictEqual(hotp(key, Math.floor(2000000000 / 30), 8), '69279037');
            assert.strictEqual(hotp(key, Math.floor(59 / 30)), '287082');
        });

        it('decodes what it encodes', () => {
            for (let length = 1; length < 40; length++) {
                const data = Buffer.from(Array.from({ length }, (_, i) => (i * 37 + length) & 255));
                assert.deepStrictEqual(base32Decode(base32Encode(data)), data);
            }
            assert.deepStrictEqual(base32Decode('gezd gnbv-gy3t'), base32Decode('GEZDGNBVGY3T'));
        });

        it('accepts one step before and after, but not more', () => {
            const secret = base32Encode(Buffer.from('12345678901234567890'));
            const now = 1_700_000_000_000;
            const step = totpStep(now);
            const key = base32Decode(secret);
            assert.strictEqual(findTotpStep(secret, hotp(key, step), now), step);
            assert.strictEqual(findTotpStep(secret, hotp(key, step - 1), now), step - 1);
            assert.strictEqual(findTotpStep(secret, hotp(key, step + 1), now), step + 1);
            assert.strictEqual(findTotpStep(secret, hotp(key, step + 2), now), null);
            assert.strictEqual(findTotpStep(secret, 'abcdef', now), null);
        });
    });

    describe('login and setup', () => {
        let adapter;
        let app;

        beforeEach(async () => {
            adapter = createAdapter();
            app = await startApp(adapter);
        });

        afterEach(async () => {
            await app.stop();
        });

        async function login(user, password, otp) {
            const params = new URLSearchParams({
                grant_type: 'password',
                username: user,
                password,
                client_id: 'ioBroker',
            });
            if (otp !== undefined) {
                params.set('otp', otp);
            }
            const res = await fetch(`${app.base}/oauth/token`, {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: params.toString(),
            });
            return { status: res.status, body: await res.json() };
        }

        async function call(method, path, token, body) {
            const res = await fetch(`${app.base}${path}`, {
                method,
                headers: {
                    authorization: `Bearer ${token}`,
                    ...(body ? { 'content-type': 'application/json' } : {}),
                },
                body: body ? JSON.stringify(body) : undefined,
            });
            return { status: res.status, body: await res.json() };
        }

        /** Switch the second factor on for a user and give back the secret and the backup codes */
        async function enable(user) {
            const { body: tokens } = await login(user, PASSWORDS[user]);
            const setup = await call('POST', '/2fa/setup', tokens.access_token, {});
            assert.strictEqual(setup.status, 200);
            assert.match(setup.body.uri, /^otpauth:\/\/totp\/ioBroker:/);
            const enabled = await call('POST', '/2fa/enable', tokens.access_token, {
                code: codeFor(setup.body.secret),
            });
            assert.strictEqual(enabled.status, 200);
            assert.strictEqual(enabled.body.backupCodes.length, 10);
            return { secret: setup.body.secret, backupCodes: enabled.body.backupCodes, token: tokens.access_token };
        }

        it('logs in with the password alone while the second factor is off', async () => {
            const result = await login('bob', PASSWORDS.bob);
            assert.strictEqual(result.status, 200);
            assert.ok(result.body.access_token);

            const wrong = await login('bob', 'wrong');
            assert.strictEqual(wrong.status, 400);
            assert.strictEqual(wrong.body.name, 'invalid_grant');
        });

        it('stores the secret encrypted and only hashes of the backup codes', async () => {
            const { secret, backupCodes } = await enable('bob');
            const stored = adapter.objects['system.user.bob'].common.externalAuthentication.totp;
            assert.notStrictEqual(stored.secret, secret);
            assert.strictEqual(adapter.decrypt(stored.secret), secret);
            assert.ok(!stored.backupCodes.includes(backupCodes[0]));
        });

        it('does not switch on with a wrong code', async () => {
            const { body: tokens } = await login('bob', PASSWORDS.bob);
            await call('POST', '/2fa/setup', tokens.access_token, {});
            const result = await call('POST', '/2fa/enable', tokens.access_token, { code: '000000' });
            assert.strictEqual(result.status, 400);
            assert.strictEqual(adapter.objects['system.user.bob'].common.externalAuthentication, undefined);
        });

        it('asks for the code and checks it', async () => {
            const { secret } = await enable('bob');

            const required = await login('bob', PASSWORDS.bob);
            assert.strictEqual(required.status, 401);
            assert.strictEqual(required.body.error, 'otp_required');

            // a wrong password still gets the usual answer, so it does not tell that the user has a second factor
            const wrong = await login('bob', 'wrong', '');
            assert.strictEqual(wrong.status, 400);
            assert.strictEqual(wrong.body.name, 'invalid_grant');

            const invalid = await login('bob', PASSWORDS.bob, '123456');
            assert.strictEqual(invalid.status, 401);
            assert.strictEqual(invalid.body.error, 'otp_invalid');

            // the code of the current step was used to switch it on, the next one is accepted too
            const ok = await login('bob', PASSWORDS.bob, codeFor(secret, 1));
            assert.strictEqual(ok.status, 200);
            assert.ok(ok.body.access_token);

            const replay = await login('bob', PASSWORDS.bob, codeFor(secret, 1));
            assert.strictEqual(replay.status, 401);
            assert.strictEqual(replay.body.error, 'otp_invalid');
        });

        it('accepts every backup code once', async () => {
            const { backupCodes } = await enable('bob');

            const ok = await login('bob', PASSWORDS.bob, backupCodes[3].toLowerCase());
            assert.strictEqual(ok.status, 200);

            const again = await login('bob', PASSWORDS.bob, backupCodes[3]);
            assert.strictEqual(again.status, 401);

            const status = await call('GET', '/2fa/status', ok.body.access_token);
            assert.deepStrictEqual(
                { enabled: status.body.enabled, backupCodes: status.body.backupCodes },
                { enabled: true, backupCodes: 9 },
            );
        });

        it('refuses basic authentication and a password in the URL for users with a second factor', async () => {
            const basic = `Basic ${Buffer.from(`eve:${PASSWORDS.eve}`).toString('base64')}`;
            let res = await fetch(`${app.base}/protected`, { headers: { authorization: basic } });
            assert.deepStrictEqual(await res.json(), { user: 'eve' });

            await enable('eve');

            res = await fetch(`${app.base}/protected`, { headers: { authorization: basic } });
            assert.strictEqual(res.status, 401);
            res = await fetch(`${app.base}/protected?user=eve&pass=${PASSWORDS.eve}`);
            assert.strictEqual(res.status, 401);
        });

        it('blocks guessing of codes even with the right password', async () => {
            const { secret } = await enable('bob');
            for (let i = 0; i < 5; i++) {
                const result = await login('bob', PASSWORDS.bob, '000000');
                assert.strictEqual(result.status, 401);
            }
            const blocked = await login('bob', PASSWORDS.bob, codeFor(secret, 1));
            assert.strictEqual(blocked.status, 400);
        });

        it('lets the user switch it off only with a code', async () => {
            const { secret, token } = await enable('bob');

            let result = await call('POST', '/2fa/disable', token, { code: '000000' });
            assert.strictEqual(result.status, 400);
            result = await call('POST', '/2fa/disable', token, { code: codeFor(secret, 1) });
            assert.strictEqual(result.status, 200);
            assert.strictEqual(adapter.objects['system.user.bob'].common.externalAuthentication.totp, undefined);

            const plain = await login('bob', PASSWORDS.bob);
            assert.strictEqual(plain.status, 200);
        });

        it('lets only administrators switch it off for others', async () => {
            await enable('bob');
            const { body: eve } = await login('eve', PASSWORDS.eve);
            const { body: admin } = await login('admin', PASSWORDS.admin);

            let result = await call('POST', '/2fa/disable', eve.access_token, { user: 'bob' });
            assert.strictEqual(result.status, 403);
            result = await call('GET', '/2fa/status?user=bob', eve.access_token);
            assert.strictEqual(result.status, 403);

            result = await call('GET', '/2fa/status?user=bob', admin.access_token);
            assert.strictEqual(result.body.enabled, true);
            result = await call('POST', '/2fa/disable', admin.access_token, { user: 'system.user.bob' });
            assert.strictEqual(result.status, 200);
            assert.strictEqual(adapter.objects['system.user.bob'].common.externalAuthentication.totp, undefined);
        });

        it('takes only JSON for changes', async () => {
            const { body: tokens } = await login('bob', PASSWORDS.bob);
            const res = await fetch(`${app.base}/2fa/setup`, {
                method: 'POST',
                headers: {
                    authorization: `Bearer ${tokens.access_token}`,
                    'content-type': 'application/x-www-form-urlencoded',
                },
                body: '',
            });
            assert.strictEqual(res.status, 415);
        });
    });

    describe('login page of the authorization code flow', () => {
        let adapter;
        let app;

        beforeEach(async () => {
            adapter = createAdapter();
            app = await startApp(adapter, { authorizationCode: true, baseUrl: 'http://127.0.0.1' });
        });

        afterEach(async () => {
            await app.stop();
        });

        async function post(form) {
            const res = await fetch(`${app.base}/oauth/authorize`, {
                method: 'POST',
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams(form).toString(),
                redirect: 'manual',
            });
            return { status: res.status, location: res.headers.get('location'), text: await res.text() };
        }

        it('asks for the code after the password and only then for the consent', async () => {
            // switch the second factor on directly in the database, as the setup is tested above
            const secret = base32Encode(randomBytes(20));
            adapter.objects['system.user.bob'].common.externalAuthentication = {
                totp: { secret: adapter.encrypt(secret), backupCodes: [], created: Date.now() },
            };

            const redirectUri = 'http://127.0.0.1:9/callback';
            const registered = await fetch(`${app.base}/oauth/register`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ client_name: 'Test', redirect_uris: [redirectUri] }),
            }).then(res => res.json());

            const verifier = randomBytes(32).toString('base64url');
            const query = new URLSearchParams({
                response_type: 'code',
                client_id: registered.client_id,
                redirect_uri: redirectUri,
                code_challenge: createHash('sha256').update(verifier).digest('base64url'),
                code_challenge_method: 'S256',
                state: 'xyz',
            });
            const page = await fetch(`${app.base}/oauth/authorize?${query}`).then(res => res.text());
            const requestId = page.match(/name="request_id" value="([^"]+)"/)[1];

            let result = await post({
                request_id: requestId,
                action: 'login',
                username: 'bob',
                password: PASSWORDS.bob,
            });
            assert.match(result.text, /Two-factor authentication/);
            assert.doesNotMatch(result.text, /Allow access/);

            // without the code there is no consent and no authorization code
            result = await post({ request_id: requestId, action: 'allow' });
            assert.match(result.text, /Please log in first/);

            result = await post({ request_id: requestId, action: 'otp', otp: '000000' });
            assert.match(result.text, /Wrong code/);

            result = await post({ request_id: requestId, action: 'otp', otp: codeFor(secret) });
            assert.match(result.text, /Allow access/);

            result = await post({ request_id: requestId, action: 'allow' });
            assert.strictEqual(result.status, 302);
            assert.match(result.location, /^http:\/\/127\.0\.0\.1:9\/callback\?code=/);
        });
    });
});

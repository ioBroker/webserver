import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Two-factor authentication with an authenticator app (TOTP, RFC 6238).
 *
 * The secret is stored encrypted with the system secret in the user object under
 * `common.externalAuthentication.totp`, so that admin and web (and every other adapter that uses this
 * package) share it. Only hashes of the backup codes are stored.
 */

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
/** Every authenticator app uses these values, most of them cannot use others */
const PERIOD_SEC = 30;
const DIGITS = 6;
/** One step before and after the current one is accepted, for clocks that are a bit off */
const WINDOW = 1;
const BACKUP_CODE_COUNT = 10;
/** How long a started setup waits for the first code */
const SETUP_TTL_MS = 10 * 60_000;

/** What is stored in `common.externalAuthentication.totp` of a user */
export interface StoredTotp {
    /** The secret in base32, encrypted with the system secret */
    secret: string;
    /** SHA-256 of the backup codes that are not used yet */
    backupCodes: string[];
    /** When the two-factor authentication was switched on */
    created: number;
    /** Time step of the last code that was accepted: a code cannot be used twice */
    lastStep?: number;
}

/**
 * Encode bytes in base32 (RFC 4648) without padding, as authenticator apps expect the secret
 *
 * @param data bytes to encode
 */
export function base32Encode(data: Buffer): string {
    let bits = 0;
    let value = 0;
    let result = '';
    for (const byte of data) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            result += BASE32[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
        // keep only the bits that are not used yet, or `value` overflows after a few bytes
        value &= (1 << bits) - 1;
    }
    if (bits > 0) {
        result += BASE32[(value << (5 - bits)) & 31];
    }
    return result;
}

/**
 * Decode base32 (RFC 4648); spaces, dashes and padding are ignored, the case does not matter
 *
 * @param text base32 text
 */
export function base32Decode(text: string): Buffer {
    const clean = text.toUpperCase().replace(/[\s=-]/g, '');
    let bits = 0;
    let value = 0;
    const bytes: number[] = [];
    for (const char of clean) {
        const index = BASE32.indexOf(char);
        if (index === -1) {
            throw new Error(`Invalid base32 character "${char}"`);
        }
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
        value &= (1 << bits) - 1;
    }
    return Buffer.from(bytes);
}

/** A new random secret (160 bits, as recommended by RFC 4226) in base32 */
export function generateTotpSecret(): string {
    return base32Encode(randomBytes(20));
}

/**
 * HOTP value (RFC 4226) of a counter
 *
 * @param key the secret as bytes
 * @param counter the counter, for TOTP the time step
 * @param digits number of digits
 */
export function hotp(key: Buffer, counter: number, digits = DIGITS): string {
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = createHmac('sha1', key).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = hmac.readUInt32BE(offset) & 0x7fffffff;
    return (binary % 10 ** digits).toString().padStart(digits, '0');
}

/**
 * Time step of a moment
 *
 * @param now milliseconds since 1970
 */
export function totpStep(now = Date.now()): number {
    return Math.floor(now / 1000 / PERIOD_SEC);
}

/**
 * Find the time step a code belongs to, or null if the code is wrong
 *
 * @param secret secret in base32
 * @param code the code the user typed
 * @param now milliseconds since 1970
 */
export function findTotpStep(secret: string, code: string, now = Date.now()): number | null {
    if (!new RegExp(`^\\d{${DIGITS}}$`).test(code)) {
        return null;
    }
    const key = base32Decode(secret);
    const step = totpStep(now);
    let found: number | null = null;
    // All steps are compared, so that the time does not tell which one matched
    for (let i = -WINDOW; i <= WINDOW; i++) {
        if (safeEqual(hotp(key, step + i), code)) {
            found = step + i;
        }
    }
    return found;
}

/**
 * Address for the QR code, which the authenticator app reads
 *
 * @param secret secret in base32
 * @param user ioBroker user name
 * @param issuer name shown in the app
 */
export function totpUri(secret: string, user: string, issuer = 'ioBroker'): string {
    const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(user)}`;
    return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${PERIOD_SEC}`;
}

/**
 * Normalize what the user typed: spaces and dashes are allowed, the case does not matter
 *
 * @param code the code as typed
 */
function normalizeCode(code: string): string {
    return code.toUpperCase().replace(/[\s-]/g, '');
}

function hashBackupCode(code: string): string {
    return createHash('sha256').update(normalizeCode(code)).digest('hex');
}

function safeEqual(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    return bufA.length === bufB.length && timingSafeEqual(bufA, bufB);
}

/** New backup codes like `K7QF2-M4XPA`, 50 random bits each */
export function generateBackupCodes(count = BACKUP_CODE_COUNT): string[] {
    const codes: string[] = [];
    for (let i = 0; i < count; i++) {
        const text = base32Encode(randomBytes(7)).substring(0, 10);
        codes.push(`${text.substring(0, 5)}-${text.substring(5)}`);
    }
    return codes;
}

/**
 * The ioBroker user name without the `system.user.` prefix, in lower case as js-controller stores it
 *
 * @param user user name or ID
 */
export function shortUserName(user: string): string {
    return user.replace(/^system\.user\./, '').toLowerCase();
}

/**
 * Two-factor authentication of the users of one adapter
 */
export class SecondFactor {
    private readonly adapter: ioBroker.Adapter;
    /** Started setups: user to the secret that waits for its first code */
    private readonly pending = new Map<string, { secret: string; expires: number }>();

    /**
     * @param adapter the adapter whose object database holds the users
     */
    constructor(adapter: ioBroker.Adapter) {
        this.adapter = adapter;
    }

    private async getUserObject(user: string): Promise<ioBroker.UserObject | null> {
        try {
            const obj = await this.adapter.getForeignObjectAsync(`system.user.${shortUserName(user)}`);
            return obj?.type === 'user' ? obj : null;
        } catch {
            return null;
        }
    }

    private static getStored(obj: ioBroker.UserObject | null): StoredTotp | null {
        const stored = obj?.common?.externalAuthentication?.totp as StoredTotp | undefined;
        return stored?.secret ? stored : null;
    }

    private async store(user: string, stored: StoredTotp | null): Promise<void> {
        const obj = await this.getUserObject(user);
        if (!obj) {
            throw new Error(`User "${user}" not found`);
        }
        obj.common.externalAuthentication ||= {};
        if (stored) {
            obj.common.externalAuthentication.totp = stored;
        } else {
            delete obj.common.externalAuthentication.totp;
        }
        await this.adapter.setForeignObjectAsync(obj._id, obj);
    }

    /**
     * Whether the user has to give a code at login
     *
     * @param user user name or ID
     */
    async isEnabled(user: string): Promise<boolean> {
        return !!SecondFactor.getStored(await this.getUserObject(user));
    }

    /**
     * Status for the settings page of the user
     *
     * @param user user name or ID
     */
    async getStatus(user: string): Promise<{ enabled: boolean; backupCodes: number; created?: number }> {
        const stored = SecondFactor.getStored(await this.getUserObject(user));
        return stored
            ? { enabled: true, backupCodes: stored.backupCodes?.length || 0, created: stored.created }
            : { enabled: false, backupCodes: 0 };
    }

    /**
     * Check a code from the authenticator app or one of the backup codes. A backup code is gone after use,
     * and a code of the app is not accepted a second time.
     *
     * @param user user name or ID
     * @param code what the user typed
     */
    async verify(user: string, code: string): Promise<boolean> {
        const obj = await this.getUserObject(user);
        const stored = SecondFactor.getStored(obj);
        if (!stored || typeof code !== 'string') {
            return false;
        }
        const normalized = normalizeCode(code);

        if (/^\d+$/.test(normalized)) {
            let secret: string;
            try {
                secret = this.adapter.decrypt(stored.secret);
            } catch (e) {
                this.adapter.log.error(`2FA: cannot decrypt the secret of "${user}": ${(e as Error).message}`);
                return false;
            }
            const step = findTotpStep(secret, normalized);
            if (step === null || (stored.lastStep !== undefined && step <= stored.lastStep)) {
                return false;
            }
            stored.lastStep = step;
            await this.store(user, stored);
            return true;
        }

        const hash = hashBackupCode(normalized);
        const index = (stored.backupCodes || []).findIndex(item => safeEqual(item, hash));
        if (index === -1) {
            return false;
        }
        stored.backupCodes.splice(index, 1);
        await this.store(user, stored);
        this.adapter.log.info(
            `2FA: "${user}" logged in with a backup code, ${stored.backupCodes.length} backup codes left`,
        );
        return true;
    }

    /**
     * Start the setup: a new secret, which is only stored after the first correct code
     *
     * @param user user name or ID
     * @param issuer name shown in the authenticator app
     */
    startSetup(user: string, issuer = 'ioBroker'): { secret: string; uri: string } {
        const now = Date.now();
        for (const [name, entry] of this.pending) {
            if (entry.expires < now) {
                this.pending.delete(name);
            }
        }
        const secret = generateTotpSecret();
        this.pending.set(shortUserName(user), { secret, expires: now + SETUP_TTL_MS });
        return { secret, uri: totpUri(secret, shortUserName(user), issuer) };
    }

    /**
     * Finish the setup with the first code from the app. Returns the backup codes, which are shown once,
     * or null if the code is wrong or the setup expired.
     *
     * @param user user name or ID
     * @param code the code from the authenticator app
     */
    async finishSetup(user: string, code: string): Promise<string[] | null> {
        const name = shortUserName(user);
        const pending = this.pending.get(name);
        if (!pending || pending.expires < Date.now() || typeof code !== 'string') {
            return null;
        }
        const step = findTotpStep(pending.secret, normalizeCode(code));
        if (step === null) {
            return null;
        }
        this.pending.delete(name);

        const backupCodes = generateBackupCodes();
        await this.store(name, {
            secret: this.adapter.encrypt(pending.secret),
            backupCodes: backupCodes.map(hashBackupCode),
            created: Date.now(),
            lastStep: step,
        });
        this.adapter.log.info(`2FA: switched on for "${name}"`);
        return backupCodes;
    }

    /**
     * New backup codes; the old ones are not valid anymore
     *
     * @param user user name or ID
     */
    async renewBackupCodes(user: string): Promise<string[]> {
        const stored = SecondFactor.getStored(await this.getUserObject(user));
        if (!stored) {
            throw new Error('Two-factor authentication is off');
        }
        const backupCodes = generateBackupCodes();
        stored.backupCodes = backupCodes.map(hashBackupCode);
        await this.store(user, stored);
        return backupCodes;
    }

    /**
     * Switch the two-factor authentication off
     *
     * @param user user name or ID
     */
    async disable(user: string): Promise<void> {
        this.pending.delete(shortUserName(user));
        await this.store(user, null);
        this.adapter.log.info(`2FA: switched off for "${shortUserName(user)}"`);
    }
}

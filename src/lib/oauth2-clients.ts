import { randomBytes } from 'node:crypto';

/**
 * Hosts for which a plain `http:` redirect URI is acceptable. Native apps receive their callback on
 * an ephemeral loopback port (RFC 8252 §7.3), so requiring TLS there would be pointless.
 */
const LOOPBACK_HOSTS = ['127.0.0.1', '::1', '[::1]', 'localhost'];

/** URI schemes that must never be accepted as a redirect target — they execute in the browser. */
const FORBIDDEN_SCHEMES = ['javascript:', 'data:', 'vbscript:', 'file:', 'blob:'];

/** How many clients we keep before the oldest dynamically registered ones are pruned. */
const DEFAULT_MAX_CLIENTS = 100;

/** Client metadata as sent by a client to the registration endpoint (RFC 7591 §2). */
export interface OAuth2ClientMetadata {
    /** Human-readable name, shown to the user on the consent page. */
    client_name?: string;
    /** Allowed callback URIs. Compared byte-for-byte at the authorization endpoint. */
    redirect_uris: string[];
    grant_types?: string[];
    response_types?: string[];
    token_endpoint_auth_method?: string;
    scope?: string;
    client_uri?: string;
    logo_uri?: string;
    software_id?: string;
    software_version?: string;
}

/** A registered OAuth2 client as stored by {@link OAuth2ClientStore}. */
export interface OAuth2Client extends OAuth2ClientMetadata {
    client_id: string;
    /** Issue time in **seconds** since the epoch (RFC 7591 uses seconds, not milliseconds). */
    client_id_issued_at: number;
    grant_types: string[];
    response_types: string[];
    /** We only support public clients with PKCE; there are no client secrets to protect. */
    token_endpoint_auth_method: 'none';
    /** True when the client registered itself dynamically instead of being configured by hand. */
    dynamic: boolean;
}

/** Error carrying an RFC 7591 §3.2.2 error code, so the registration endpoint can report it verbatim. */
export class ClientRegistrationError extends Error {
    /** RFC 7591 error code, e.g. `invalid_redirect_uri` or `invalid_client_metadata`. */
    readonly code: 'invalid_redirect_uri' | 'invalid_client_metadata';

    constructor(code: 'invalid_redirect_uri' | 'invalid_client_metadata', message: string) {
        super(message);
        this.code = code;
        this.name = 'ClientRegistrationError';
    }
}

/**
 * Validate a single redirect URI.
 *
 * Accepted are `https:` URIs, `http:` URIs pointing at the loopback interface, and private-use
 * schemes such as `myapp://callback` used by native applications. Fragments are forbidden because
 * the authorization response appends its own query parameters.
 *
 * @param uri The redirect URI to check
 * @returns An error description, or `null` when the URI is acceptable
 */
function checkRedirectUri(uri: string): string | null {
    if (typeof uri !== 'string' || !uri) {
        return 'redirect_uris must contain non-empty strings';
    }

    let parsed: URL;
    try {
        parsed = new URL(uri);
    } catch {
        return `"${uri}" is not an absolute URI`;
    }

    if (parsed.hash) {
        return `"${uri}" must not contain a fragment`;
    }

    const scheme = parsed.protocol.toLowerCase();

    if (FORBIDDEN_SCHEMES.includes(scheme)) {
        return `"${uri}" uses a forbidden scheme`;
    }

    if (scheme === 'http:') {
        // `URL` keeps IPv6 hosts in brackets, so compare against both spellings.
        if (!LOOPBACK_HOSTS.includes(parsed.hostname.toLowerCase())) {
            return `"${uri}" must use https: — plain http: is only allowed for loopback addresses`;
        }
    }

    return null;
}

/**
 * Persistent store for OAuth2 clients.
 *
 * Clients must survive an adapter restart, so they are kept as ioBroker objects under
 * `<adapter.namespace>.oauth.clients.<client_id>` rather than in the (expiring) session storage.
 * Lookups are cached in memory; the cache is only ever filled from the objects database, so a
 * client registered by another instance is still found after a cache miss.
 */
export class OAuth2ClientStore {
    private readonly adapter: ioBroker.Adapter;
    private readonly maxClients: number;
    private readonly cache = new Map<string, OAuth2Client>();

    /**
     * @param adapter ioBroker adapter used for object access and logging
     * @param options Options
     * @param options.maxClients Maximum number of stored clients before the oldest dynamic ones are pruned
     */
    constructor(adapter: ioBroker.Adapter, options?: { maxClients?: number }) {
        this.adapter = adapter;
        this.maxClients = options?.maxClients || DEFAULT_MAX_CLIENTS;
    }

    /** Object ID prefix under which all clients of this instance live. */
    private get folder(): string {
        return `${this.adapter.namespace}.oauth.clients`;
    }

    /**
     * Look up a client by its ID.
     *
     * @param clientId The `client_id` to resolve
     * @returns The stored client, or `null` when it is unknown
     */
    async get(clientId: string): Promise<OAuth2Client | null> {
        if (!clientId || !/^[a-zA-Z0-9_-]+$/.test(clientId)) {
            // Reject anything that could escape the object ID namespace before touching the database.
            return null;
        }

        const cached = this.cache.get(clientId);
        if (cached) {
            return cached;
        }

        const obj = await this.adapter.getForeignObjectAsync(`${this.folder}.${clientId}`);
        const client = obj?.native?.client as OAuth2Client | undefined;
        if (!client) {
            return null;
        }

        this.cache.set(clientId, client);
        return client;
    }

    /** List all stored clients, oldest registration first. */
    async list(): Promise<OAuth2Client[]> {
        // Query by ID range instead of by object view: the range query does not depend on a view for
        // the `config` object type existing in the objects database.
        const res = await this.adapter.getObjectListAsync({
            startkey: `${this.folder}.`,
            endkey: `${this.folder}.香`,
        });

        const clients: OAuth2Client[] = [];
        for (const row of res?.rows || []) {
            const client = row.value?.native?.client as OAuth2Client | undefined;
            if (client?.client_id) {
                clients.push(client);
            }
        }

        return clients.sort((a, b) => a.client_id_issued_at - b.client_id_issued_at);
    }

    /**
     * Register a new client from the metadata a client sent to the registration endpoint.
     *
     * The parameter is deliberately typed as partial: it carries unvalidated data straight off the
     * network, and every field is checked here before anything is stored.
     *
     * @param metadata Client metadata (RFC 7591 §2)
     * @param options Options
     * @param options.dynamic Whether this registration came in via the dynamic registration endpoint
     * @returns The stored client, including the generated `client_id`
     * @throws ClientRegistrationError when the metadata is not acceptable
     */
    async register(metadata: Partial<OAuth2ClientMetadata>, options?: { dynamic?: boolean }): Promise<OAuth2Client> {
        const redirectUris = metadata?.redirect_uris;
        if (!Array.isArray(redirectUris) || !redirectUris.length) {
            throw new ClientRegistrationError('invalid_redirect_uri', 'redirect_uris must be a non-empty array');
        }
        if (redirectUris.length > 10) {
            throw new ClientRegistrationError(
                'invalid_redirect_uri',
                'redirect_uris must not contain more than 10 entries',
            );
        }
        for (const uri of redirectUris) {
            const error = checkRedirectUri(uri);
            if (error) {
                throw new ClientRegistrationError('invalid_redirect_uri', error);
            }
        }

        // We are a public-client-only authorization server: PKCE replaces the client secret, so any
        // other authentication method would be a promise we do not keep.
        const authMethod = metadata.token_endpoint_auth_method || 'none';
        if (authMethod !== 'none') {
            throw new ClientRegistrationError(
                'invalid_client_metadata',
                `token_endpoint_auth_method "${authMethod}" is not supported, only "none" (public client with PKCE)`,
            );
        }

        const grantTypes = metadata.grant_types?.length
            ? metadata.grant_types
            : ['authorization_code', 'refresh_token'];
        const unsupported = grantTypes.filter(g => g !== 'authorization_code' && g !== 'refresh_token');
        if (unsupported.length) {
            throw new ClientRegistrationError(
                'invalid_client_metadata',
                `unsupported grant_types: ${unsupported.join(', ')}`,
            );
        }

        const responseTypes = metadata.response_types?.length ? metadata.response_types : ['code'];
        if (responseTypes.some(t => t !== 'code')) {
            throw new ClientRegistrationError('invalid_client_metadata', 'only the "code" response type is supported');
        }

        const client: OAuth2Client = {
            client_id: randomBytes(16).toString('hex'),
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_name: typeof metadata.client_name === 'string' ? metadata.client_name.slice(0, 200) : undefined,
            redirect_uris: redirectUris,
            grant_types: grantTypes,
            response_types: responseTypes,
            token_endpoint_auth_method: 'none',
            scope: typeof metadata.scope === 'string' ? metadata.scope.slice(0, 500) : undefined,
            client_uri: typeof metadata.client_uri === 'string' ? metadata.client_uri : undefined,
            logo_uri: typeof metadata.logo_uri === 'string' ? metadata.logo_uri : undefined,
            software_id: typeof metadata.software_id === 'string' ? metadata.software_id : undefined,
            software_version: typeof metadata.software_version === 'string' ? metadata.software_version : undefined,
            dynamic: options?.dynamic !== false,
        };

        await this.adapter.setForeignObjectAsync(`${this.folder}.${client.client_id}`, {
            type: 'config',
            common: {
                name: client.client_name || client.client_id,
            },
            native: { client },
        });

        this.cache.set(client.client_id, client);

        await this.prune();

        return client;
    }

    /**
     * Remove a client. Already issued access tokens stay valid until they expire.
     *
     * @param clientId The `client_id` to remove
     */
    async delete(clientId: string): Promise<void> {
        if (!clientId || !/^[a-zA-Z0-9_-]+$/.test(clientId)) {
            return;
        }
        this.cache.delete(clientId);
        try {
            await this.adapter.delForeignObjectAsync(`${this.folder}.${clientId}`);
        } catch (e) {
            this.adapter.log.warn(`Cannot delete OAuth2 client "${clientId}": ${(e as Error).message}`);
        }
    }

    /**
     * Drop the oldest dynamically registered clients once the store grew past its limit. Without this
     * every re-added connector would leave a record behind forever. Clients registered by hand are
     * never pruned.
     */
    private async prune(): Promise<void> {
        const clients = await this.list();
        if (clients.length <= this.maxClients) {
            return;
        }

        const removable = clients.filter(c => c.dynamic);
        const excess = clients.length - this.maxClients;
        for (const client of removable.slice(0, excess)) {
            this.adapter.log.warn(
                `Removing oldest dynamically registered OAuth2 client "${client.client_name || client.client_id}" — the limit of ${this.maxClients} clients was reached`,
            );
            await this.delete(client.client_id);
        }
    }
}

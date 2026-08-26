import tls from 'node:tls';
import http from 'node:http';
import https, { type ServerOptions } from 'node:https';
import { type CertificateCollection, CertificateManager } from './certificateManager';
import { ACME_CHALLENGE_PREFIX, serveAcmeChallenge } from './acmeChallenge';

export interface WebServerAccessControl {
    /** Access-Control-Allow-Headers */
    accessControlAllowHeaders?: string;
    /** Access-Control-Allow-Methods */
    accessControlAllowMethods?: string;
    /**
     * Access-Control-Allow-Origin: either a literal value (`*` or one concrete origin) or a
     * function picking one for the origin of the incoming request - `origin => origin` reflects
     * it back, which is what a configuration that allows every origin with credentials needs.
     */
    accessControlAllowOrigin?: string | ((origin: string | undefined) => string | undefined);
    /** Access-Control-Expose-Headers */
    accessControlExposeHeaders?: string;
    /** Access-Control-Max-Age, in seconds: how long a browser may cache the preflight result */
    accessControlMaxAge?: number;
    /**
     * @deprecated `Access-Control-Request-Headers` is what the browser sends in a preflight; as a
     * response header it has no effect. Only used as a fallback for {@link accessControlAllowHeaders}.
     */
    accessControlRequestHeaders?: string;
    /**
     * @deprecated `Access-Control-Request-Method` is what the browser sends in a preflight; as a
     * response header it has no effect. Only used as a fallback for {@link accessControlAllowMethods}.
     */
    accessControlRequestMethod?: string;
    /** Access-Control-Allow-Credentials */
    accessControlAllowCredentials?: boolean;
}

interface WebServerOptions {
    /** the ioBroker adapter */
    adapter: ioBroker.Adapter;
    app?: http.RequestListener | null;
    /** if https should be used */
    secure: boolean | undefined;
    /** access control options */
    accessControl?: WebServerAccessControl;
    /**
     * Answer ACME HTTP-01 challenges published by the acme adapter, so it does
     * not have to stop this adapter to get at port 80. Enabled by default; set
     * to false to keep `/.well-known/acme-challenge/` entirely to the app.
     */
    acmeChallenge?: boolean;
}

interface AdapterConfig {
    /** Collection ID */
    leCollection: string | boolean | undefined;
    /** The name of the public self-signed certificate or custom certificate */
    certPublic: string | undefined;
    /** The name of the private self-signed certificate or custom certificate */
    certPrivate: string | undefined;
    /** The name of the chained self-signed certificate or custom certificate */
    certChained: string | undefined;
}

interface Certificates {
    /** public certificate */
    key: string;
    /** private certificate */
    cert: string;
    /** chained certificate */
    ca?: string;
}

export class WebServer {
    private server: http.Server | https.Server | undefined;
    private readonly adapter: ioBroker.Adapter;
    private readonly secure: boolean;
    private app?: http.RequestListener;
    private originalApp: http.RequestListener | undefined;
    private readonly certManager: CertificateManager | undefined;
    private readonly accessControl: WebServerAccessControl | undefined;
    private readonly acmeChallenge: boolean;

    constructor(options: WebServerOptions) {
        this.secure = !!options.secure;
        this.adapter = options.adapter;
        this.app = options.app || undefined;
        if (this.secure) {
            this.certManager = new CertificateManager({ adapter: options.adapter });
        }
        this.accessControl = options.accessControl;
        this.acmeChallenge = options.acmeChallenge !== false;
    }

    /**
     * Wrap the app with everything that has to run in front of it.
     *
     * Called from every branch of init() because each of them creates the
     * server from `this.app` and there is no single point after it.
     */
    private prepareApp(): void {
        this.initAccessControl();
        // Outermost, so a challenge is answered without collecting CORS headers
        // it has no use for.
        this.initAcmeChallenge();
    }

    /**
     * Put the ACME HTTP-01 challenge lookup in front of the app.
     *
     * In front rather than in a route because the CA is anonymous and the
     * lookup therefore has to happen before any authentication the app
     * installs. Requests that are not a published challenge are handed on
     * untouched, so nothing the app serves is shadowed.
     */
    private initAcmeChallenge(): void {
        if (!this.acmeChallenge) {
            return;
        }

        const app = this.app;
        const passOn = (req: http.IncomingMessage, res: http.ServerResponse): void => {
            if (app) {
                app(req, res);
            } else {
                // Without an app there is nobody left to answer.
                res.writeHead(404);
                res.end();
            }
        };

        this.app = (req, res) => {
            // Cheap string test first: this runs for every single request.
            if (!req.url?.startsWith(ACME_CHALLENGE_PREFIX)) {
                passOn(req, res);
                return;
            }
            serveAcmeChallenge(this.adapter, req, res).then(
                served => {
                    if (!served) {
                        passOn(req, res);
                    }
                },
                (e: Error) => {
                    this.adapter.log.warn(`Could not answer ACME challenge: ${e.message}`);
                    passOn(req, res);
                },
            );
        };
    }

    /**
     * Put the configured CORS headers in front of the app.
     *
     * Outermost rather than as a route, so every answer carries them - including the ones the app
     * produces before any middleware it registered later would run, such as the OAuth2 token
     * endpoint or a 401 out of the authorization middleware.
     */
    private initAccessControl(): void {
        const accessControl = this.accessControl;
        if (
            !accessControl ||
            (accessControl.accessControlAllowCredentials === undefined &&
                !accessControl.accessControlAllowHeaders &&
                !accessControl.accessControlAllowMethods &&
                !accessControl.accessControlAllowOrigin &&
                !accessControl.accessControlExposeHeaders &&
                accessControl.accessControlMaxAge === undefined &&
                !accessControl.accessControlRequestHeaders &&
                !accessControl.accessControlRequestMethod)
        ) {
            return;
        }

        // The deprecated `Request-*` options are request headers and were never valid on a
        // response, so whoever set them meant the `Allow-*` ones. They only fill in when the
        // correct option is absent.
        const allowHeaders = accessControl.accessControlAllowHeaders || accessControl.accessControlRequestHeaders;
        const allowMethods = accessControl.accessControlAllowMethods || accessControl.accessControlRequestMethod;

        this.originalApp = this.app;
        this.app = (req, res) => {
            if (accessControl.accessControlAllowCredentials !== undefined) {
                res.setHeader(
                    'Access-Control-Allow-Credentials',
                    accessControl.accessControlAllowCredentials ? 'true' : 'false',
                );
            }
            if (allowHeaders) {
                res.setHeader('Access-Control-Allow-Headers', allowHeaders);
            }
            if (allowMethods) {
                res.setHeader('Access-Control-Allow-Methods', allowMethods);
            }

            const origin =
                typeof accessControl.accessControlAllowOrigin === 'function'
                    ? accessControl.accessControlAllowOrigin(req.headers.origin)
                    : accessControl.accessControlAllowOrigin;
            if (origin) {
                res.setHeader('Access-Control-Allow-Origin', origin);
                if (origin !== '*') {
                    // The answer depends on the origin, so a cache must not hand it to another one.
                    res.setHeader('Vary', 'Origin');
                }
            }

            if (accessControl.accessControlExposeHeaders) {
                res.setHeader('Access-Control-Expose-Headers', accessControl.accessControlExposeHeaders);
            }
            if (accessControl.accessControlMaxAge !== undefined) {
                res.setHeader('Access-Control-Max-Age', accessControl.accessControlMaxAge.toString());
            }

            // @ts-expect-error this.originalApp is set
            return this.originalApp(req, res);
        };
    }

    /**
     * Initialize a new https / http server; according to configuration, it will be present on `this.server`
     */
    async init(): Promise<http.Server | https.Server> {
        if (!this.certManager) {
            this.adapter.log.debug('Secure connection not enabled - using http createServer');
            this.prepareApp();
            this.server = http.createServer(this.app);
            return this.server;
        }
        const config: AdapterConfig = this.adapter.config as AdapterConfig;

        // Load self-signed or custom certificates for fallback
        const customCertificates = await this.getCustomCertificates();

        // Load certificate collections
        this.adapter.log.debug('Loading all certificate collections...');

        let collections: Record<string, CertificateCollection> | null;
        // true => use all collections, false => do not use collections, string => use the collection with this ID
        const collectionId: string | boolean | undefined = config.leCollection;

        if (collectionId && typeof collectionId === 'string') {
            collections = {
                [collectionId]: await this.certManager.getCollection(collectionId),
            } as Record<string, CertificateCollection>;
        } else if (collectionId !== false) {
            collections = await this.certManager.getAllCollections();
            if (!collections || !Object.keys(collections).length) {
                this.adapter.log.warn(
                    'Could not find any certificate collections - check ACME installation or consider installing',
                );

                this.prepareApp();
                if (customCertificates) {
                    this.adapter.log.warn('Falling back to self-signed certificates or to custom certificates');
                    this.server = https.createServer(customCertificates as ServerOptions, this.app);
                } else {
                    // This really should never happen as customCertificatesContext should always be available
                    this.adapter.log.error(
                        'Could not find self-signed certificate - falling back to insecure http createServer',
                    );
                    this.server = http.createServer(this.app);
                }
                return this.server;
            }
        } else {
            // fallback to self-signed or custom certificates
            collections = null;
            this.prepareApp();

            if (customCertificates) {
                this.adapter.log.debug('Use self-signed certificates or custom certificates');
                this.server = https.createServer(customCertificates as ServerOptions, this.app);
            } else {
                // This really should never happen as customCertificatesContext should always be available
                this.adapter.log.error(
                    'Could not find self-signed certificate - falling back to insecure http createServer',
                );
                this.server = http.createServer(this.app);
            }

            return this.server;
        }

        let contexts: Record<string, tls.SecureContext> | undefined;

        const customCertificatesContext = customCertificates ? tls.createSecureContext(customCertificates) : null;

        if (collections) {
            contexts = this.buildSecureContexts(collections);

            this.certManager.subscribeCollections(
                collectionId === true ? null : collectionId || null,
                (err, collections) => {
                    if (!err && collections) {
                        this.adapter.log.silly(`collections update ${JSON.stringify(collections)}`);
                        contexts = this.buildSecureContexts(collections);
                        if (!Object.keys(contexts).length) {
                            this.adapter.log.warn('Could not find any certificate collections after update');
                            if (!customCertificatesContext) {
                                this.adapter.log.error(
                                    'No certificate collections or self-signed certificate available - HTTPS requests will now fail',
                                );
                                // This is very bad, and perhaps the adapter should also terminate itself?
                            }
                        }
                        // contexts are now up to date and will be utilized in SNICallback - nothing more to do.
                    } else if (err) {
                        this.adapter.log.error(`Error updating certificate collections: ${err.toString()}`);
                    } else {
                        this.adapter.log.error(
                            `${
                                collectionId ? `Collection "${collectionId}" was` : 'All collections were'
                            } removed from certificate collections and now we cannot update certificates`,
                        );
                    }
                },
            );
        }

        const options: https.ServerOptions = {
            SNICallback: (serverName, callback) => {
                // Find which context to use for this server
                let context;
                if (contexts) {
                    if (serverName in contexts) {
                        // Easy - name is explicitly mentioned
                        if (this.adapter.common?.loglevel === 'debug') {
                            this.adapter.log.debug(`Using explicit context for "${serverName}"`);
                        }
                        context = contexts[serverName];
                    } else {
                        // Check for wildcard
                        const serverParts = serverName.split('.');
                        if (serverParts.length > 1) {
                            serverParts.shift();
                            serverParts.unshift('*');
                            const wildcard = serverParts.join('.');
                            if (wildcard in contexts) {
                                // OK - wildcard found
                                if (this.adapter.common?.loglevel === 'debug') {
                                    this.adapter.log.debug(`Using wildcard context for "${serverName}"`);
                                }
                                context = contexts[wildcard];
                            }
                        }
                    }
                }
                if (!context) {
                    // Not found above.
                    if (customCertificatesContext) {
                        // Use custom context
                        // Don't spit out warnings here as this may be a common occurrence
                        // and one already emitted at startup.
                        context = customCertificatesContext;
                    } else if (contexts) {
                        // See the note above about terminating - if that is implemented, no need for this check.
                        if (!Object.keys(contexts).length) {
                            // No customCertificatesContext and no contexts - this is very bad!
                            this.adapter.log.error(`Could not derive secure context for "${serverName}"`);
                        } else {
                            this.adapter.log.warn(
                                `No matching context for "${serverName}" - using first certificate collection which will likely cause browser security warnings`,
                            );
                            context = contexts[Object.keys(contexts)[0]];
                        }
                    } else {
                        this.adapter.log.error(`Could not find any certificates for "${serverName}"`);
                    }
                }
                callback(null, context);
            },
        };

        this.prepareApp();
        this.adapter.log.debug('Using https createServer');
        this.server = https.createServer(options, this.app);
        return this.server;
    }

    /**
     * Assemble the certificate a secure context has to present for a collection.
     *
     * `cert` holds the leaf only - the issuing chain lives in `chain`, and without it every
     * client that does not already know the intermediate rejects the connection. Producers
     * disagree on whether `chain` repeats the leaf, so it is normalized here.
     *
     * @param collection the certificate collection
     */
    private static buildCertificateChain(collection: CertificateCollection): string {
        const leaf = WebServer.splitCertificates(collection.cert);
        const issuers = WebServer.splitCertificates(collection.chain).filter(cert => !leaf.includes(cert));
        const bundle = leaf.concat(issuers);

        if (!bundle.length) {
            // Nothing parseable in there - hand the raw value on and let TLS report what is wrong.
            return collection.cert.toString();
        }

        // Joined by a newline, never by an empty string: OpenSSL only recognizes a BEGIN marker
        // at the start of a line and would silently drop every certificate after the first.
        return `${bundle.join('\n')}\n`;
    }

    /**
     * Cut a collection field into its individual PEM certificates.
     *
     * The field may be a single certificate, a whole concatenated chain or an array of either,
     * as string or as Buffer - which one it is depends on who wrote the collection.
     *
     * @param source the collection field to read
     */
    private static splitCertificates(source: CertificateCollection['chain']): string[] {
        const parts = Array.isArray(source) ? source : source ? [source] : [];
        const certificates: string[] = [];

        for (const part of parts) {
            // A base64 body never contains a dash, so the end of a block is unambiguous.
            const found = part.toString().match(/-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----/g);
            if (found) {
                certificates.push(...found);
            }
        }

        return certificates;
    }

    /**
     * Build secure context from certificate collections
     *
     * @param collections the certificate collections
     */
    private buildSecureContexts(collections: Record<string, CertificateCollection>): Record<string, tls.SecureContext> {
        this.adapter.log.debug('buildSecureContexts...');
        const contexts: Record<string, tls.SecureContext> = {};

        if (typeof collections === 'object') {
            for (const [collectionId, collection] of Object.entries(collections)) {
                const context = tls.createSecureContext({
                    key: collection.key,
                    cert: WebServer.buildCertificateChain(collection),
                });

                for (const domain of collection.domains) {
                    this.adapter.log.debug(`${domain} -> ${collectionId}`);
                    contexts[domain] = context;
                }
            }
        }
        return contexts;
    }

    /**
     * Get the custom certificates as text
     */
    async getCustomCertificates(): Promise<Certificates | null> {
        const config: AdapterConfig = this.adapter.config as AdapterConfig;
        const defaultPublic = config.certPublic || 'defaultPublic';
        const defaultPrivate = config.certPrivate || 'defaultPrivate';
        const defaultChain = config.certChained || '';

        const customCertificates = await this.adapter.getCertificatesAsync(defaultPublic, defaultPrivate, defaultChain);
        this.adapter.log.debug(
            `Loaded custom certificates: ${JSON.stringify(customCertificates && customCertificates[0])}`,
        );
        if (customCertificates && customCertificates[0]) {
            const certs = customCertificates[0];
            if (certs.key.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.key}" does not exists or iobroker user has no rights for it.`,
                );
            } else if (certs.cert.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.cert}" does not exists or iobroker user has no rights for it.`,
                );
            } else if (certs.ca && typeof certs.ca === 'string' && certs.ca.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.ca}" does not exists or iobroker user has no rights for it.`,
                );
            } else {
                return certs;
            }
        }
        return null;
    }

    /**
     * Get the custom certificates context
     */
    async getCustomCertificatesContext(): Promise<tls.SecureContext | null> {
        try {
            const customCertificates = await this.getCustomCertificates();

            if (customCertificates) {
                // All good
                return tls.createSecureContext(customCertificates);
            }
        } catch (e: any) {
            this.adapter.log.error(e.message);
        }
        // If we got here, then we either failed to load or use self-signed certificate or custom certificates.
        this.adapter.log.warn('Could not create custom context for fallback use');
        return null;
    }
}

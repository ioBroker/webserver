import tls, { SecureContextOptions } from 'node:tls';
import http from 'node:http';
import https, { ServerOptions } from 'node:https';
import { CertificateCollection, CertificateManager } from './certificateManager';

export interface WebServerAccessControl {
    /** Access-Control-Allow-Headers */
    accessControlAllowHeaders?: string;
    /** Access-Control-Allow-Methods */
    accessControlAllowMethods?: string;
    /** Access-Control-Allow-Origin */
    accessControlAllowOrigin?: string;
    /** Access-Control-Expose-Headers */
    accessControlExposeHeaders?: string;
    /** Access-Control-Request-Headers */
    accessControlRequestHeaders?: string;
    /** Access-Control-Request-Method */
    accessControlRequestMethod?: string;
    /** Access-Control-Allow-Credentials */
    accessControlAllowCredentials?: boolean;
}

interface WebServerOptions {
    /** the ioBroker adapter */
    adapter: ioBroker.Adapter;
    app: http.RequestListener;
    /** if https should be used */
    secure: boolean | undefined;
    /** access control options */
    accessControl?: WebServerAccessControl;
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
    ca: string | undefined;
}

export class WebServer {
    private server: http.Server | https.Server | undefined;
    private readonly adapter: ioBroker.Adapter;
    private readonly secure: boolean;
    private app: http.RequestListener;
    private originalApp: http.RequestListener | undefined;
    private readonly certManager: CertificateManager | undefined;
    private readonly accessControl: WebServerAccessControl | undefined;

    constructor(options: WebServerOptions) {
        this.secure = !!options.secure;
        this.adapter = options.adapter;
        this.app = options.app;
        if (this.secure) {
            this.certManager = new CertificateManager({ adapter: options.adapter });
        }
        this.accessControl = options.accessControl;
    }

    private initAccessControl(): void {
        if (
            this.accessControl &&
            (this.accessControl.accessControlAllowCredentials !== undefined ||
                this.accessControl.accessControlAllowHeaders ||
                this.accessControl.accessControlAllowMethods ||
                this.accessControl.accessControlAllowOrigin ||
                this.accessControl.accessControlExposeHeaders ||
                this.accessControl.accessControlRequestHeaders ||
                this.accessControl.accessControlRequestMethod)
        ) {
            this.originalApp = this.app;
            this.app = (req, res) => {
                if (this.accessControl) {
                    if (this.accessControl.accessControlAllowCredentials !== undefined) {
                        res.setHeader(
                            'Access-Control-Allow-Credentials',
                            this.accessControl.accessControlAllowCredentials ? 'true' : 'false'
                        );
                    }
                    if (this.accessControl.accessControlAllowHeaders) {
                        res.setHeader('Access-Control-Allow-Headers', this.accessControl.accessControlAllowHeaders);
                    }
                    if (this.accessControl.accessControlAllowMethods) {
                        res.setHeader('Access-Control-Allow-Methods', this.accessControl.accessControlAllowMethods);
                    }
                    if (this.accessControl.accessControlAllowOrigin) {
                        res.setHeader('Access-Control-Allow-Origin', this.accessControl.accessControlAllowOrigin);
                    }
                    if (this.accessControl.accessControlExposeHeaders) {
                        res.setHeader('Access-Control-Expose-Headers', this.accessControl.accessControlExposeHeaders);
                    }
                    if (this.accessControl.accessControlRequestHeaders) {
                        res.setHeader('Access-Control-Request-Headers', this.accessControl.accessControlRequestHeaders);
                    }
                    if (this.accessControl.accessControlRequestMethod) {
                        res.setHeader('Access-Control-Request-Method', this.accessControl.accessControlRequestMethod);
                    }
                }

                // @ts-expect-error this.originalApp is set
                return this.originalApp(req, res);
            };
        }
    }

    /**
     * Initialize new https/http server, according to configuration, it will be present on `this.server`
     */
    async init(): Promise<http.Server | https.Server> {
        if (!this.certManager) {
            this.adapter.log.debug('Secure connection not enabled - using http createServer');
            this.initAccessControl();
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
                [collectionId]: await this.certManager.getCollection(collectionId)
            } as Record<string, CertificateCollection>;
        } else if (collectionId !== false) {
            collections = await this.certManager.getAllCollections();
            if (!collections || !Object.keys(collections).length) {
                this.adapter.log.warn(
                    'Could not find any certificate collections - check ACME installation or consider installing'
                );

                if (customCertificates) {
                    this.adapter.log.warn('Falling back to self-signed certificates or to custom certificates');
                    this.initAccessControl();
                    this.server = https.createServer(customCertificates as ServerOptions, this.app);
                    return this.server;
                } else {
                    // This really should never happen as customCertificatesContext should always be available
                    this.adapter.log.error(
                        'Could not find self-signed certificate - falling back to insecure http createServer'
                    );
                    this.initAccessControl();
                    this.server = http.createServer(this.app);

                    return this.server;
                }
            }

            if (!collections) {
                throw new Error('Cannot create secure server: No certificate collection found');
            }
        } else {
            // fallback to self-signed or custom certificates
            collections = null;
            if (customCertificates) {
                this.adapter.log.debug('Use self-signed certificates or custom certificates');
                this.initAccessControl();
                this.server = https.createServer(customCertificates as ServerOptions, this.app);
                return this.server;
            } else {
                // This really should never happen as customCertificatesContext should always be available
                this.adapter.log.error(
                    'Could not find self-signed certificate - falling back to insecure http createServer'
                );
                this.initAccessControl();
                this.server = http.createServer(this.app);

                return this.server;
            }
        }

        let contexts: Record<string, tls.SecureContext> | undefined;

        const customCertificatesContext = tls.createSecureContext(customCertificates as SecureContextOptions);

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
                                    'No certificate collections or self-signed certificate available - HTTPS requests will now fail'
                                );
                                // This is very bad, and perhaps the adapter should also terminate itself?
                            }
                        }
                        // contexts are now up-to-date and will be utilized in SNICallback - nothing more to do.
                    } else if (err) {
                        this.adapter.log.error(`Error updating certificate collections: ${err}`);
                    } else {
                        this.adapter.log.error(
                            `${
                                collectionId ? `Collection "${collectionId}" was` : 'All collections were'
                            } removed from certificate collections and now we cannot update certificates`
                        );
                    }
                }
            );
        }

        const options: https.ServerOptions = {
            SNICallback: (serverName, callback) => {
                // Find which context to use for this server
                let context;
                if (contexts) {
                    if (serverName in contexts) {
                        // Easy - name is explicitly mentioned
                        if (this.adapter.common.loglevel === 'debug') {
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
                                if (this.adapter.common.loglevel === 'debug') {
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
                                `No matching context for "${serverName}" - using first certificate collection which will likely cause browser security warnings`
                            );
                            context = contexts[Object.keys(contexts)[0]];
                        }
                    } else {
                        this.adapter.log.error(`Could not find any certificates for "${serverName}"`);
                    }
                }
                callback(null, context);
            }
        };

        this.adapter.log.debug('Using https createServer');
        this.server = https.createServer(options, this.app);
        return this.server;
    }

    /**
     * Build secure context from certificate collections
     * @param collections the certificate collections
     */
    private buildSecureContexts(collections: Record<string, CertificateCollection>): Record<string, tls.SecureContext> {
        this.adapter.log.debug('buildSecureContexts...');
        const contexts: Record<string, tls.SecureContext> = {};

        if (typeof collections === 'object') {
            for (const [collectionId, collection] of Object.entries(collections)) {
                const context = tls.createSecureContext({
                    key: collection.key,
                    cert: collection.cert
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

        // @ts-expect-error types are missing
        const customCertificates = await this.adapter.getCertificatesAsync(defaultPublic, defaultPrivate, defaultChain);
        this.adapter.log.debug(
            `Loaded custom certificates: ${JSON.stringify(customCertificates && customCertificates[0])}`
        );
        if (customCertificates && customCertificates[0]) {
            const certs = customCertificates[0];
            if (certs.key.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.key}" does not exists or iobroker user has no rights for it.`
                );
            } else if (certs.cert.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.cert}" does not exists or iobroker user has no rights for it.`
                );
            } else if (certs.ca && typeof certs.ca === 'string' && certs.ca.endsWith('.pem')) {
                this.adapter.log.error(
                    `Cannot load custom certificates. File "${certs.ca}" does not exists or iobroker user has no rights for it.`
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

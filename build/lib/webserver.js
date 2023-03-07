"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Webserver = void 0;
const tls_1 = __importDefault(require("tls"));
const http_1 = __importDefault(require("http"));
const https_1 = __importDefault(require("https"));
const SYSTEM_CERTIFICATES_ID = 'system.certificates';
class Webserver {
    constructor(options) {
        this.secure = options.secure;
        this.adapter = options.adapter;
        this.app = options.app;
    }
    /**
     * Initialize new https/http server according to configuration, it will be present on `this.server`
     */
    async init() {
        if (!this.secure) {
            this.adapter.log.debug('Secure connection not enabled - using http createServer');
            this.server = http_1.default.createServer(this.app);
            return;
        }
        // Load self-signed certificate for fallback
        const selfSignedContext = await this.getSelfSignedContext();
        // Load certificate collections
        this.adapter.log.debug('Loading all certificate collections...');
        const collections = await this.getCertificateCollection();
        if (!collections || !Object.keys(collections).length) {
            this.adapter.log.warn('Could not find any certificate collections - check ACME installation or consider installing');
            if (selfSignedContext) {
                this.adapter.log.warn('Falling back to self-signed certificate');
            }
            else {
                // This really should never happen as selfSigned should always be available
                this.adapter.log.error('Could not find self-signed certificate - falling back to insecure http createServer');
                this.server = http_1.default.createServer(this.app);
                return;
            }
        }
        if (!collections) {
            throw new Error('Cannot create secure server: No certificate collection found');
        }
        let contexts = this.buildSecureContexts(collections);
        this.subscribeCertificateCollections(null, (err, collections) => {
            if (!err && collections) {
                this.adapter.log.silly(`collections update ${JSON.stringify(collections)}`);
                contexts = this.buildSecureContexts(collections);
                if (!Object.keys(contexts).length) {
                    this.adapter.log.warn('Could not find any certificate collections after update');
                    if (!selfSignedContext) {
                        this.adapter.log.error('No certificate collections or self-signed certificate available - HTTPS requests will now fail');
                        // This is very bad and perhaps the adapter should also terminate itself?
                    }
                }
            }
        });
        const options = {
            SNICallback: (serverName, callback) => {
                // Find which context to use for this server
                let context;
                if (serverName in contexts) {
                    // Easy - name is explicitly mentioned
                    this.adapter.log.debug(`Using explicit context for ${serverName}`);
                    context = contexts[serverName];
                }
                else {
                    // Check for wildcard
                    const serverParts = serverName.split('.');
                    if (serverParts.length > 1) {
                        serverParts.shift();
                        serverParts.unshift('*');
                        const wildcard = serverParts.join('.');
                        if (wildcard in contexts) {
                            // OK - wildcard found
                            this.adapter.log.debug(`Using wildcard context for ${serverName}`);
                            context = contexts[wildcard];
                        }
                    }
                }
                if (!context) {
                    // Not found above.
                    if (selfSignedContext) {
                        // Use self-signed context
                        // Don't spit out warnings here as this may be common occurrence
                        // and one already emitted at startup.
                        context = selfSignedContext;
                    }
                    else {
                        // See note above about terminate - if that is implemented no need for this check.
                        if (!Object.keys(contexts).length) {
                            // No selfSignedContext and no contexts - this is very bad!
                            this.adapter.log.error(`Could not derive secure context for ${serverName}`);
                        }
                        else {
                            this.adapter.log.warn(`No matching context for ${serverName} - using first certificate collection which will likely cause browser security warnings`);
                            context = contexts[Object.keys(contexts)[0]];
                        }
                    }
                }
                callback(null, context);
            }
        };
        this.adapter.log.debug('Using https createServer');
        this.server = https_1.default.createServer(options, this.app);
    }
    /**
     * Build secure context from certificate collections
     * @param collections the certificate collections
     */
    buildSecureContexts(collections) {
        this.adapter.log.debug('buildSecureContexts...');
        const contexts = {};
        if (typeof collections === 'object') {
            for (const [collectionId, collection] of Object.entries(collections)) {
                const context = tls_1.default.createSecureContext({
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
     * Subscribes certificate collections object and calls callback on every change
     * @param collectionId if null, return all collections in callback
     * @param callback called on every change
     */
    subscribeCertificateCollections(collectionId, callback) {
        this.adapter.subscribeForeignObjects(SYSTEM_CERTIFICATES_ID);
        this.adapter.on('objectChange', (id, obj) => {
            var _a;
            if (id === SYSTEM_CERTIFICATES_ID) {
                this.adapter.log.debug(`${SYSTEM_CERTIFICATES_ID} updated`);
                if (!((_a = obj === null || obj === void 0 ? void 0 : obj.native) === null || _a === void 0 ? void 0 : _a.collections)) {
                    return;
                }
                const collections = obj.native.collections;
                if (!collectionId) {
                    // No specific ID requested, return them all
                    callback(null, collections);
                }
                else {
                    if (Array.isArray(collections) && collectionId in collections) {
                        callback(null, { collectionId: collections[collectionId] });
                    }
                    else {
                        // Can't find requested collection ID, return empty object & error
                        callback(new Error(`Subscribed collection ID ${collectionId} not found`), {});
                    }
                }
            }
        });
    }
    /**
     * Returns collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId or omit to return all
     */
    async getCertificateCollection(collectionId) {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            // If collectionId does not exist not an error situation: return null to indicate this.
            const collections = obj === null || obj === void 0 ? void 0 : obj.native.collections;
            if (!collections) {
                return null;
            }
            return collectionId ? collections[collectionId] : collections;
        }
        catch (e) {
            this.adapter.log.error(`No certificates found: ${e.message}`);
            return null;
        }
    }
    /**
     * Get the self-signed certificate context
     */
    async getSelfSignedContext() {
        try {
            // @ts-expect-error types are missing
            const selfSigned = (await this.adapter.getCertificatesAsync('defaultPublic', 'defaultPrivate'))[0];
            this.adapter.log.debug(`Loaded self signed certificate: ${JSON.stringify(selfSigned)}`);
            if (selfSigned) {
                // All good
                return tls_1.default.createSecureContext(selfSigned);
            }
        }
        catch (e) {
            this.adapter.log.error(e.message);
        }
        // If we got here then we either failed to load or use self-signed certificate.
        this.adapter.log.warn('Could not create self-signed context for fallback use');
        return null;
    }
}
exports.Webserver = Webserver;
//# sourceMappingURL=webserver.js.map
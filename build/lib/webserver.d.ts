/// <reference types="iobroker" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import tls from 'tls';
import http from 'http';
interface WebserverOptions {
    /** the ioBroker adapter */
    adapter: ioBroker.Adapter;
    app: http.RequestListener;
    /** if https should be used */
    secure: boolean;
}
interface CertificateCollection {
    /** Creating adapter */
    from: string;
    /** expiry date/time - mandatory */
    /** So not everyone needs to decode cert to discover this */
    tsExpires: number;
    /** private key - mandatory */
    key: string | Buffer;
    /** public certificate - mandatory */
    cert: string | Buffer;
    /** domains - mandatory */
    domains: string[];
    /** chain - optional */
    chain?: string | Buffer;
}
export declare class Webserver {
    private server;
    private readonly adapter;
    private readonly secure;
    private readonly app;
    constructor(options: WebserverOptions);
    /**
     * Initialize new https/http server according to configuration, it will be present on `this.server`
     */
    init(): Promise<void>;
    /**
     * Build secure context from certificate collections
     * @param collections the certificate collections
     */
    private buildSecureContexts;
    /**
     * Subscribes certificate collections object and calls callback on every change
     * @param collectionId if null, return all collections in callback
     * @param callback called on every change
     */
    private subscribeCertificateCollections;
    getCertificateCollection(): Promise<Record<string, CertificateCollection> | null>;
    getCertificateCollection(collectionId: string): Promise<CertificateCollection | null>;
    /**
     * Get the self-signed certificate context
     */
    getSelfSignedContext(): Promise<tls.SecureContext | null>;
}
export {};

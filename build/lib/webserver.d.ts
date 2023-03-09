/// <reference types="iobroker" />
/// <reference types="node" />
/// <reference types="node" />
/// <reference types="node" />
import tls from 'tls';
import http from 'http';
import https from 'https';
interface WebserverOptions {
    /** the ioBroker adapter */
    adapter: ioBroker.Adapter;
    app: http.RequestListener;
    /** if https should be used */
    secure: boolean;
}
export declare class Webserver {
    private server;
    private readonly adapter;
    private readonly secure;
    private readonly app;
    private readonly certManager;
    constructor(options: WebserverOptions);
    /**
     * Initialize new https/http server according to configuration, it will be present on `this.server`
     */
    init(): Promise<http.Server | https.Server>;
    /**
     * Build secure context from certificate collections
     * @param collections the certificate collections
     */
    private buildSecureContexts;
    /**
     * Get the self-signed certificate context
     */
    getSelfSignedContext(): Promise<tls.SecureContext | null>;
}
export {};

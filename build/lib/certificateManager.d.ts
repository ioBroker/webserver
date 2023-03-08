/// <reference types="iobroker" />
/// <reference types="node" />
interface CertificateManagerOptions {
    adapter: ioBroker.Adapter;
}
export interface CertificateCollection {
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
export type SubscribeCertificateCollectionsCallback = (err: Error | null, collections?: Record<string, CertificateCollection>) => void;
export declare class CertificateManager {
    private readonly adapter;
    constructor(options: CertificateManagerOptions);
    getCertificateCollection(): Promise<Record<string, CertificateCollection> | null>;
    getCertificateCollection(collectionId: string): Promise<CertificateCollection | null>;
    /**
     * Saves collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId collection ID
     * @param collection object holding all related keys, certificates, etc.
     */
    setCertificateCollection(collectionId: string, collection: CertificateCollection): Promise<void>;
    /**
     * Remove collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId collection ID
     */
    delCertificateCollection(collectionId: string): Promise<void>;
    /**
     * Subscribes certificate collections object and calls callback on every change
     *
     * @param collectionId if null, return all collections in callback
     * @param callback called on every change
     */
    subscribeCertificateCollections(collectionId: string | null, callback: SubscribeCertificateCollectionsCallback): void;
    /**
     * Returns list of available certificate collection IDs
     */
    listCertificateCollectionIds(): Promise<string[]>;
}
export {};

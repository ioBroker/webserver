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

export type SubscribeCertificateCollectionsCallback = (
    err: Error | null,
    collections?: Record<string, CertificateCollection>
) => void;

const SYSTEM_CERTIFICATES_ID = 'system.certificates';

export class CertificateManager {
    private readonly adapter: ioBroker.Adapter;

    constructor(options: CertificateManagerOptions) {
        this.adapter = options.adapter;
    }

    getCertificateCollection(): Promise<Record<string, CertificateCollection> | null>;
    getCertificateCollection(collectionId: string): Promise<CertificateCollection | null>;

    /**
     * Returns collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId or omit to return all
     */
    async getCertificateCollection(
        collectionId?: string
    ): Promise<CertificateCollection | Record<string, CertificateCollection> | null> {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            // If collectionId does not exist not an error situation: return null to indicate this.
            const collections = obj?.native.collections;

            if (!collections) {
                return null;
            }

            return collectionId ? collections[collectionId] : collections;
        } catch (e: any) {
            this.adapter.log.error(`No certificates found: ${e.message}`);
            return null;
        }
    }

    /**
     * Saves collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId collection ID
     * @param collection object holding all related keys, certificates, etc.
     */
    async setCertificateCollection(collectionId: string, collection: CertificateCollection): Promise<void> {
        const mandatory = ['from', 'tsExpires', 'key', 'cert', 'domains'];
        if (!mandatory.every(key => Object.keys(collection).includes(key))) {
            throw new Error(`At least one mandatory key (${mandatory.join(',')}) missing from collection`);
        }

        await this.adapter.extendForeignObjectAsync(SYSTEM_CERTIFICATES_ID, {
            native: {
                collections: {
                    [collectionId]: collection
                }
            }
        });
    }

    /**
     * Remove collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId collection ID
     */
    async delCertificateCollection(collectionId: string): Promise<void> {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            if (
                obj?.native.collections &&
                typeof obj.native.collections === 'object' &&
                collectionId in obj.native.collections
            ) {
                delete obj.native.collections[collectionId];
                await this.adapter.setForeignObjectAsync(SYSTEM_CERTIFICATES_ID, obj);
            } else {
                // Did not exit -> goal reached
                return;
            }
        } catch (e: any) {
            throw new Error(`No certificates found: ${e.message}`);
        }
    }

    /**
     * Subscribes certificate collections object and calls callback on every change
     *
     * @param collectionId if null, return all collections in callback
     * @param callback called on every change
     */
    subscribeCertificateCollections(
        collectionId: string | null,
        callback: SubscribeCertificateCollectionsCallback
    ): void {
        this.adapter.subscribeForeignObjects(SYSTEM_CERTIFICATES_ID);

        this.adapter.on('objectChange', (id, obj) => {
            if (id === SYSTEM_CERTIFICATES_ID) {
                this.adapter.log.debug(`${SYSTEM_CERTIFICATES_ID} updated`);

                if (!obj?.native?.collections) {
                    return;
                }

                const collections = obj.native.collections as Record<string, CertificateCollection>;
                if (!collectionId) {
                    // No specific ID requested, return them all
                    callback(null, collections);
                } else {
                    if (Array.isArray(collections) && collectionId in collections) {
                        callback(null, { collectionId: collections[collectionId] });
                    } else {
                        // Can't find requested collection ID, return empty object & error
                        callback(new Error(`Subscribed collection ID ${collectionId} not found`), {});
                    }
                }
            }
        });
    }

    /**
     * Returns list of available certificate collection IDs
     */
    async listCertificateCollectionIds(): Promise<string[]> {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            const collections = obj?.native.collections;
            return collections ? Object.keys(collections) : [];
        } catch (e: any) {
            throw new Error(`No certificates found: ${e.message}`);
        }
    }
}

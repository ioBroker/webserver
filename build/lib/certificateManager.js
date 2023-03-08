"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CertificateManager = void 0;
const SYSTEM_CERTIFICATES_ID = 'system.certificates';
class CertificateManager {
    constructor(options) {
        this.adapter = options.adapter;
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
     * Saves collection of SSL keys, certificates, etc. by ID.
     *
     * @param collectionId collection ID
     * @param collection object holding all related keys, certificates, etc.
     */
    async setCertificateCollection(collectionId, collection) {
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
    async delCertificateCollection(collectionId) {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            if ((obj === null || obj === void 0 ? void 0 : obj.native.collections) &&
                typeof obj.native.collections === 'object' &&
                collectionId in obj.native.collections) {
                delete obj.native.collections[collectionId];
                await this.adapter.setForeignObjectAsync(SYSTEM_CERTIFICATES_ID, obj);
            }
            else {
                // Did not exit -> goal reached
                return;
            }
        }
        catch (e) {
            throw new Error(`No certificates found: ${e.message}`);
        }
    }
    /**
     * Subscribes certificate collections object and calls callback on every change
     *
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
     * Returns list of available certificate collection IDs
     */
    async listCertificateCollectionIds() {
        try {
            const obj = await this.adapter.getForeignObjectAsync(SYSTEM_CERTIFICATES_ID);
            const collections = obj === null || obj === void 0 ? void 0 : obj.native.collections;
            return collections ? Object.keys(collections) : [];
        }
        catch (e) {
            throw new Error(`No certificates found: ${e.message}`);
        }
    }
}
exports.CertificateManager = CertificateManager;
//# sourceMappingURL=certificateManager.js.map
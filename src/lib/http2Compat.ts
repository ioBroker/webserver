import http from 'node:http';
import http2 from 'node:http2';

/**
 * Collect the members an HTTP/2 compat object has to keep on the instance itself.
 *
 * These are the members of the HTTP/2 prototype and every member of the HTTP/1 prototypes, each
 * resolved the way the HTTP/2 prototype chain resolves it. The HTTP/1 ones matter as well: after a
 * prototype swap they would otherwise be found on the HTTP/1 class and run against the HTTP/2
 * internals - `IncomingMessage.prototype._destroy`, for example, writes the getter-only `aborted`.
 * A member the HTTP/2 chain does not have at all is covered with `undefined`, as it would be
 * without the swap.
 *
 * @param http2Prototype prototype of the HTTP/2 compat class
 * @param http1Prototypes prototypes of the HTTP/1 class chain down to where both chains meet
 */
function collectMembers(http2Prototype: object, http1Prototypes: object[]): PropertyDescriptorMap {
    const keys = new Set<PropertyKey>(Reflect.ownKeys(http2Prototype));
    for (const prototype of http1Prototypes) {
        for (const key of Reflect.ownKeys(prototype)) {
            keys.add(key);
        }
    }
    keys.delete('constructor');

    const members: PropertyDescriptorMap = {};
    for (const key of keys) {
        let descriptor: PropertyDescriptor | undefined;
        for (let prototype = http2Prototype; prototype && !descriptor; prototype = Object.getPrototypeOf(prototype)) {
            descriptor = Object.getOwnPropertyDescriptor(prototype, key);
        }
        // Configurable, so that whoever wants to redefine a member on the instance still can
        members[key] = { ...(descriptor || { value: undefined, writable: true }), configurable: true };
    }
    return members;
}

// Both chains meet at `Readable` (requests) and at the legacy `Stream` (responses)
const requestMembers = collectMembers(http2.Http2ServerRequest.prototype, [http.IncomingMessage.prototype]);
const responseMembers = collectMembers(http2.Http2ServerResponse.prototype, [
    http.ServerResponse.prototype,
    http.OutgoingMessage.prototype,
]);

/**
 * HTTP/1 connection-specific headers, which HTTP/2 forbids (RFC 9113, 8.2.2). Node drops `connection` with a
 * process warning, but throws on the others - once the response is sent, i.e. out of `res.end()`, where no app
 * expects it and where even the error handler trips over the same header again.
 */
const CONNECTION_HEADERS = ['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade'];

function isConnectionHeader(name: unknown): boolean {
    return typeof name === 'string' && CONNECTION_HEADERS.includes(name.toLowerCase());
}

const { setHeader, appendHeader, writeHead } = http2.Http2ServerResponse.prototype;

responseMembers.setHeader.value = function (this: http2.Http2ServerResponse, name: unknown, value: unknown) {
    return isConnectionHeader(name) ? this : Reflect.apply(setHeader, this, [name, value]);
};
responseMembers.appendHeader.value = function (this: http2.Http2ServerResponse, name: unknown, value: unknown) {
    return isConnectionHeader(name) ? this : Reflect.apply(appendHeader, this, [name, value]);
};
// writeHead() stores its headers without going through setHeader(). A header list given as an array is
// passed on as it is.
responseMembers.writeHead.value = function (this: http2.Http2ServerResponse, ...args: unknown[]) {
    return Reflect.apply(
        writeHead,
        this,
        args.map(arg =>
            arg && typeof arg === 'object' && !Array.isArray(arg)
                ? Object.fromEntries(Object.entries(arg).filter(([name]) => !isConnectionHeader(name)))
                : arg,
        ),
    );
};
// HTTP/1 only, so covered with `undefined` above. express-session calls it whenever it saves the session
// before the response ends - with `resave` on every response - and each of them failed with
// `res._implicitHeader is not a function`. HTTP/1 does `this.writeHead(this.statusCode)`; only once here,
// as HTTP/2 throws on a second writeHead().
responseMembers._implicitHeader.value = function (this: http2.Http2ServerResponse): void {
    if (!this.headersSent) {
        this.writeHead(this.statusCode);
    }
};

/**
 * Make an HTTP/2 compat request and response usable for apps written against HTTP/1.
 *
 * Express replaces the prototype of every request and response with its own, which inherits from
 * `http.IncomingMessage` / `http.ServerResponse`. An `Http2ServerRequest` loses `url`, `headers`,
 * `method`, `_read` and the rest of its class that way, and the first read of the body throws
 * outside any handler - which takes the whole process down. Pinned to the instance, those members
 * come before whatever prototype is installed afterwards. HTTP/1 connection headers an app sets on
 * the response are dropped on the way.
 *
 * On top of that, it fills in two headers HTTP/1 code relies on:
 * - `host`: an HTTP/2 client sends the `:authority` pseudo-header instead, so `req.hostname` and
 *   every URL built from `req.get('host')` would come out empty;
 * - `transfer-encoding`: a body without `content-length` is valid in HTTP/2, but `type-is` - and so
 *   body-parser - only detects a body by one of these two headers and would skip it silently.
 *
 * @param req the HTTP/2 compat request
 * @param res the HTTP/2 compat response
 */
export function adaptHttp2Request(req: http2.Http2ServerRequest, res: http2.Http2ServerResponse): void {
    Object.defineProperties(req, requestMembers);
    Object.defineProperties(res, responseMembers);

    const headers = req.headers;
    if (headers.host === undefined && headers[':authority'] !== undefined) {
        headers.host = headers[':authority'];
    }
    if (headers['content-length'] === undefined && !req.stream.endAfterHeaders) {
        headers['transfer-encoding'] = 'chunked';
    }
}

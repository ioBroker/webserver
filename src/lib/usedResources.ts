/*
 * Reports the TCP port a server listens on to the per-host registry of exclusive resources
 * js-controller 8 maintains (`system.host.<hostname>.usedResources.<type>`).
 *
 * The registry answers "which port is already spoken for on this host", so a user configuring a new
 * instance can pick a free one instead of guessing and running into EADDRINUSE. For an adapter that
 * does not declare anything, js-controller derives the entry from `native.port` - which is a guess
 * about the configuration, not about what was really opened: an adapter listening on a second port,
 * on a port taken from somewhere else than `native.port`, or not listening at all, is listed wrong.
 *
 * This module reports what the server actually bound to, which is only known once it listens, and
 * takes the entry back when it closes again. The host is the only writer of the registry, so both
 * are round-trips to it; they are queued so that a close following a listen cannot overtake it.
 *
 * Nothing here is required for the server to work - every failure is logged and swallowed.
 */

import type net from 'node:net';

/** Feature a js-controller announces once it maintains the registry. Since js-controller 8. */
const USED_RESOURCES_FEATURE = 'CONTROLLER_USED_RESOURCES';

/**
 * Addresses that stand for every interface. A socket bound to one of them occupies the port in both
 * address families (a wildcard listener is dual-stack), so the family must not be reported for it.
 */
const WILDCARD_ADDRESSES = ['0.0.0.0', '::', '*', ''];

/**
 * Payload of the `tcpPort` resource type - `ioBroker.TcpPortResourceData` of js-controller 8.
 *
 * Declared here rather than taken from `@iobroker/types` because an adapter using this library may
 * well be built against the types of js-controller 7, which do not know the registry at all.
 */
export interface UsedTcpPort {
    /** TCP port number */
    port: number;
    /** Address the socket is bound to, `0.0.0.0` or `::` for every interface */
    bind?: string;
    /** Address family, only reported for a concrete bind address */
    family?: 4 | 6;
}

/**
 * The part of the adapter API this module uses, all of it optional: the methods exist since
 * js-controller 8 and `supportsFeature()` is typed against a union of known features that does not
 * contain {@link USED_RESOURCES_FEATURE} in older types.
 */
interface UsedResourcesApi {
    registerUsedResource?: (type: 'tcpPort', data: UsedTcpPort) => Promise<void>;
    freeUsedResource?: (type: 'tcpPort', data?: Partial<UsedTcpPort>) => Promise<void>;
    supportsFeature?: (feature: string) => boolean;
}

/** `common` of the instance object, with the flag deciding who fills the registry for it */
type UsedResourcesCommon = ioBroker.AdapterCommon & {
    /**
     * `true`: the adapter declares its resources itself, which is what this module does.
     * Not set: js-controller derives them from `native.port`. `false`: the instance has no entries.
     */
    declareUsedResources?: boolean;
};

/**
 * Log without ever throwing.
 *
 * Everything here runs on a server event, and a `close` in particular arrives while the adapter is
 * being torn down - at which point its logger can already be gone. A throwing log statement inside
 * one of the queued tasks below would end up as a rejection nobody listens to, and that terminates
 * the host adapter: a lot of damage for a line that only says a port was registered.
 *
 * @param adapter the ioBroker adapter
 * @param level the log level to write with
 * @param message what to write
 */
function log(adapter: ioBroker.Adapter, level: 'debug' | 'warn', message: string): void {
    try {
        adapter.log[level](message);
    } catch {
        // There is nothing left that could report this
    }
}

/**
 * How a port is named in the log. An IPv6 address is bracketed, otherwise its own colons run into
 * the one before the port (`:::8082`).
 */
function describe(data: Partial<UsedTcpPort>): string {
    if (!data.bind) {
        return `${data.port}`;
    }
    return data.bind.includes(':') ? `[${data.bind}]:${data.port}` : `${data.bind}:${data.port}`;
}

/**
 * Whether the registry of used resources can be spoken to at all.
 *
 * Both halves have to be asked, because they are two independent versions: the methods exist in the
 * `@iobroker/adapter-core` the adapter was built with, the registry behind them exists in the
 * js-controller that is running. A call to a host that knows no `registerUsedResource` is not
 * refused, it is simply never answered - and every single one of them would sit out the five second
 * timeout of the adapter API before rejecting.
 *
 * @param adapter the ioBroker adapter
 * @returns whether resources may be registered and freed
 */
export function supportsUsedResources(adapter: ioBroker.Adapter): boolean {
    const api = adapter as unknown as UsedResourcesApi;

    if (typeof api.registerUsedResource !== 'function' || typeof api.freeUsedResource !== 'function') {
        return false;
    }

    // Typed against a union of known features that does not contain this one in the types of
    // js-controller 7, hence the loosely typed `supportsFeature` of `UsedResourcesApi`
    return typeof api.supportsFeature === 'function' && api.supportsFeature(USED_RESOURCES_FEATURE);
}

/**
 * Whether this instance may report its used resources to the host.
 *
 * All three reasons against it are perfectly normal - an older controller, an adapter built against
 * an older `@iobroker/adapter-core`, an adapter that leaves the registry to the controller - so none
 * of them is worth more than a debug line. The host would refuse the registration in the last case
 * anyway, and asking it first only to be told so costs a message round-trip per start.
 *
 * @param adapter the ioBroker adapter
 */
function canReportUsedResources(adapter: ioBroker.Adapter): boolean {
    const api = adapter as unknown as UsedResourcesApi;

    if (typeof api.registerUsedResource !== 'function' || typeof api.freeUsedResource !== 'function') {
        // Told apart from the feature below only to name the half that is missing: the adapter can do
        // something about this one by updating its @iobroker/adapter-core
        log(adapter, 'debug', 'Used resources are not reported: @iobroker/adapter-core is older than js-controller 8');
        return false;
    }

    if (!supportsUsedResources(adapter)) {
        log(
            adapter,
            'debug',
            'Used resources are not reported: js-controller keeps no registry of used resources (feature "CONTROLLER_USED_RESOURCES")',
        );
        return false;
    }

    if ((adapter.common as UsedResourcesCommon | undefined)?.declareUsedResources !== true) {
        log(
            adapter,
            'debug',
            'Used resources are not reported: set "common.declareUsedResources" to true in io-package.json to report the port this adapter really listens on',
        );
        return false;
    }

    return true;
}

/**
 * Report a TCP port as occupied by this instance.
 *
 * Registering is additive, one call per port, so an adapter serving several of them reports each.
 *
 * @param adapter the ioBroker adapter
 * @param data the port, and the address it is bound to if it is not every interface
 * @returns whether the host accepted the registration
 */
export async function registerUsedPort(adapter: ioBroker.Adapter, data: UsedTcpPort): Promise<boolean> {
    if (!canReportUsedResources(adapter)) {
        return false;
    }

    try {
        await (adapter as unknown as UsedResourcesApi).registerUsedResource!('tcpPort', data);
        log(adapter, 'debug', `Registered TCP port ${describe(data)} as used by this instance`);
        return true;
    } catch (e: any) {
        log(adapter, 'warn', `Could not register TCP port ${describe(data)} as used: ${e.message}`);
        return false;
    }
}

/**
 * Take a previously reported TCP port back.
 *
 * `data` is a filter and not the exact payload: every field it names has to match, fields it leaves
 * out are ignored - so omitting it frees every TCP port of this instance. Freeing on shutdown is not
 * needed, the host marks the entries of a stopped instance as no longer held by itself.
 *
 * @param adapter the ioBroker adapter
 * @param data the fields identifying the ports to free; every TCP port of this instance without it
 * @returns whether the host accepted the request
 */
export async function freeUsedPort(adapter: ioBroker.Adapter, data?: Partial<UsedTcpPort>): Promise<boolean> {
    if (!canReportUsedResources(adapter)) {
        return false;
    }

    try {
        await (adapter as unknown as UsedResourcesApi).freeUsedResource!('tcpPort', data);
        log(adapter, 'debug', `Freed TCP port ${data ? describe(data) : 'registrations'} of this instance`);
        return true;
    } catch (e: any) {
        log(adapter, 'warn', `Could not free TCP port ${data ? describe(data) : 'registrations'}: ${e.message}`);
        return false;
    }
}

/**
 * What a listening server occupies, as the registry wants it.
 *
 * @param server the server to look at
 * @returns the payload, or undefined when the server holds no TCP port
 */
function listeningPort(server: net.Server): UsedTcpPort | undefined {
    const address = server.address();

    if (!address || typeof address === 'string') {
        // A pipe or a UNIX socket - no port, and no resource type the registry knows for it
        return undefined;
    }

    const data: UsedTcpPort = { port: address.port, bind: address.address };

    if (!WILDCARD_ADDRESSES.includes(address.address)) {
        // Named only for a concrete address: on a wildcard one the port is occupied in both families,
        // and the host treats a family it is not told about as "every family", which is exactly that.
        data.family = address.family === 'IPv6' ? 6 : 4;
    }

    return data;
}

/**
 * Report the port a server listens on for as long as it listens.
 *
 * The port is registered when the server starts listening - only then is it known, and a port taken
 * from the configuration may not be the one that was really bound - and freed when it closes again.
 * A server that is already listening is reported right away.
 *
 * @param adapter the ioBroker adapter
 * @param server the server whose port is reported
 * @returns a function that stops reporting and frees a port still registered
 */
export function trackUsedPort(adapter: ioBroker.Adapter, server: net.Server): () => void {
    /** What was reported, so the same port can be taken back - the server has no address by then */
    let reported: UsedTcpPort | undefined;
    /** Both calls go to the host, and a free must not arrive before the register it undoes */
    let queue: Promise<unknown> = Promise.resolve();

    const enqueue = (task: () => Promise<unknown>): void => {
        // The tasks report their own failures, so nothing is expected here - but a rejected promise
        // nobody listens to terminates the host adapter, which no port registration is worth.
        queue = queue.then(task, task).catch((e: any) => {
            log(adapter, 'warn', `Could not report the used TCP port: ${e?.message}`);
        });
    };

    const onListening = (): void => {
        const data = listeningPort(server);
        if (!data) {
            return;
        }
        reported = data;
        enqueue(() => registerUsedPort(adapter, data));
    };

    const onClose = (): void => {
        const data = reported;
        if (!data) {
            return;
        }
        reported = undefined;
        // Filtered by port and address only: the family was derived from the address, and a filter
        // naming a field the entry does not have matches nothing.
        enqueue(() => freeUsedPort(adapter, { port: data.port, bind: data.bind }));
    };

    server.on('listening', onListening);
    server.on('close', onClose);

    if (server.listening) {
        // Attached to a server that is already up, so its `listening` event is long gone
        onListening();
    }

    return () => {
        server.off('listening', onListening);
        server.off('close', onClose);
        onClose();
    };
}

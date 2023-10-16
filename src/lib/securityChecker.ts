import http from 'http';
import https from 'https';
import { URL } from 'url';

function _getPublicIP(): Promise<string> {
    return new Promise((resolve, reject) => {
        https
            .get('https://ip.iobroker.in', res => {
                const data: Uint8Array[] = [];

                res.on('data', chunk => data.push(chunk));

                res.on('end', () => resolve(Buffer.concat(data).toString()));
            })
            .on('error', err => reject(err.message));
    });
}

function _checkURL(url: string, pattern?: string, fullCompare?: boolean): Promise<null> {
    return new Promise((resolve, reject) => {
        const oldState = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
        const urlParsed = new URL(url);

        const options = {
            host: urlParsed.hostname, // server uses this
            port: urlParsed.port, // server uses this

            method: 'GET', // client uses this
            path: urlParsed.pathname, // client uses this
            timeout: 2000 // timeout in 2 seconds if the server does not respond in time
        };

        const req = (url.startsWith('https') ? https : http).get(options, res => {
            const data: Buffer[] = [];

            res.on('data', (chunk: Buffer) => data.push(chunk));

            res.on('end', () => {
                process.env.NODE_TLS_REJECT_UNAUTHORIZED = oldState;
                if (res.statusCode === 200) {
                    if (pattern) {
                        const file = Buffer.concat(data).toString();
                        if ((fullCompare && file === pattern) || file.includes(pattern)) {
                            return reject(
                                new Error(`The URL "${url}" is reachable from internet without any protection!`)
                            );
                        } else {
                            resolve(null);
                        }
                    }

                    reject(new Error(`The URL "${url}" is reachable from internet without any protection!`));
                } else {
                    resolve(null);
                }
            });
        });
        req.on('timeout', () => {
            req.destroy();
            resolve(null);
        });

        req.on('error', () => {
            process.env.NODE_TLS_REJECT_UNAUTHORIZED = oldState;
            resolve(null);
        });
    });
}

/**
 * Checks public IP address of the server and tries to connect to it.
 * Throws error if connection is possible.
 */
async function checkPublicIP(port: number | string, pattern?: string, customPath?: string): Promise<void> {
    if (typeof port === 'string') {
        port = parseInt(port, 10);
    }
    let publicIP;
    // we check the public ip address of the server
    try {
        publicIP = await _getPublicIP();
    } catch {
        // Ignore. We just don't know the public IP
    }
    if (customPath && customPath[0] !== '/') {
        customPath = `/${customPath}`;
    }

    if (publicIP) {
        // check http://publicIP:port
        await _checkURL(`http://${publicIP}:${port}${customPath}`, pattern, !!customPath)

        // check https://publicIP:port
        await _checkURL(`https://${publicIP}:${port}${customPath}`, pattern, !!customPath);

        // check http://publicIP:80
        if (port !== 80) {
            await _checkURL(`http://${publicIP}:80${customPath}`, pattern, !!customPath);
        }
        if (port !== 443) {
            await _checkURL(`https://${publicIP}:443${customPath}`, pattern, !!customPath);
        }
    }
}

export { checkPublicIP };

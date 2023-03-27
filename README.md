# Webserver for ioBroker adapters

## Description
This module provides a webserver, which automatically takes care of 
certificate handling using the ioBroker certificates.

## How-To
Install via `npm i @iobroker/webserver`.

Use the webserver in your ioBroker adapter as following:

- TypeScript: 
```typescript
import { WebServer } from '@iobroker/webserver';

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

- JavaScript:
```javascript
const { WebServer } = require('@iobroker/webserver');

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

And so you can use `CertificateManager` that is used in the WebServer already:
- TypeScript:
```typescript
import { CertificateManager } from '@iobroker/webserver';

// Not required for server
const certManager = new CertificateManager({ adapter })

// get all collections
const collections = await certManager.getAllCollections();
```

- JavaScript:
```javascript
const { CertificateManager } = require('@iobroker/webserver');

// Not required for server
const certManager = new CertificateManager({ adapter })

// get all collections
const collections = await certManager.getAllCollections();
```

## Changelog
<!--
  Placeholder for the next version (at the beginning of the line):
  ### **WORK IN PROGRESS**
-->
### 0.3.4 (2023-03-27)
* (bluefox) Corrected small error with CA certificate

### 0.3.3 (2023-03-24)
* (bluefox) Added check of the cert files

### 0.3.1 (2023-03-20)
* (bluefox) Corrected error with `getCertificatesAsync`

### 0.3.0 (2023-03-20)
* (bluefox) Added support of user configured certificates for fallback

### 0.2.1 (2023-03-20)
* (bluefox) Rename `Webserver` to `WebServer`

### 0.1.0 (2023-03-13)
* (foxriver76) initial release based on https://github.com/ioBroker/ioBroker.js-controller/pull/2104 by @raintonr

# Webserver for ioBroker adapters

## Description

This module provides a webserver, which automatically takes care of
certificate handling using the ioBroker certificates.

## How-To

Install via `npm i @iobroker/webserver`.

Use the webserver in your ioBroker adapter as the following:

-   TypeScript:

```typescript
import { WebServer } from '@iobroker/webserver';

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

-   JavaScript:

```javascript
const { WebServer } = require('@iobroker/webserver');

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

And so you can use `CertificateManager` that is used in the WebServer already:

-   TypeScript:

```typescript
import { CertificateManager } from '@iobroker/webserver';

// Not required for server
const certManager = new CertificateManager({ adapter });

// get all collections
const collections = await certManager.getAllCollections();
```

-   JavaScript:

```javascript
const { CertificateManager } = require('@iobroker/webserver');

// Not required for server
const certManager = new CertificateManager({ adapter });

// get all collections
const collections = await certManager.getAllCollections();
```

## Changelog

<!--
  Placeholder for the next version (at the beginning of the line):
  ### **WORK IN PROGRESS**
-->
### 1.0.7 (2025-02-07)

-   (@GermanBluefox) Updated packages and typing

### 1.0.6 (2024-09-14)

-   (@GermanBluefox) Added access control options for server
-   (@GermanBluefox) Used `@iobroker/eslint-config` for linting

### 1.0.3 (2023-10-16)

-   (@GermanBluefox) Extend the security checker with the pattern detection and custom URL

### 1.0.1 (2023-10-11)

-   (@GermanBluefox) Changed the error text of the security checker

### 1.0.0 (2023-10-11)

-   (@GermanBluefox) added the security checker

### 0.3.7 (2023-09-24)

-   (raintonr) Fix contexts for SNICallback ([#3](https://github.com/ioBroker/webserver/issues/3)).

### 0.3.6 (2023-07-07)

-   (@GermanBluefox) Update packages

### 0.3.4 (2023-03-27)

-   (@GermanBluefox) Corrected small error with CA certificate

### 0.3.3 (2023-03-24)

-   (@GermanBluefox) Added check of the cert files

### 0.3.1 (2023-03-20)

-   (@GermanBluefox) Corrected error with `getCertificatesAsync`

### 0.3.0 (2023-03-20)

-   (@GermanBluefox) Added support for user-configured certificates for fallback

### 0.2.1 (2023-03-20)

-   (@GermanBluefox) Rename `Webserver` to `WebServer`

### 0.1.0 (2023-03-13)

-   (foxriver76) initial release based on https://github.com/ioBroker/ioBroker.js-controller/pull/2104 by @raintonr

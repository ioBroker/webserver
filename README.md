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

- Javascript:
```javascript
const { WebServer } = require('@iobroker/webserver');

const webServer = new WebServer({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webServer.init();
```

And so you can use `CertificateManager` that is used in the WebServer already:
- typescript:
```typescript
import { CertificateManager } from '@iobroker/webserver';

// Not required for server
const certManager = new CertificateManager({ adapter })

// get all collections
const collections = await certManager.getAllCollections();
```

- Javascript:
```typescript
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
### **WORK IN PROGRESS**
* (bluefox) Rename `Webserver` to `WebServer`

### 0.1.0 (2023-03-13)
* (foxriver76) initial release

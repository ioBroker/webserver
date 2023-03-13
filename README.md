# Webserver for ioBroker adapters

## Description
This module provides a webserver, which automatically takes care of 
certificate handling using the ioBroker certificates.

## How-To
Install via `npm i @iobroker/webserver`.

Use the webserver in your ioBroker adapter as following:

```typescript
import { Webserver, CertificateManager } from '@iobroker/webserver';

const webserver = new Webserver({ app, adapter, secure: true });

// initialize and you can use your server as known
const server = await webserver.init();

const certManager = new CertificateManager({ adapter })

// get all collections
const collections = await certManager.getAllCollections();
```

## Changelog
<!--
  Placeholder for the next version (at the beginning of the line):
  ### **WORK IN PROGRESS**
-->
### 0.1.0 (2023-03-13)
* (foxriver76) initial release

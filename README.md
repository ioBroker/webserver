# Webserver for ioBroker adapters

## Description
This module provides a webserver, which automatically takes care of 
certificate handling using the ioBroker certificates.

## How-To
Install via `npm i @iobroker/webserver`.

Use the webserver in your ioBroker adapter as following:

```typescript
import { Webserver } from '@iobroker/webserver';

const webserver = new Webserver({ app, adapter, secure: true });

await webserver.init();

// now the server is available at webserver.server

// get all collections
const collections = await webserver.getCertificateCollection();
```

## Changelog

### 0.0.1
* (foxriver76) initial release

# Webserver for ioBroker adapters

## How-To

```typescript
import { Webserver } from '@iobroker/webserver';

const webserver = new Webserver({ app, adapter, secure: true });

await webserver.init();

// now the server is available at webserver.server
```
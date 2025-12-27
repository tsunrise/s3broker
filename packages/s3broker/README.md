# S3Broker

[![npm version](https://img.shields.io/npm/v/s3broker.svg)](https://www.npmjs.com/package/s3broker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Cloudflare Workers library for building S3 proxies with guardrails.

## Overview

S3Broker is a TypeScript library for building proxies and guardrails for S3-compatible storage. It sits between your S3 clients and your S3-compatible storage, providing dual-key authentication and policy-based guardrails:

```
==========              ============             ============
||Client|| -- Key A --> ||S3Broker|| -- Key B --> ||Upstream||
==========              ============             ============
```

**Key Features:**

- **Two-Key Authentication**: Clients authenticate with Key A; S3Broker re-signs requests with Key B for the upstream
- **Guardrails Framework**: Configurable policies to protect your data (e.g., prevent deletion of recently created objects)
- **Full S3 Compatibility**: Works with any S3 client (AWS SDK, s3cmd, rclone, etc.)
- **Cloudflare Workers**: Built for Cloudflare Workers runtime

## Installation

```bash
npm install s3broker
```

## Quick Start

```typescript
import { handle } from 's3broker';

export default {
	async fetch(request, env, ctx) {
		return handle(request, {
			s3Endpoint: env.S3_ENDPOINT,
			clientAccessKeyId: env.CLIENT_ACCESS_KEY_ID,
			clientSecretAccessKey: env.CLIENT_SECRET_ACCESS_KEY,
			upstreamAccessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			upstreamSecretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
		});
	},
};
```

## With Custom Guardrails

```typescript
import { handle } from 's3broker';

export default {
	async fetch(request, env, ctx) {
		return handle(request, {
			s3Endpoint: env.S3_ENDPOINT,
			clientAccessKeyId: env.CLIENT_ACCESS_KEY_ID,
			clientSecretAccessKey: env.CLIENT_SECRET_ACCESS_KEY,
			upstreamAccessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			upstreamSecretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
			guardrailConfig: {
				noDeleteOld: [
					{
						pattern: '/protected/.*',
						config: { noDeleteBeforeSeconds: 3600 }, // Files older than 1h in /protected/ could not be deleted
					},
				],
			},
		});
	},
};
```

## Limitations

- **`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`** payload signing method is not supported.

## Documentation

For full documentation, see the [GitHub repository](https://github.com/tsunrise/s3broker).

## License

MIT

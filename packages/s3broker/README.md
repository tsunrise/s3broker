# S3Broker

[![npm version](https://img.shields.io/npm/v/s3broker.svg)](https://www.npmjs.com/package/s3broker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Cloudflare Workers library for building S3 proxies with guardrails.

This is a work in progress. More guardrails and features would be added soon.

## Overview

S3Broker is a TypeScript library for building proxies and guardrails for S3-compatible storage. The library is intended to be used on Cloudflare Workers.

When you have an S3 secret key with read/write access, any client using that key can perform destructive operations. Your data is vulnerable to:

- **Accidental deletion** by users or misconfigured tools
- **Ransomware attacks** that encrypt or delete your files

S3Broker acts as a protective layer between your clients and the upstream S3 endpoint. Instead of giving clients direct access to your upstream key (Key B), you give them a different key (Key A). S3Broker validates every request against configurable guardrails and blocks dangerous operations before they reach your storage.

```
==========              ============             ============
||Client|| -- Key A --> ||S3Broker|| -- Key B --> ||Upstream||
==========              ============             ============
```

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

Example: Reject requests deleting/replacing files older than 1 hour unless the file has path prefix `/frequent_updated/`.

```typescript
import { handle } from 's3broker';

export default {
	async fetch(request, env, ctx) {
		return handle(request, ctx, {
			s3Endpoint: env.S3_ENDPOINT,
			clientAccessKeyId: env.CLIENT_ACCESS_KEY_ID,
			clientSecretAccessKey: env.CLIENT_SECRET_ACCESS_KEY,
			upstreamAccessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			upstreamSecretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
			guardrailConfig: {
				noDeleteOld: [
					{
						pattern: '/frequent_updated/.*',
						config: null,
					},
					{
						pattern: '/.*',
						config: { noDeleteBeforeSeconds: 3600 },
					},
				],
				noReplaceOld: [
					{
						pattern: '/frequent_updated/.*',
						config: null,
					},
					{
						pattern: '/.*',
						config: { noReplaceBeforeSeconds: 3600 },
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

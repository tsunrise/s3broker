# S3Broker

[![npm version](https://img.shields.io/npm/v/s3broker.svg)](https://www.npmjs.com/package/s3broker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An S3-compatible proxy library with SigV4 signature verification and configurable guardrails policies.

This is a work in progress. More guardrails and features would be added soon.

## Overview

S3Broker is a TypeScript library for building proxies and guardrails for S3-compatible storage. It sits between your S3 clients and your S3-compatible storage, providing dual-key authentication and policy-based guardrails:

```
==========              ============             ============
||Client|| -- Key A --> ||S3Broker|| -- Key B --> ||Upstream||
==========              ============             ============
```

**Key Features:**

- **Two-Key Authentication**: Clients authenticate with Key A; S3Broker re-signs requests with Key B for the upstream
- **Guardrails Framework**: Configurable policies to protect your data (e.g., prevent deletion of recently created objects).
- **Full S3 Compatibility**: Works with any S3 client (AWS SDK, s3cmd, rclone, etc.)
- **Platform Agnostic**: Works in Cloudflare Workers, Vercel, Netlify, AWS Lambda, or any JavaScript runtime with Fetch API

## Installation

```bash
npm install s3broker
```

## Quick Start

We show a basic example of how to use S3Broker in a Cloudflare Worker. Those examples should also work in other JavaScript runtimes with Fetch API support.

### Basic Usage (With Default Guardrails)

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

### With Custom Guardrails

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
						pattern: '/protected/.*',
						config: { noDeleteBeforeSeconds: 3600 }, // Files older than 1h in /protected/ could not be deleted
					},
				],
			},
		});
	},
};
```

### Built-in Policies

#### `noDeleteOld`

Prevents deletion of objects unless they were created recently (within `noDeleteBeforeSeconds`).

## Limitations

- **`STREAMING-AWS4-HMAC-SHA256-PAYLOAD`** payload signing method is not supported. Use unsigned payloads or standard SHA256 signing instead.

## About this repository

The repo is structured as a monorepo with the following packages:

- `s3broker` (at `packages/s3broker`): The main library published to npm, living in `packages/s3broker`.
- `s3broker-worker` (at root path): A Cloudflare Worker for the author to test the package with Cloudflare R2 S3-compatible API. You could use it as an example of how to use the library. Note that in `package.json`, it depends on `s3broker` from the monorepo:

  ```
  {"s3broker": "workspace:*"}
  ```

  In production, you should install `s3broker` from npm instead.

## License

MIT

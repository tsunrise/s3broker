/**
 * S3 Proxy Worker - Uses s3broker library
 *
 * This worker is a thin wrapper that uses the S3Broker library to handle
 * all S3 proxy functionality including signature verification, guardrails,
 * and request proxying.
 */

import { handle } from 's3broker';
import type { Env } from './env';

export default {
	async fetch(request, env, _ctx): Promise<Response> {
		// Verify required environment variables
		if (!env.CLIENT_ACCESS_KEY_ID || !env.CLIENT_SECRET_ACCESS_KEY) {
			return new Response('Server configuration error: missing client credentials', { status: 500 });
		}
		if (!env.UPSTREAM_ACCESS_KEY_ID || !env.UPSTREAM_SECRET_ACCESS_KEY) {
			return new Response('Server configuration error: missing upstream credentials', { status: 500 });
		}
		if (!env.S3_ENDPOINT) {
			return new Response('Server configuration error: missing S3_ENDPOINT', { status: 500 });
		}

		// Delegate to S3Broker library
		return handle(request, {
			s3Endpoint: env.S3_ENDPOINT,
			clientAccessKeyId: env.CLIENT_ACCESS_KEY_ID,
			clientSecretAccessKey: env.CLIENT_SECRET_ACCESS_KEY,
			upstreamAccessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			upstreamSecretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
		});
	},
} satisfies ExportedHandler<Env>;

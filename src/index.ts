/**
 * S3 Proxy Worker - Uses s3broker library
 *
 * This worker is a thin wrapper that uses the S3Broker library to handle
 * all S3 proxy functionality including signature verification, guardrails,
 * and request proxying.
 */

import { GuardrailConfig, GuardrailConfigZod, handle } from 's3broker';
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

		// Parse custom guardrail policy from env if provided
		let guardrailConfig: GuardrailConfig | undefined;
		if (env.GUARDRAIL_POLICY) {
			try {
				guardrailConfig = GuardrailConfigZod.parse(JSON.parse(env.GUARDRAIL_POLICY));
			} catch {
				return new Response('Server configuration error: invalid GUARDRAIL_POLICY JSON from env', { status: 500 });
			}
		} else {
			guardrailConfig = {
				noDeleteOld: [
					{
						pattern: '/\\w*/free/.*',
						config: null,
					},
					{
						pattern: '/.*',
						config: { noDeleteBeforeSeconds: 60 },
					},
				],
				noReplaceOld: [
					{
						pattern: '/\\w*/free/.*',
						config: null,
					},
					{
						pattern: '/.*',
						config: { noReplaceBeforeSeconds: 60 },
					},
				],
				// Only add managedSse if SSE_KEY is provided
				...(env.SSE_KEY && {
					managedSse: [
						{
							pattern: '/\\w*/encrypted/.*',
							config: { key: env.SSE_KEY },
						},
					],
				}),
			};
		}

		// Delegate to S3Broker library
		return handle(request, {
			s3Endpoint: env.S3_ENDPOINT,
			clientAccessKeyId: env.CLIENT_ACCESS_KEY_ID,
			clientSecretAccessKey: env.CLIENT_SECRET_ACCESS_KEY,
			upstreamAccessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			upstreamSecretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
			guardrailConfig,
		});
	},
} satisfies ExportedHandler<Env>;

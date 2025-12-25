/**
 * S3 Proxy Worker with SigV4 Re-signing
 * 
 * This worker acts as a transparent S3 proxy that:
 * 1. Verifies incoming requests signed with Key A (client credentials)
 * 2. Re-signs requests with Key B (upstream credentials) for Cloudflare R2
 * 3. Proxies the request to the upstream S3-compatible endpoint
 */

import { AwsClient } from 'aws4fetch';
import { verifySignature } from './sigv4';
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

		// Log all headers for debugging
		const headerObj: Record<string, string> = {};
		request.headers.forEach((value, key) => {
			headerObj[key] = value;
		});

		// Verify the incoming request signature (Client Key)
		const verificationResult = await verifySignature(
			request,
			env.CLIENT_SECRET_ACCESS_KEY,
			env.CLIENT_ACCESS_KEY_ID
		);

		if (!verificationResult.valid) {
			return new Response(
				`Signature verification failed: ${verificationResult.error}`,
				{
					status: 403,
					headers: { 'Content-Type': 'text/plain' }
				}
			);
		}

		// Parse the request URL to get the path and query string
		const url = new URL(request.url);

		const upstreamUrl = new URL(url.pathname + url.search, env.S3_ENDPOINT);

		// Create a new request for the upstream, copying only S3-specific headers
		// Use an allowlist approach to be robust against new Cloudflare headers
		const upstreamHeaders = new Headers();
		const headersToInclude = new Set([
			// S3-specific headers
			'x-amz-date',
			'x-amz-content-sha256',
			'x-amz-security-token',  // For temporary credentials
			'x-amz-server-side-encryption',
			'x-amz-server-side-encryption-aws-kms-key-id',
			'x-amz-server-side-encryption-customer-algorithm',
			'x-amz-server-side-encryption-customer-key',
			'x-amz-server-side-encryption-customer-key-md5',
			'x-amz-storage-class',
			'x-amz-tagging',
			'x-amz-website-redirect-location',
			'x-amz-acl',
			'x-amz-grant-read',
			'x-amz-grant-write',
			'x-amz-grant-read-acp',
			'x-amz-grant-write-acp',
			'x-amz-grant-full-control',
			'x-amz-metadata-directive',
			'x-amz-copy-source',
			'x-amz-copy-source-if-match',
			'x-amz-copy-source-if-none-match',
			'x-amz-copy-source-if-unmodified-since',
			'x-amz-copy-source-if-modified-since',
			'x-amz-copy-source-range',
			// Standard HTTP headers that S3 uses
			'content-type',
			'content-length',
			'content-md5',
			'content-encoding',
			'content-disposition',
			'cache-control',
			'expires',
			'range',
			'if-match',
			'if-none-match',
			'if-modified-since',
			'if-unmodified-since',
			// User agent for debugging
			'user-agent',
		]);

		for (const [key, value] of request.headers.entries()) {
			if (headersToInclude.has(key.toLowerCase())) {
				upstreamHeaders.set(key, value);
			}
		}

		// Force UNSIGNED-PAYLOAD for the upstream request
		upstreamHeaders.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');

		// Create the upstream request
		const upstreamRequest = new Request(upstreamUrl.toString(), {
			method: request.method,
			headers: upstreamHeaders,
			body: request.body,
			// @ts-ignore - duplex is needed for streaming bodies
			duplex: 'half',
		});

		// Initialize AWS client with upstream credentials (Key B)
		const aws = new AwsClient({
			accessKeyId: env.UPSTREAM_ACCESS_KEY_ID,
			secretAccessKey: env.UPSTREAM_SECRET_ACCESS_KEY,
			retries: 0
		});

		// Sign and send the request to upstream
		try {
			const response = await aws.fetch(upstreamRequest);

			if (!response.ok) {
				// Clone the response so we can read the body for logging
				// while still returning the original response to the client
				const responseClone = response.clone();
				const errorBody = await responseClone.text();
				console.log(`Upstream request failed: ${response.status} ${response.statusText}, response: ${errorBody}`);
			}

			// Always return the upstream response to the client (including errors)
			// This properly handles the response body and avoids stalled response warnings
			return new Response(response.body, {
				status: response.status,
				statusText: response.statusText,
				headers: response.headers,
			});
		} catch (error) {
			console.error('Upstream request failed:', error);
			return new Response(
				`Upstream request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
				{ status: 502 }
			);
		}
	},
} satisfies ExportedHandler<Env>;

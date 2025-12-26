/**
 * S3Broker - S3 Proxy Library with SigV4 Verification and Guardrails
 *
 * ==========              ===========             ============
 * ||Client|| -- Key A --> ||S3Broker|| -- Key B --> ||Upstream||
 * ==========              ===========             ============
 *
 * S3Broker is a library for building secure S3-compatible proxies. It can be used in:
 * - Cloudflare Workers
 * - Any other serverless platforms (Vercel, Netlify, etc.)
 * - Any JavaScript/TypeScript runtime with fetch API support
 *
 * Features:
 * 1. Verifies incoming requests signed with Key A (client credentials)
 * 2. Enforces configurable guardrails policies (e.g., prevent deletion of recent objects)
 * 3. Re-signs requests with Key B (upstream credentials) for the upstream S3 service
 * 4. Proxies the request to any S3-compatible endpoint (AWS S3, Cloudflare R2, MinIO, etc.)
 */

import { AwsClient } from 'aws4fetch';
import { verifySignature } from './sigv4';
import { textErrorResponse, ErrorCode } from './utils';
import { evaluateGuardrails } from './guardrails/guardrails';
import type { S3BrokerOptions } from './types';
import { GuardrailConfig } from './guardrails/type';

// Re-export types
export type { S3BrokerOptions } from './types';
export type { GuardrailConfig, GuardrailViolation } from './guardrails/type';

// Headers that should be forwarded to upstream (allowlist approach)
const HEADERS_TO_INCLUDE = new Set([
	// S3-specific headers
	'x-amz-date',
	'x-amz-content-sha256',
	'x-amz-security-token',
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
	'user-agent',
]);

// Presigned URL parameters that should be stripped when re-signing
const PRESIGNED_PARAMS = new Set([
	'X-Amz-Algorithm',
	'X-Amz-Credential',
	'X-Amz-Date',
	'X-Amz-Expires',
	'X-Amz-SignedHeaders',
	'X-Amz-Signature',
	'X-Amz-Security-Token',
]);

export const defaultGuardrailConfig: GuardrailConfig = {
	noDeleteOld: [
		{
			pattern: '/.*',
			config: {
				noDeleteBeforeSeconds: 60,
			},
		},
	],
};

/**
 * Handle an incoming S3 request with signature verification, guardrails, and proxying.
 *
 * @param request - The incoming HTTP request (must be a valid S3 API request)
 * @param options - S3Broker configuration options including credentials and guardrails
 * @returns Response from the upstream S3 service, or an error response if validation fails
 *
 * @example
 * ```typescript
 * import { handle } from 's3broker';
 *
 * const response = await handle(request, ctx, {
 *   s3Endpoint: 'https://my-bucket.s3.amazonaws.com',
 *   clientAccessKeyId: 'CLIENT_KEY',
 *   clientSecretAccessKey: 'CLIENT_SECRET',
 *   upstreamAccessKeyId: 'UPSTREAM_KEY',
 *   upstreamSecretAccessKey: 'UPSTREAM_SECRET',
 * });
 * ```
 */
export async function handle(request: Request<unknown, IncomingRequestCfProperties>, options: S3BrokerOptions): Promise<Response> {
	const currentTimestamp = Date.now();

	// Verify the incoming request signature (Client Key)
	const verificationResult = await verifySignature(request, options.clientSecretAccessKey, options.clientAccessKeyId, currentTimestamp);

	if (!verificationResult.valid) {
		return textErrorResponse(`Signature verification failed: ${verificationResult.error}`, ErrorCode.Forbidden);
	}

	// Parse the request URL
	const url = new URL(request.url);

	// Evaluate guardrails
	const guardrailUpstreamClient = new AwsClient({
		accessKeyId: options.upstreamAccessKeyId,
		secretAccessKey: options.upstreamSecretAccessKey,
		retries: 5,
	});

	const guardrailViolation = await evaluateGuardrails(
		request,
		guardrailUpstreamClient,
		options.s3Endpoint,
		currentTimestamp,
		options.guardrailConfig || defaultGuardrailConfig,
	);

	if (guardrailViolation) {
		console.log(`Guardrail violation`, {
			path: url.pathname,
			method: request.method,
			query: url.search,
			policy: guardrailViolation.policy,
			violation: guardrailViolation.violation,
		});
		return textErrorResponse(
			`Request violating guardrail policy ${guardrailViolation.policy}: ${guardrailViolation.violation}`,
			ErrorCode.Forbidden,
		);
	}

	// Build upstream URL, stripping presigned parameters
	const upstreamUrl = new URL(url.pathname, options.s3Endpoint);
	for (const [key, value] of url.searchParams.entries()) {
		if (!PRESIGNED_PARAMS.has(key)) {
			upstreamUrl.searchParams.set(key, value);
		}
	}

	// Build upstream headers (allowlist approach)
	const upstreamHeaders = new Headers();
	for (const [key, value] of request.headers.entries()) {
		if (HEADERS_TO_INCLUDE.has(key.toLowerCase())) {
			upstreamHeaders.set(key, value);
		}
	}
	upstreamHeaders.set('x-amz-content-sha256', 'UNSIGNED-PAYLOAD');

	// Create upstream request
	const upstreamRequest = new Request(upstreamUrl.toString(), {
		method: request.method,
		headers: upstreamHeaders,
		body: request.body,
		// @ts-ignore - duplex is needed for streaming bodies
		duplex: 'half',
	});

	// Sign and send to upstream
	const proxyUpstreamAws = new AwsClient({
		accessKeyId: options.upstreamAccessKeyId,
		secretAccessKey: options.upstreamSecretAccessKey,
		retries: 0,
	});

	try {
		return await proxyUpstreamAws.fetch(upstreamRequest);
	} catch (error) {
		console.error('Upstream request failed:', error);
		return textErrorResponse(
			`Upstream request failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
			ErrorCode.UpstreamFailure,
		);
	}
}

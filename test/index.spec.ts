import { env, createExecutionContext, waitOnExecutionContext, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import worker from '../src/index';
import { parseAuthorizationHeader, verifySignature } from '../src/sigv4';
import type { Env } from '../src/env';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('SigV4 Utilities', () => {
	describe('parseAuthorizationHeader', () => {
		it('parses valid AWS4-HMAC-SHA256 header', () => {
			const header = 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231224/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123';
			const result = parseAuthorizationHeader(header);

			expect(result.algorithm).toBe('AWS4-HMAC-SHA256');
			expect(result.credential.accessKeyId).toBe('AKIAIOSFODNN7EXAMPLE');
			expect(result.credential.date).toBe('20231224');
			expect(result.credential.region).toBe('us-east-1');
			expect(result.credential.service).toBe('s3');
			expect(result.signedHeaders).toEqual(['host', 'x-amz-date']);
			expect(result.signature).toBe('abc123');
		});

		it('throws on invalid header format', () => {
			expect(() => parseAuthorizationHeader('Bearer token123')).toThrow();
		});

		it('throws on missing parameters', () => {
			expect(() => parseAuthorizationHeader('AWS4-HMAC-SHA256 Credential=AKID/20231224/us-east-1/s3/aws4_request')).toThrow();
		});
	});

	describe('verifySignature', () => {
		it('rejects request with missing Authorization header', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key');
			const result = await verifySignature(request, 'secret', 'AKID');

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Authorization');
		});

		it('rejects streaming payload signatures', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key', {
				headers: {
					'Authorization': 'AWS4-HMAC-SHA256 Credential=AKID/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
					'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
					'x-amz-date': '20231224T120000Z',
				},
			});
			const result = await verifySignature(request, 'secret', 'AKID');

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Streaming payload');
		});

		it('rejects mismatched access key ID', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key', {
				headers: {
					'Authorization': 'AWS4-HMAC-SHA256 Credential=WRONGKEY/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
					'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
					'x-amz-date': '20231224T120000Z',
					'host': 'example.com',
				},
			});
			const result = await verifySignature(request, 'secret', 'AKID');

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Access key ID');
		});
	});
});

describe('S3 Proxy Worker', () => {
	// Mock environment with test credentials
	const testEnv: Env = {
		CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
		CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
		UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
		S3_ENDPOINT: 'https://test.r2.cloudflarestorage.com',
	};

	it('returns 500 if environment is not configured', async () => {
		const request = new IncomingRequest('https://example.com/bucket/key');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, env, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(500);
		expect(await response.text()).toContain('configuration error');
	});

	it('returns 403 if Authorization header is missing', async () => {
		const request = new IncomingRequest('https://example.com/bucket/key');
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain('Signature verification failed');
	});

	it('returns 403 if signature is invalid', async () => {
		const request = new IncomingRequest('https://example.com/bucket/key', {
			headers: {
				'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=invalidsignature',
				'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
				'x-amz-date': '20231224T120000Z',
				'host': 'example.com',
			},
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});

	it('rejects streaming payload signatures', async () => {
		const request = new IncomingRequest('https://example.com/bucket/key', {
			headers: {
				'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
				'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
				'x-amz-date': '20231224T120000Z',
				'host': 'example.com',
			},
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain('Streaming payload');
	});
});

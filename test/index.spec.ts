import { createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index';
import { parseAuthorizationHeader, verifySignature } from 's3broker/sigv4';
import type { Env } from '../src/env';

// For now, you'll need to do something like this to get a correctly-typed
// `Request` to pass to `worker.fetch()`.
const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;

describe('SigV4 Utilities', () => {
	describe('parseAuthorizationHeader', () => {
		it('parses valid AWS4-HMAC-SHA256 header', () => {
			const header =
				'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231224/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abc123';
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
			const result = await verifySignature(request, 'secret', 'AKID', Date.now());

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Authorization');
		});

		it('rejects streaming payload signatures', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key', {
				headers: {
					Authorization: 'AWS4-HMAC-SHA256 Credential=AKID/20251226/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
					'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
					'x-amz-date': '20251226T001100Z',
				},
			});
			const result = await verifySignature(request, 'secret', 'AKID', Date.UTC(2025, 11, 26, 0, 12, 0));

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Streaming payload');
		});

		it('rejects mismatched access key ID', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key', {
				headers: {
					Authorization: 'AWS4-HMAC-SHA256 Credential=WRONGKEY/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
					'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
					'x-amz-date': '20231224T120000Z',
					host: 'example.com',
				},
			});
			const result = await verifySignature(request, 'secret', 'AKID', Date.UTC(2023, 11, 24, 12, 2, 0));

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Access key ID');
		});

		it('rejects requests with stale timestamps (>5 min)', async () => {
			const request = new IncomingRequest('https://example.com/bucket/key', {
				headers: {
					Authorization: 'AWS4-HMAC-SHA256 Credential=AKID/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc',
					'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
					'x-amz-date': '20231224T120000Z',
					host: 'example.com',
				},
			});
			// Current time is 6 minutes after the request date
			// Request: 2023-12-24 12:00:00 UTC, Current: 2023-12-24 12:06:00 UTC
			const currentTime = Date.UTC(2023, 11, 24, 12, 6, 0);
			const result = await verifySignature(request, 'secret', 'AKID', currentTime);

			expect(result.valid).toBe(false);
			expect(result.error).toContain('Request date too old');
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
		const response = await worker.fetch(request, {} as Env, ctx);
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
				Authorization:
					'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20231224/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=invalidsignature',
				'x-amz-content-sha256': 'UNSIGNED-PAYLOAD',
				'x-amz-date': '20231224T120000Z',
				host: 'example.com',
			},
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
	});

	it('rejects streaming payload signatures', async () => {
		// Use current date to pass staleness check
		const now = new Date();
		const dateStamp = now.toISOString().slice(0, 10).replace(/-/g, '');
		const amzDate = now.toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		const request = new IncomingRequest('https://example.com/bucket/key', {
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/${dateStamp}/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc`,
				'x-amz-content-sha256': 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
				'x-amz-date': amzDate,
				host: 'example.com',
			},
		});
		const ctx = createExecutionContext();
		const response = await worker.fetch(request, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(403);
		expect(await response.text()).toContain('Streaming payload');
	});

	it('proxies valid requests to upstream successfully', async () => {
		// Import fetchMock from cloudflare:test and signature utilities
		const { fetchMock } = await import('cloudflare:test');
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');

		// Enable mocking and set up mock response
		fetchMock.activate();
		fetchMock
			.get('https://test.r2.cloudflarestorage.com')
			.intercept({ path: '/bucket/test-key', method: 'GET' })
			.reply(200, 'mock object content', {
				headers: { 'Content-Type': 'text/plain' },
			});

		// Generate a properly signed request with current timestamp (to pass staleness check)
		const now = new Date();
		const currentDate = now.toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = now.toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';
		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = 'https://example.com/bucket/test-key';

		// Create unsigned request to build canonical request
		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'GET',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});

		// Build canonical request and derive signature
		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnv.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		// Create the properly signed request
		const signedRequest = new IncomingRequest(requestUrl, {
			method: 'GET',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnv.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		expect(response.status).toBe(200);
		expect(await response.text()).toBe('mock object content');

		// Deactivate mock
		fetchMock.deactivate();
	});
});

describe('Guardrails - NoDeleteOld', () => {
	const testEnv: Env = {
		CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
		CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
		UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
		S3_ENDPOINT: 'https://test.r2.cloudflarestorage.com',
	};

	/**
	 * Helper to create a signed DELETE request
	 */
	async function createSignedDeleteRequest(
		path: string,
		currentDate: string,
		currentAmzDate: string,
	): Promise<Request<unknown, IncomingRequestCfProperties>> {
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');

		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = `https://example.com${path}`;

		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'DELETE',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});

		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnv.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		return new IncomingRequest(requestUrl, {
			method: 'DELETE',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnv.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});
	}

	it('blocks deletion of objects older than threshold', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Create S3 mock with an object created 120 seconds ago (older than 60s threshold)
		const s3Mock = new S3Mock(testEnv.S3_ENDPOINT);
		const objectCreatedAt = now - 120 * 1000; // 120 seconds ago
		s3Mock.putObject('/bucket/old-object', 'old content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request
		const signedRequest = await createSignedDeleteRequest('/bucket/old-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be blocked by guardrail (403 Forbidden)
		expect(response.status).toBe(403);
		const text = await response.text();
		expect(text).toContain('noDeleteOld');
		expect(text).toContain('exceeds');
	});

	it('allows deletion of recently created objects', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint to avoid mock conflicts with other tests
		const uniqueEndpoint = 'https://test2.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		// Create S3 mock with an object created 30 seconds ago (within 60s threshold)
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 30 * 1000; // 30 seconds ago
		s3Mock.putObject('/bucket/new-object', 'new content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request (reuse helper but with unique env for signing)
		const signedRequest = await createSignedDeleteRequest('/bucket/new-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed (204 No Content from upstream mock)
		expect(response.status).toBe(204);
	});
});

describe('Guardrails - Exclude Rules (null config)', () => {
	const testEnv: Env = {
		CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
		CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
		UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
		S3_ENDPOINT: 'https://test-exclude.r2.cloudflarestorage.com',
		GUARDRAIL_POLICY: JSON.stringify({
			noDeleteOld: [
				{ pattern: '/bucket/free/.*', config: null }, // Exclude /free/ paths from guardrail
				{ pattern: '/bucket/.*', config: { noDeleteBeforeSeconds: 60 } }, // Apply to all other paths
			],
		}),
	};

	/**
	 * Helper to create a signed DELETE request
	 */
	async function createSignedDeleteRequest(
		path: string,
		currentDate: string,
		currentAmzDate: string,
	): Promise<Request<unknown, IncomingRequestCfProperties>> {
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');

		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = `https://example.com${path}`;

		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'DELETE',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});

		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnv.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		return new IncomingRequest(requestUrl, {
			method: 'DELETE',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnv.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
		});
	}

	it('allows deletion of old objects in excluded paths (/free/)', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Create S3 mock with an old object in /free/ path (120 seconds old, exceeds 60s threshold)
		const s3Mock = new S3Mock(testEnv.S3_ENDPOINT);
		const objectCreatedAt = now - 120 * 1000; // 120 seconds ago
		s3Mock.putObject('/bucket/free/old-object', 'old content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request for /free/ path
		const signedRequest = await createSignedDeleteRequest('/bucket/free/old-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed (204 No Content) because /free/ is excluded from guardrail
		expect(response.status).toBe(204);
	});

	it('blocks deletion of old objects in protected paths', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint to avoid mock conflicts
		const uniqueEndpoint = 'https://test-exclude2.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		// Create S3 mock with an old object in /protected/ path (120 seconds old, exceeds 60s threshold)
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 120 * 1000; // 120 seconds ago
		s3Mock.putObject('/bucket/protected/old-object', 'old content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request for /protected/ path
		const signedRequest = await createSignedDeleteRequest('/bucket/protected/old-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be blocked by guardrail (403 Forbidden) because /protected/ matches the second pattern
		expect(response.status).toBe(403);
		const text = await response.text();
		expect(text).toContain('noDeleteOld');
	});

	it('first matching pattern wins - more specific exclude takes priority', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint
		const uniqueEndpoint = 'https://test-exclude3.r2.cloudflarestorage.com';
		const testEnvSpecificFirst: Env = {
			CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
			CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
			UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
			UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
			S3_ENDPOINT: uniqueEndpoint,
			GUARDRAIL_POLICY: JSON.stringify({
				noDeleteOld: [
					{ pattern: '/bucket/free/vip/.*', config: { noDeleteBeforeSeconds: 120 } }, // VIP within free still protected
					{ pattern: '/bucket/free/.*', config: null }, // Exclude /free/ paths
					{ pattern: '/bucket/.*', config: { noDeleteBeforeSeconds: 60 } }, // Protect all other paths
				],
				noReplaceOld: [],
			}),
		};

		// Create S3 mock with an old object in /free/vip/ path (90 seconds old)
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 90 * 1000; // 90 seconds ago (within 120s threshold, but > 60s)
		s3Mock.putObject('/bucket/free/vip/important', 'vip content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request for /free/vip/ path
		const signedRequest = await createSignedDeleteRequest('/bucket/free/vip/important', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvSpecificFirst, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed because object age (90s) is within the 120s threshold of the first matching pattern
		expect(response.status).toBe(204);
	});

	it('pattern matches full path only (not substring)', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint
		const uniqueEndpoint = 'https://test-fullmatch.r2.cloudflarestorage.com';
		const testEnvFullMatch: Env = {
			CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
			CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
			UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
			UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
			S3_ENDPOINT: uniqueEndpoint,
			GUARDRAIL_POLICY: JSON.stringify({
				// Pattern '/bucket/tom/.*' should match '/bucket/tom/a' but NOT '/bucket/alpha/tom/a'
				noDeleteOld: [{ pattern: '/bucket/tom/.*', config: { noDeleteBeforeSeconds: 60 } }],
			}),
		};

		// Create S3 mock with an old object at path that contains 'tom' but doesn't START with '/bucket/tom/'
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 120 * 1000; // 120 seconds ago
		s3Mock.putObject('/bucket/alpha/tom/file', 'old content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed DELETE request for '/bucket/alpha/tom/file' - should NOT match pattern '/bucket/tom/.*'
		const signedRequest = await createSignedDeleteRequest('/bucket/alpha/tom/file', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvFullMatch, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed (204 No Content) because '/bucket/alpha/tom/file' does NOT match pattern '/bucket/tom/.*'
		// The pattern requires the path to START with '/bucket/tom/', not just contain 'tom' somewhere
		expect(response.status).toBe(204);
	});
});

describe('Guardrails - NoReplaceOld', () => {
	const testEnv: Env = {
		CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
		CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
		UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
		S3_ENDPOINT: 'https://test-replace.r2.cloudflarestorage.com',
		GUARDRAIL_POLICY: JSON.stringify({
			noReplaceOld: [{ pattern: '/.*', config: { noReplaceBeforeSeconds: 60 } }],
		}),
	};

	/**
	 * Helper to create a signed PUT request
	 */
	async function createSignedPutRequest(
		path: string,
		currentDate: string,
		currentAmzDate: string,
		body: string = 'new content',
	): Promise<Request<unknown, IncomingRequestCfProperties>> {
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');

		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = `https://example.com${path}`;

		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
			body,
		});

		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnv.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		return new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnv.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
			body,
		});
	}

	it('blocks replacing objects older than threshold', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint to avoid mock conflicts
		const uniqueEndpoint = 'https://test-replace-block.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		// Create S3 mock with an object created 120 seconds ago (older than 60s threshold)
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 120 * 1000; // 120 seconds ago
		s3Mock.putObject('/bucket/old-object', 'old content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed PUT request
		const signedRequest = await createSignedPutRequest('/bucket/old-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be blocked by guardrail (403 Forbidden)
		expect(response.status).toBe(403);
		const text = await response.text();
		expect(text).toContain('noReplaceOld');
		expect(text).toContain('exceeds');
	});

	it('allows replacing recently created objects', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint to avoid mock conflicts with other tests
		const uniqueEndpoint = 'https://test-replace2.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		// Create S3 mock with an object created 30 seconds ago (within 60s threshold)
		const s3Mock = new S3Mock(uniqueEndpoint);
		const objectCreatedAt = now - 30 * 1000; // 30 seconds ago
		s3Mock.putObject('/bucket/new-object', 'new content', new Headers(), {
			currentTimestampMs: objectCreatedAt,
		});

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed PUT request
		const signedRequest = await createSignedPutRequest('/bucket/new-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed (200 OK from upstream mock)
		expect(response.status).toBe(200);
	});

	it('allows creating new objects (PUT to non-existing path)', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Current time for the test
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		// Use a unique endpoint
		const uniqueEndpoint = 'https://test-replace3.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		// Create S3 mock with NO existing object at the path
		const s3Mock = new S3Mock(uniqueEndpoint);
		// Don't put any object - simulating creating a new object

		// Activate fetch mocking and attach S3 mock
		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create signed PUT request for a non-existing object
		const signedRequest = await createSignedPutRequest('/bucket/brand-new-object', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be allowed (200 OK from upstream mock) - creating new objects is always allowed
		expect(response.status).toBe(200);
	});
});

describe('Managed SSE', () => {
	// Test base64 key (32 bytes = 256 bits for AES-256)
	const testKey = btoa('12345678901234567890123456789012'); // 32-byte key base64 encoded

	const testEnv: Env = {
		CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
		CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
		UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
		UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
		S3_ENDPOINT: 'https://test-sse.r2.cloudflarestorage.com',
		GUARDRAIL_POLICY: JSON.stringify({
			managedSse: [{ pattern: '/bucket/encrypted/.*', config: { key: testKey } }],
		}),
	};

	/**
	 * Helper to create a signed PUT request
	 */
	async function createSignedPutRequest(
		path: string,
		currentDate: string,
		currentAmzDate: string,
		body: string = 'test content',
	): Promise<Request<unknown, IncomingRequestCfProperties>> {
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');

		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = `https://example.com${path}`;

		const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
			body,
		});

		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnv.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		return new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnv.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
			},
			body,
		});
	}

	it('injects SSE headers for PUT requests in managed SSE paths', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		const s3Mock = new S3Mock(testEnv.S3_ENDPOINT);

		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		const signedRequest = await createSignedPutRequest('/bucket/encrypted/file.txt', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnv, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		expect(response.status).toBe(200);

		// Verify SSE headers were sent to upstream
		const capturedHeaders = s3Mock.getLastRequestHeaders('/bucket/encrypted/file.txt');
		expect(capturedHeaders).toBeDefined();
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-algorithm']).toBe('AES256');
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-key']).toBe(testKey);
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-key-md5']).toBeDefined();
	});

	it('does not inject SSE headers for paths outside managed SSE config', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		const uniqueEndpoint = 'https://test-sse2.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		const s3Mock = new S3Mock(uniqueEndpoint);

		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Use path outside the managed SSE pattern (/bucket/encrypted/.*)
		const signedRequest = await createSignedPutRequest('/bucket/unencrypted/file.txt', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		expect(response.status).toBe(200);

		// Verify SSE headers were NOT sent to upstream
		const capturedHeaders = s3Mock.getLastRequestHeaders('/bucket/unencrypted/file.txt');
		expect(capturedHeaders).toBeDefined();
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-algorithm']).toBeUndefined();
	});

	it('passes through client-provided SSE headers without overwriting', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		const clientKey = btoa('clientkey1234567890123456789012'); // Different 32-byte key

		const uniqueEndpoint = 'https://test-sse3.r2.cloudflarestorage.com';
		const testEnvWithUniqueEndpoint: Env = {
			...testEnv,
			S3_ENDPOINT: uniqueEndpoint,
		};

		const s3Mock = new S3Mock(uniqueEndpoint);

		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Create request with client-provided SSE headers
		const { deriveSigningKey, calculateSignature, buildCanonicalRequest, createStringToSign } = await import('s3broker/sigv4');
		const region = 'us-east-1';
		const service = 's3';
		const signedHeaders = ['host', 'x-amz-content-sha256', 'x-amz-date', 'x-amz-server-side-encryption-customer-algorithm'];
		const payloadHash = 'UNSIGNED-PAYLOAD';
		const requestUrl = 'https://example.com/bucket/encrypted/file.txt';

		const IncomingRequest = Request<unknown, IncomingRequestCfProperties>;
		const unsignedRequest = new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
				'x-amz-server-side-encryption-customer-algorithm': 'AES256',
				'x-amz-server-side-encryption-customer-key': clientKey,
				'x-amz-server-side-encryption-customer-key-md5': 'client-md5',
			},
			body: 'test content',
		});

		const canonicalRequest = await buildCanonicalRequest(unsignedRequest, signedHeaders, payloadHash, false);
		const credentialScope = `${currentDate}/${region}/${service}/aws4_request`;
		const stringToSign = await createStringToSign('AWS4-HMAC-SHA256', currentAmzDate, credentialScope, canonicalRequest);
		const signingKey = await deriveSigningKey(testEnvWithUniqueEndpoint.CLIENT_SECRET_ACCESS_KEY, currentDate, region, service);
		const signature = await calculateSignature(signingKey, stringToSign);

		const signedRequest = new IncomingRequest(requestUrl, {
			method: 'PUT',
			headers: {
				Authorization: `AWS4-HMAC-SHA256 Credential=${testEnvWithUniqueEndpoint.CLIENT_ACCESS_KEY_ID}/${currentDate}/${region}/${service}/aws4_request, SignedHeaders=${signedHeaders.join(';')}, Signature=${signature}`,
				host: 'example.com',
				'x-amz-content-sha256': payloadHash,
				'x-amz-date': currentAmzDate,
				'x-amz-server-side-encryption-customer-algorithm': 'AES256',
				'x-amz-server-side-encryption-customer-key': clientKey,
				'x-amz-server-side-encryption-customer-key-md5': 'client-md5',
			},
			body: 'test content',
		});

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithUniqueEndpoint, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		expect(response.status).toBe(200);

		// Verify CLIENT's SSE headers were sent (not the managed key)
		const capturedHeaders = s3Mock.getLastRequestHeaders('/bucket/encrypted/file.txt');
		expect(capturedHeaders).toBeDefined();
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-key']).toBe(clientKey);
		expect(capturedHeaders!['x-amz-server-side-encryption-customer-key-md5']).toBe('client-md5');
	});

	it('guardrails work on encrypted paths (SSE headers in HEAD request)', async () => {
		const { fetchMock } = await import('cloudflare:test');
		const { S3Mock } = await import('./s3mock');

		// Setup: object created 2 minutes ago (older than threshold)
		const oldObjectCreationTime = Date.now() - 120_000;
		const now = Date.now();
		const currentDate = new Date(now).toISOString().slice(0, 10).replace(/-/g, '');
		const currentAmzDate = new Date(now).toISOString().replace(/[-:]/g, '').slice(0, 15) + '00Z';

		const uniqueEndpoint = 'https://test-sse4.r2.cloudflarestorage.com';
		// Config with both noReplaceOld guardrail and SSE
		const testEnvWithGuardrails: Env = {
			CLIENT_ACCESS_KEY_ID: 'AKIAIOSFODNN7EXAMPLE',
			CLIENT_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
			UPSTREAM_ACCESS_KEY_ID: 'AKIOUPSTREAM12345678',
			UPSTREAM_SECRET_ACCESS_KEY: 'upstreamSecretKey1234567890abcdefghijklmn',
			S3_ENDPOINT: uniqueEndpoint,
			GUARDRAIL_POLICY: JSON.stringify({
				noReplaceOld: [{ pattern: '/bucket/encrypted/.*', config: { noReplaceBeforeSeconds: 60 } }],
				managedSse: [{ pattern: '/bucket/encrypted/.*', config: { key: testKey } }],
			}),
		};

		const s3Mock = new S3Mock(uniqueEndpoint);
		// Pre-populate with an old encrypted object
		s3Mock.putObject('/bucket/encrypted/old-file.txt', 'old content', new Headers(), {
			currentTimestampMs: oldObjectCreationTime,
		});

		fetchMock.activate();
		s3Mock.attachToMock(fetchMock);

		// Try to replace the old encrypted object
		const signedRequest = await createSignedPutRequest('/bucket/encrypted/old-file.txt', currentDate, currentAmzDate);

		const ctx = createExecutionContext();
		const response = await worker.fetch(signedRequest, testEnvWithGuardrails, ctx);
		await waitOnExecutionContext(ctx);

		fetchMock.deactivate();

		// Should be blocked by guardrail (403)
		expect(response.status).toBe(403);
		const text = await response.text();
		expect(text).toContain('noReplaceOld');

		// Verify HEAD request included SSE headers (proving it can read encrypted object metadata)
		const headHeaders = s3Mock.getLastHeadRequestHeaders('/bucket/encrypted/old-file.txt');
		expect(headHeaders).toBeDefined();
		expect(headHeaders!['x-amz-server-side-encryption-customer-algorithm']).toBe('AES256');
		expect(headHeaders!['x-amz-server-side-encryption-customer-key']).toBe(testKey);
		expect(headHeaders!['x-amz-server-side-encryption-customer-key-md5']).toBeDefined();
	});
});

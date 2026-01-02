/**
 * Managed SSE-C (Server-Side Encryption with Customer-Provided Keys) module.
 *
 * Automatically injects SSE-C headers for configured paths, making encryption
 * seamless to clients.
 */

import { HeaderModifier, HandleResponseResult, ManagedSseConfig } from '../guardrails/type';

// SSE-C header names
const SSE_ALGORITHM_HEADER = 'x-amz-server-side-encryption-customer-algorithm';
const SSE_KEY_HEADER = 'x-amz-server-side-encryption-customer-key';
const SSE_KEY_MD5_HEADER = 'x-amz-server-side-encryption-customer-key-md5';

/**
 * Compute MD5 hash of a base64-encoded key and return as base64.
 */
async function computeKeyMd5(base64Key: string): Promise<string> {
	// Decode base64 key to bytes
	const keyBytes = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));

	// Compute MD5 hash using Web Crypto API
	const hashBuffer = await crypto.subtle.digest('MD5', keyBytes);

	// Encode hash as base64
	const hashArray = new Uint8Array(hashBuffer);
	return btoa(String.fromCharCode(...hashArray));
}

/**
 * ManagedSseModifier implements HeaderModifier to automatically inject
 * SSE-C headers for PUT/GET/HEAD requests when the client hasn't provided their own.
 */
export class ManagedSseModifier implements HeaderModifier {
	private base64Key: string;
	private keyMd5Promise: Promise<string>;

	constructor(config: ManagedSseConfig) {
		this.base64Key = config.key;
		// Compute MD5 eagerly but cache the promise for reuse
		this.keyMd5Promise = computeKeyMd5(config.key);
	}

	async modifyHeaders(request: Request<unknown, IncomingRequestCfProperties>, upstreamHeaders: Headers): Promise<Headers> {
		// Skip if client already provided SSE headers (passthrough)
		if (upstreamHeaders.has(SSE_ALGORITHM_HEADER)) {
			return upstreamHeaders;
		}

		// For methods that don't use SSE-C (e.g., DELETE, LIST), skip
		const method = request.method.toUpperCase();
		if (method !== 'GET' && method !== 'HEAD' && method !== 'PUT') {
			return upstreamHeaders;
		}

		// Clone headers and add managed SSE headers
		const headers = new Headers(upstreamHeaders);
		headers.set(SSE_ALGORITHM_HEADER, 'AES256');
		headers.set(SSE_KEY_HEADER, this.base64Key);
		headers.set(SSE_KEY_MD5_HEADER, await this.keyMd5Promise);
		return headers;
	}

	handleResponse(upstreamResponse: Response, sentRequestHeaders: Headers): HandleResponseResult {
		// For GET/HEAD: If 400 error (wrong key), retry without SSE headers
		// This handles unencrypted legacy files in managed SSE paths
		if (upstreamResponse.status === 400) {
			const retryHeaders = new Headers(sentRequestHeaders);
			retryHeaders.delete(SSE_ALGORITHM_HEADER);
			retryHeaders.delete(SSE_KEY_HEADER);
			retryHeaders.delete(SSE_KEY_MD5_HEADER);
			return { retryRequest: retryHeaders };
		}
		return { modifiedResponse: upstreamResponse };
	}
}

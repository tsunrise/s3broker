import { GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { z } from 'zod';

export const NoReplaceOldPolicyConfig = z.object({
	noReplaceBeforeSeconds: z.number().int(),
});

export type NoReplaceOldPolicyConfig = z.infer<typeof NoReplaceOldPolicyConfig>;

/**
 * Check if request is a write/upload operation:
 * - PUT method (standard object upload)
 * - POST method without special query params (browser-based form upload)
 *
 * Note: POST with ?delete is handled by NoDeleteOldPolicy
 * Note: POST with ?uploads is multipart initiation (creates new, doesn't replace)
 */
function isWriteRequest(request: Request<unknown, IncomingRequestCfProperties>): boolean {
	if (request.method === 'PUT') {
		return true;
	}
	// POST without special query params is a form-based upload
	if (request.method === 'POST') {
		const url = new URL(request.url);
		// Exclude bulk delete (handled by NoDeleteOldPolicy)
		if (url.searchParams.has('delete')) {
			return false;
		}
		// Exclude multipart upload initiation (creates new object, doesn't replace)
		if (url.searchParams.has('uploads')) {
			return false;
		}
		// Other POST requests (form uploads) can overwrite objects
		return true;
	}
	return false;
}

export class NoReplaceOldPolicy implements GuardrailPolicy {
	private config: NoReplaceOldPolicyConfig;
	private currentTimestampMs: number;

	constructor(config: NoReplaceOldPolicyConfig, currentTimestampMs: number) {
		this.config = config;
		this.currentTimestampMs = currentTimestampMs;
	}

	async evaluate(
		request: Request<unknown, IncomingRequestCfProperties>,
		metadata: () => Promise<Headers>,
	): Promise<GuardrailViolation | null> {
		// Only applies to write/upload requests
		if (!isWriteRequest(request)) {
			return null;
		}

		try {
			// Check if object exists and get its metadata via HEAD request
			// This doesn't buffer the request body - just checks headers
			const headers = await metadata();

			// Get the Last-Modified header to determine object age
			const lastModified = headers.get('Last-Modified');
			if (!lastModified) {
				// If no Last-Modified header, allow replacement (object metadata issue)
				return null;
			}

			const objectCreatedAtMs = new Date(lastModified).getTime();
			const objectAgeMs = this.currentTimestampMs - objectCreatedAtMs;
			const thresholdMs = this.config.noReplaceBeforeSeconds * 1000;

			if (objectAgeMs > thresholdMs) {
				return {
					violation: `Cannot replace object: object is ${Math.floor(objectAgeMs / 1000)} seconds old, which exceeds the ${this.config.noReplaceBeforeSeconds} seconds threshold`,
				};
			}

			return null;
		} catch (error) {
			if (error instanceof UpstreamError && error.code === '404') {
				// Object doesn't exist, allow upload (creating new object)
				return null;
			}
			throw error;
		}
	}
}

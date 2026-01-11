import { GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { z } from 'zod';

export const NoDeleteOldPolicyConfig = z.object({
	noDeleteBeforeSeconds: z.number().int(),
});

export type NoDeleteOldPolicyConfig = z.infer<typeof NoDeleteOldPolicyConfig>;

/**
 * Check if request is a deletion operation:
 * - DELETE method (single object deletion)
 * - POST with ?delete query param (bulk delete via DeleteObjects API)
 */
function isDeletionRequest(request: Request<unknown, IncomingRequestCfProperties>): 'single' | 'bulk' | false {
	if (request.method === 'DELETE') {
		return 'single';
	}
	// S3 DeleteObjects uses POST with ?delete query parameter
	if (request.method === 'POST') {
		const url = new URL(request.url);
		if (url.searchParams.has('delete')) {
			return 'bulk';
		}
	}
	return false;
}

export class NoDeleteOldPolicy implements GuardrailPolicy {
	private config: NoDeleteOldPolicyConfig;
	private currentTimestampMs: number;

	constructor(config: NoDeleteOldPolicyConfig, currentTimestampMs: number) {
		this.config = config;
		this.currentTimestampMs = currentTimestampMs;
	}

	async evaluate(
		request: Request<unknown, IncomingRequestCfProperties>,
		metadata: () => Promise<Headers>,
	): Promise<GuardrailViolation | null> {
		const deleteType = isDeletionRequest(request);

		// Not a deletion request
		if (!deleteType) {
			return null;
		}

		// Bulk delete (POST ?delete): Block entirely for protected paths
		// We cannot efficiently check the age of each object in the bulk request
		// without parsing the XML body, which would require buffering
		if (deleteType === 'bulk') {
			return {
				violation: `Bulk delete (DeleteObjects) is not allowed in protected paths. Use single object DELETE instead.`,
			};
		}

		// Single object DELETE: Check object age
		try {
			const headers = await metadata();

			// Get the Last-Modified header to determine object age
			const lastModified = headers.get('Last-Modified');
			if (!lastModified) {
				// If no Last-Modified header, allow deletion (object might be newly created)
				return null;
			}

			const objectCreatedAtMs = new Date(lastModified).getTime();
			const objectAgeMs = this.currentTimestampMs - objectCreatedAtMs;
			const thresholdMs = this.config.noDeleteBeforeSeconds * 1000;

			if (objectAgeMs > thresholdMs) {
				return {
					violation: `Cannot delete object: object is ${Math.floor(objectAgeMs / 1000)} seconds old, which exceeds the ${this.config.noDeleteBeforeSeconds} seconds threshold`,
				};
			}

			return null;
		} catch (error) {
			if (error instanceof UpstreamError && error.code === '404') {
				// Object doesn't exist, allow deletion attempt (will fail at upstream)
				return null;
			}
			throw error;
		}
	}
}

import { GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { z } from 'zod';

export const NoReplaceOldPolicyConfig = z.object({
	noReplaceBeforeSeconds: z.number().int(),
});

export type NoReplaceOldPolicyConfig = z.infer<typeof NoReplaceOldPolicyConfig>;

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
		// Only applies to PUT requests
		if (request.method !== 'PUT') {
			return null;
		}

		try {
			// Check if object exists and get its metadata via HEAD request
			// This doesn't buffer the PUT body - just checks headers
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
				// Object doesn't exist, allow PUT (creating new object)
				return null;
			}
			throw error;
		}
	}
}

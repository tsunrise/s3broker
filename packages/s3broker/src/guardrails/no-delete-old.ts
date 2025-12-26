import { GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { z } from 'zod';
import { AwsClient } from 'aws4fetch';
import { getObjectMetadata } from './s3_helper';

export const NoDeleteOldPolicyConfig = z.object({
	noDeleteBeforeSeconds: z.number().int(),
});

export type NoDeleteOldPolicyConfig = z.infer<typeof NoDeleteOldPolicyConfig>;

export class NoDeleteOldPolicy implements GuardrailPolicy {
	private config: NoDeleteOldPolicyConfig;
	private upstreamFetcher: AwsClient;
	private upstreamEndpoint: string;
	private currentTimestampMs: number;

	constructor(config: NoDeleteOldPolicyConfig, upstreamFetcher: AwsClient, upstreamEndpoint: string, currentTimestampMs: number) {
		this.config = config;
		this.upstreamFetcher = upstreamFetcher;
		this.upstreamEndpoint = upstreamEndpoint;
		this.currentTimestampMs = currentTimestampMs;
	}

	async evaluate(request: Request<unknown, IncomingRequestCfProperties>): Promise<GuardrailViolation | null> {
		// Only applies to DELETE requests
		if (request.method !== 'DELETE') {
			return null;
		}

		const url = new URL(request.url);
		const objectPath = this.upstreamEndpoint + url.pathname;

		try {
			const headers = await getObjectMetadata(this.upstreamFetcher, objectPath);

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

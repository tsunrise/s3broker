import { z, ZodType } from 'zod';
import { NoDeleteOldPolicyConfig } from './no-delete-old';
import { NoReplaceOldPolicyConfig } from './no-replace-old';

/**
 * Configuration for managed SSE-C (Server-Side Encryption with Customer-Provided Keys)
 */
export const ManagedSseConfig = z.object({
	// Base64-encoded 256-bit (32-byte) AES key
	key: z.string(),
});
export type ManagedSseConfig = z.infer<typeof ManagedSseConfig>;

/**
 * Result of handling an upstream response.
 * Either retry with new headers, or return a (possibly modified) response.
 */
export type HandleResponseResult = { retryRequest: Headers } | { modifiedResponse: Response };

/**
 * HeaderModifier modifies request headers before sending to upstream.
 * Used for SSE header injection and similar request transformations.
 */
export interface HeaderModifier {
	/**
	 * Modify the upstream request headers.
	 * Implementation can either mutate headers in place and return them,
	 * or clone and return new headers.
	 * @param request - The original incoming request
	 * @param upstreamHeaders - The base headers built for upstream
	 * @returns Modified headers to use for upstream request
	 */
	modifyHeaders(request: Request<unknown, IncomingRequestCfProperties>, upstreamHeaders: Headers): Promise<Headers>;

	/**
	 * Handle response from upstream, optionally retrying with different headers.
	 * @param upstreamResponse - Response from upstream
	 * @param sentRequestHeaders - Headers that were sent in the request
	 * @returns Either retry instructions or the final response
	 */
	handleResponse?(upstreamResponse: Response, sentRequestHeaders: Headers): HandleResponseResult;
}

export interface GuardrailPolicy {
	evaluate(request: Request<unknown, IncomingRequestCfProperties>, metadata: () => Promise<Headers>): Promise<GuardrailViolation | null>;
}

export type GuardrailViolation = {
	violation: string;
};

/*
 * Corresponding config for each object path pattern in regex. First match wins.
 * If config is null, the guardrail is disabled for that pattern.
 */
export const GuardrailPolicyConfigPerPattern = <T extends ZodType>(policy: T) =>
	z.array(
		z.object({
			pattern: z.string(),
			config: policy.nullable(),
		}),
	);
/**
 * - `noDeleteOld`: Prevents deletion of old objects in protected paths
 * - `noReplaceOld`: Prevents replacement of old objects in protected paths
 * - `managedSse`: Automatically injects SSE-C headers for paths
 */
export const GuardrailConfig = z.object({
	noDeleteOld: GuardrailPolicyConfigPerPattern(NoDeleteOldPolicyConfig).optional(),
	noReplaceOld: GuardrailPolicyConfigPerPattern(NoReplaceOldPolicyConfig).optional(),
	managedSse: GuardrailPolicyConfigPerPattern(ManagedSseConfig).optional(),
});
export type GuardrailConfig = z.infer<typeof GuardrailConfig>;

/**
 * Error calling upstream when evaluating guardrails
 */
export class UpstreamError extends Error {
	code: string;
	constructor(code: string, message: string) {
		super(message);
		this.code = code;
	}
}

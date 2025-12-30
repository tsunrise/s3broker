import { AwsClient } from 'aws4fetch';
import { GuardrailConfig, GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { NoDeleteOldPolicy } from './no-delete-old';
import { NoReplaceOldPolicy } from './no-replace-old';
import { getObjectMetadata } from './s3_helper';
import { cached } from '../utils';

/**
 * Evaluate guardrails for a given request
 * @param request The incoming request
 * @param config The guardrail configuration to use
 * @returns The first guardrail violation if the request violates a policy, null otherwise
 */
export async function evaluateGuardrails(
	request: Request<unknown, IncomingRequestCfProperties>,
	upstreamFetcher: AwsClient,
	s3Endpoint: string,
	currentTimestampMs: number,
	config: GuardrailConfig,
): Promise<(GuardrailViolation & { policy: string }) | null> {
	const path = new URL(request.url).pathname;
	const policies = getPolicies(config, path, currentTimestampMs);

	if (policies.length === 0) {
		return null;
	}

	const metadata = cached(() => getObjectMetadata(upstreamFetcher, s3Endpoint + path));

	// Create evaluation promises that include policy name
	const evalPromises = policies.map(({ name: policyName, policy }) => ({
		policyName,
		promise: (async () => {
			const violation = await policy.evaluate(request, metadata);
			return violation ? { ...violation, policy: policyName } : null;
		})(),
	}));

	// Race until one returns a violation or all are done
	// Using Promise.race with a filter pattern to get first non-null result
	return new Promise((resolve) => {
		let pendingCount = evalPromises.length;

		for (const { policyName, promise } of evalPromises) {
			promise
				.then((result) => {
					if (result !== null) {
						// First violation wins
						resolve(result);
					} else {
						pendingCount--;
						if (pendingCount === 0) {
							// All policies passed
							resolve(null);
						}
					}
				})
				.catch((error) => {
					// If a policy throws, treat it as a violation
					let message = error instanceof Error ? error.message : String(error);
					if (error instanceof UpstreamError) {
						message = `Error calling upstream when evaluating guardrail: ${message}`;
					}
					resolve({ violation: message, policy: policyName });
				});
		}
	});
}

/**
 * Get all applicable policies for a given path
 */
export function getPolicies(
	config: GuardrailConfig,
	path: string,
	currentTimestampMs: number,
): { name: string; policy: GuardrailPolicy }[] {
	const policies: { name: string; policy: GuardrailPolicy }[] = [];

	// Check noDeleteOld policies - first matching pattern wins
	// If config is null, the guardrail is disabled for that pattern (exclude case)
	for (const entry of config.noDeleteOld ?? []) {
		const regex = new RegExp(entry.pattern);
		if (regex.test(path)) {
			if (entry.config !== null) {
				policies.push({
					name: 'noDeleteOld',
					policy: new NoDeleteOldPolicy(entry.config, currentTimestampMs),
				});
			}
			break; // First match wins - even if config is null, we don't check further patterns
		}
	}

	// Check noReplaceOld policies - first matching pattern wins
	// If config is null, the guardrail is disabled for that pattern (exclude case)
	for (const entry of config.noReplaceOld ?? []) {
		const regex = new RegExp(entry.pattern);
		if (regex.test(path)) {
			if (entry.config !== null) {
				policies.push({
					name: 'noReplaceOld',
					policy: new NoReplaceOldPolicy(entry.config, currentTimestampMs),
				});
			}
			break; // First match wins - even if config is null, we don't check further patterns
		}
	}

	return policies;
}

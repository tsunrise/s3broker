import { AwsClient } from 'aws4fetch';
import { GuardrailConfig, GuardrailPolicy, GuardrailViolation, UpstreamError } from './type';
import { NoDeleteOldPolicy } from './no-delete-old';

/**
 * Evaluate guardrails for a given request
 * @param request The incoming request
 * @param config The guardrail configuration to use
 * @returns The first guardrail violation if the request violates a policy, null otherwise
 */
export async function evaluateGuardrails(
	request: Request<unknown, IncomingRequestCfProperties>,
	upstreamFetcher: AwsClient,
	s3_endpoint: string,
	currentTimestampMs: number,
	config: GuardrailConfig,
): Promise<(GuardrailViolation & { policy: string }) | null> {
	const path = new URL(request.url).pathname;
	const policies = getPolicies(config, path, upstreamFetcher, s3_endpoint, currentTimestampMs);

	if (policies.length === 0) {
		return null;
	}

	// Create evaluation promises that include policy name
	const evalPromises = policies.map(({ name: policyName, policy }) => ({
		policyName,
		promise: (async () => {
			const violation = await policy.evaluate(request);
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
	upstreamFetcher: AwsClient,
	upstreamEndpoint: string,
	currentTimestampMs: number,
): { name: string; policy: GuardrailPolicy }[] {
	const policies: { name: string; policy: GuardrailPolicy }[] = [];

	// Check noDeleteOld policies - first matching pattern wins
	for (const entry of config.noDeleteOld) {
		const regex = new RegExp(entry.pattern);
		if (regex.test(path)) {
			policies.push({
				name: 'noDeleteOld',
				policy: new NoDeleteOldPolicy(entry.config, upstreamFetcher, upstreamEndpoint, currentTimestampMs),
			});
			break; // First match wins
		}
	}

	return policies;
}

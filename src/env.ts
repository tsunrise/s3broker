/**
 * Environment variable and secret definitions for the S3 Proxy Worker
 *
 * This file defines the Env interface that contains all configuration
 * needed by the worker at runtime.
 */

export interface Env {
	/**
	 * S3-compatible endpoint URL (e.g., Cloudflare R2)
	 * Example: "https://<account_id>.r2.cloudflarestorage.com"
	 *
	 * Set in wrangler.toml under [vars]
	 */
	S3_ENDPOINT: string;

	/**
	 * Client Access Key ID (Key A)
	 *
	 * This is the access key ID that clients use to sign their requests.
	 * The worker verifies incoming requests against this credential.
	 *
	 * Set via: wrangler secret put CLIENT_ACCESS_KEY_ID
	 * Or generate with: npm run rotate-client-key
	 */
	CLIENT_ACCESS_KEY_ID: string;

	/**
	 * Client Secret Access Key (Key A)
	 *
	 * This is the secret key corresponding to CLIENT_ACCESS_KEY_ID.
	 * Used by the worker to verify the signature of incoming requests.
	 *
	 * Set via: wrangler secret put CLIENT_SECRET_ACCESS_KEY
	 * Or generate with: npm run rotate-client-key
	 */
	CLIENT_SECRET_ACCESS_KEY: string;

	/**
	 * Upstream Access Key ID (Key B)
	 *
	 * This is the access key ID for the upstream S3/R2 service.
	 * The worker uses this to sign requests to the upstream endpoint.
	 *
	 * Set via: wrangler secret put UPSTREAM_ACCESS_KEY_ID
	 */
	UPSTREAM_ACCESS_KEY_ID: string;

	/**
	 * Upstream Secret Access Key (Key B)
	 *
	 * This is the secret key corresponding to UPSTREAM_ACCESS_KEY_ID.
	 * Used by the worker to sign outgoing requests to S3/R2.
	 *
	 * Set via: wrangler secret put UPSTREAM_SECRET_ACCESS_KEY
	 */
	UPSTREAM_SECRET_ACCESS_KEY: string;

	/**
	 * Optional JSON string containing custom guardrail policy
	 * If not provided, default guardrails will be used
	 *
	 * Example:
	 * ```json
	 * {
	 *   "noDeleteOld": [
	 *     { "pattern": "/free/.*", "config": null },
	 *     { "pattern": "/.*", "config": { "noDeleteBeforeSeconds": 60 } }
	 *   ]
	 * }
	 * ```
	 *
	 * Set in wrangler.toml under [vars] or via secret
	 */
	GUARDRAIL_POLICY?: string;

	/**
	 * SSE Key for managed SSE-C encryption
	 *
	 * Set via: wrangler secret put SSE_KEY
	 */
	SSE_KEY?: string;
}

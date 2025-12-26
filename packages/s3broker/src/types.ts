import { GuardrailConfig } from './guardrails/type';

/**
 * Configuration options for the S3Broker handler.
 *
 * S3Broker uses a two-key authentication model:
 * - **Client credentials (Key A)**: Used to verify incoming requests from your clients
 * - **Upstream credentials (Key B)**: Used to sign requests to the upstream S3 service
 */
export interface S3BrokerOptions {
	/**
	 * The upstream S3-compatible endpoint URL.
	 *
	 * Supports AWS S3, Cloudflare R2, MinIO, and other S3-compatible services.
	 *
	 * @example 'https://s3.us-east-1.amazonaws.com'
	 * @example 'https://account-id.r2.cloudflarestorage.com'
	 */
	s3Endpoint: string;

	/**
	 * Access Key ID for client authentication (Key A)
	 * Used to verify incoming requests
	 */
	clientAccessKeyId: string;

	/**
	 * Secret Access Key for client authentication (Key A)
	 * Used to verify incoming requests
	 */
	clientSecretAccessKey: string;

	/**
	 * Access Key ID for upstream authentication (Key B)
	 * Used to sign requests to the upstream S3 service
	 */
	upstreamAccessKeyId: string;

	/**
	 * Secret Access Key for upstream authentication (Key B)
	 * Used to sign requests to the upstream S3 service
	 */
	upstreamSecretAccessKey: string;

	/**
	 * Optional custom guardrail configuration
	 * If not provided, default configuration will be used
	 */
	guardrailConfig?: GuardrailConfig;
}

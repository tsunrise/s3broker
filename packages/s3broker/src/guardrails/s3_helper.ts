import { AwsClient } from 'aws4fetch';
import { UpstreamError } from './type';

/**
 * Issue a `HEAD` request to retrieve object metadata
 * @param upstream - AWS client for signing requests
 * @param objectPath - Full path to the object (including endpoint)
 * @param sseHeaders - Optional SSE-C headers for encrypted objects
 */
export async function getObjectMetadata(
	upstream: AwsClient,
	objectPath: string,
	sseHeaders?: { key: string; keyMd5: string },
): Promise<Headers> {
	const headers: Record<string, string> = {};
	if (sseHeaders) {
		headers['x-amz-server-side-encryption-customer-algorithm'] = 'AES256';
		headers['x-amz-server-side-encryption-customer-key'] = sseHeaders.key;
		headers['x-amz-server-side-encryption-customer-key-md5'] = sseHeaders.keyMd5;
	}

	const response = await upstream.fetch(objectPath, {
		method: 'HEAD',
		headers,
	});
	if (!response.ok) {
		throw new UpstreamError(response.status.toString(), response.statusText);
	}
	return response.headers;
}

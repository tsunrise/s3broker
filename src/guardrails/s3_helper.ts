import { AwsClient } from "aws4fetch";
import { UpstreamError } from "./type";
/**
 * Issue a `HEAD` request to retrieve object metadata
 * @param upstream 
 * @param objectPath 
 */
export async function getObjectMetadata(upstream: AwsClient, objectPath: string): Promise<Headers> {
    const response = await upstream.fetch(objectPath, {
        method: 'HEAD',
    });
    if (!response.ok) {
        throw new UpstreamError(response.status.toString(), response.statusText);
    }
    return response.headers;
}
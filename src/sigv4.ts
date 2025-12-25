/**
 * AWS Signature Version 4 verification utilities
 * 
 * This module provides functions to verify incoming S3 requests signed with SigV4.
 * It parses the Authorization header, reconstructs the canonical request, and
 * verifies the signature matches what we expect.
 */

interface SigV4Params {
    algorithm: string;
    credential: {
        accessKeyId: string;
        date: string;
        region: string;
        service: string;
    };
    signedHeaders: string[];
    signature: string;
    // Presigned URL specific
    expires?: number;
    isPresigned?: boolean;
}

/**
 * Check if request uses presigned URL authentication
 */
export function isPresignedUrl(request: Request): boolean {
    const url = new URL(request.url);
    return url.searchParams.has('X-Amz-Signature');
}

/**
 * Parse presigned URL query parameters
 * Query params: X-Amz-Algorithm, X-Amz-Credential, X-Amz-Date, X-Amz-Expires, X-Amz-SignedHeaders, X-Amz-Signature
 */
export function parsePresignedUrl(request: Request): SigV4Params {
    const url = new URL(request.url);

    const algorithm = url.searchParams.get('X-Amz-Algorithm');
    const credential = url.searchParams.get('X-Amz-Credential');
    const signedHeaders = url.searchParams.get('X-Amz-SignedHeaders');
    const signature = url.searchParams.get('X-Amz-Signature');
    const expires = url.searchParams.get('X-Amz-Expires');

    if (!algorithm || algorithm !== 'AWS4-HMAC-SHA256') {
        throw new Error('Invalid or missing X-Amz-Algorithm');
    }
    if (!credential || !signedHeaders || !signature) {
        throw new Error('Missing required presigned URL parameters');
    }

    // Parse credential: accessKeyId/date/region/service/aws4_request
    const credentialParts = credential.split('/');
    if (credentialParts.length !== 5 || credentialParts[4] !== 'aws4_request') {
        throw new Error('Invalid credential format in presigned URL');
    }

    return {
        algorithm: 'AWS4-HMAC-SHA256',
        credential: {
            accessKeyId: credentialParts[0],
            date: credentialParts[1],
            region: credentialParts[2],
            service: credentialParts[3],
        },
        signedHeaders: signedHeaders.split(';'),
        signature: signature,
        expires: expires ? parseInt(expires, 10) : undefined,
        isPresigned: true,
    };
}

/**
 * Parse the AWS SigV4 Authorization header
 * Format: AWS4-HMAC-SHA256 Credential=AKID/20231224/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=...
 */
export function parseAuthorizationHeader(authHeader: string): SigV4Params {
    if (!authHeader.startsWith('AWS4-HMAC-SHA256 ')) {
        throw new Error('Invalid authorization header: must start with AWS4-HMAC-SHA256');
    }

    // Split by comma and trim whitespace to handle both "key=value, key=value" and "key=value,key=value"
    const parts = authHeader.substring('AWS4-HMAC-SHA256 '.length).split(',').map(p => p.trim());
    const params: Record<string, string> = {};

    for (const part of parts) {
        const [key, value] = part.split('=', 2);
        params[key] = value;
    }

    if (!params.Credential || !params.SignedHeaders || !params.Signature) {
        throw new Error('Missing required authorization parameters');
    }

    // Parse credential: accessKeyId/date/region/service/aws4_request
    const credentialParts = params.Credential.split('/');
    if (credentialParts.length !== 5 || credentialParts[4] !== 'aws4_request') {
        throw new Error('Invalid credential format');
    }

    return {
        algorithm: 'AWS4-HMAC-SHA256',
        credential: {
            accessKeyId: credentialParts[0],
            date: credentialParts[1],
            region: credentialParts[2],
            service: credentialParts[3],
        },
        signedHeaders: params.SignedHeaders.split(';'),
        signature: params.Signature,
        isPresigned: false,
    };
}

/**
 * Build the canonical request from the incoming request
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 * 
 * @param isPresigned - If true, exclude X-Amz-Signature from query string
 */
export async function buildCanonicalRequest(
    request: Request,
    signedHeaders: string[],
    payloadHash: string,
    isPresigned: boolean = false
): Promise<string> {
    const url = new URL(request.url);
    const method = request.method;

    // Canonical URI (path)
    const canonicalUri = url.pathname || '/';

    // Canonical query string (sorted, exclude X-Amz-Signature for presigned URLs)
    const queryParams = Array.from(url.searchParams.entries())
        .filter(([key]) => !isPresigned || key !== 'X-Amz-Signature')
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
        .join('&');

    // Canonical headers (lowercase, sorted, trimmed)
    const headers: Record<string, string> = {};
    for (const headerName of signedHeaders) {
        const value = request.headers.get(headerName);
        if (value !== null) {
            headers[headerName.toLowerCase()] = value.trim();
        }
    }

    const canonicalHeaders = signedHeaders
        .map(name => `${name.toLowerCase()}:${headers[name.toLowerCase()] || ''}\n`)
        .join('');

    const signedHeadersList = signedHeaders.map(h => h.toLowerCase()).join(';');

    // Combine into canonical request
    return [
        method,
        canonicalUri,
        queryParams,
        canonicalHeaders,
        signedHeadersList,
        payloadHash,
    ].join('\n');
}

/**
 * Create the string to sign
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 */
export async function createStringToSign(
    algorithm: string,
    requestDate: string,
    credentialScope: string,
    canonicalRequest: string
): Promise<string> {
    const encoder = new TextEncoder();
    const canonicalRequestHash = await crypto.subtle.digest(
        'SHA-256',
        encoder.encode(canonicalRequest)
    );
    const canonicalRequestHashHex = Array.from(new Uint8Array(canonicalRequestHash))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');

    return [
        algorithm,
        requestDate,
        credentialScope,
        canonicalRequestHashHex,
    ].join('\n');
}

/**
 * Derive the signing key
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 */
export async function deriveSigningKey(
    secretKey: string,
    date: string,
    region: string,
    service: string
): Promise<ArrayBuffer> {
    const encoder = new TextEncoder();

    const kDate = await hmacSha256(encoder.encode('AWS4' + secretKey), encoder.encode(date));
    const kRegion = await hmacSha256(kDate, encoder.encode(region));
    const kService = await hmacSha256(kRegion, encoder.encode(service));
    const kSigning = await hmacSha256(kService, encoder.encode('aws4_request'));

    return kSigning;
}

/**
 * HMAC-SHA256 helper
 */
async function hmacSha256(key: ArrayBuffer | Uint8Array, data: Uint8Array): Promise<ArrayBuffer> {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    return crypto.subtle.sign('HMAC', cryptoKey, data);
}

/**
 * Calculate the signature
 */
export async function calculateSignature(
    signingKey: ArrayBuffer,
    stringToSign: string
): Promise<string> {
    const encoder = new TextEncoder();
    const signature = await hmacSha256(signingKey, encoder.encode(stringToSign));
    return Array.from(new Uint8Array(signature))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Verify the signature of an incoming request
 * Supports both Authorization header and presigned URL authentication
 */
export async function verifySignature(
    request: Request,
    clientSecretKey: string,
    expectedAccessKeyId: string
): Promise<{ valid: boolean; error?: string; isPresigned?: boolean }> {
    try {
        const url = new URL(request.url);
        const authHeader = request.headers.get('Authorization');
        const isPresigned = url.searchParams.has('X-Amz-Signature');

        // Parse auth params from either header or query parameters
        let params: SigV4Params;
        if (isPresigned) {
            params = parsePresignedUrl(request);
        } else if (authHeader) {
            params = parseAuthorizationHeader(authHeader);
        } else {
            return { valid: false, error: 'Missing authentication (no Authorization header or presigned URL parameters)' };
        }

        // Verify access key ID matches
        if (params.credential.accessKeyId !== expectedAccessKeyId) {
            console.log(`Access key ID mismatch: expected ${expectedAccessKeyId}, got ${params.credential.accessKeyId}`);
            return { valid: false, error: 'Access key ID mismatch' };
        }

        // For presigned URLs, check expiration
        if (isPresigned && params.expires !== undefined) {
            const requestDate = url.searchParams.get('X-Amz-Date');
            if (requestDate) {
                // Parse the request date (format: 20231224T120000Z)
                const year = parseInt(requestDate.substring(0, 4));
                const month = parseInt(requestDate.substring(4, 6)) - 1;
                const day = parseInt(requestDate.substring(6, 8));
                const hour = parseInt(requestDate.substring(9, 11));
                const minute = parseInt(requestDate.substring(11, 13));
                const second = parseInt(requestDate.substring(13, 15));
                const signedAt = new Date(Date.UTC(year, month, day, hour, minute, second));
                const expiresAt = new Date(signedAt.getTime() + params.expires * 1000);

                if (new Date() > expiresAt) {
                    return { valid: false, error: 'Presigned URL has expired' };
                }
            }
        }

        // Get the payload hash
        let payloadHash: string;
        if (isPresigned) {
            // Presigned URLs always use UNSIGNED-PAYLOAD
            payloadHash = 'UNSIGNED-PAYLOAD';
        } else {
            payloadHash = request.headers.get('x-amz-content-sha256') || 'UNSIGNED-PAYLOAD';
        }

        // Check for streaming payload (not supported)
        if (payloadHash === 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD') {
            return { valid: false, error: 'Streaming payload signatures are not supported' };
        }

        // Build canonical request
        const canonicalRequest = await buildCanonicalRequest(
            request,
            params.signedHeaders,
            payloadHash,
            isPresigned
        );

        // Get request date
        let requestDate: string | null;
        if (isPresigned) {
            requestDate = url.searchParams.get('X-Amz-Date');
        } else {
            requestDate = request.headers.get('x-amz-date');
        }

        if (!requestDate) {
            return { valid: false, error: 'Missing request date (x-amz-date)' };
        }

        // Create credential scope
        const credentialScope = `${params.credential.date}/${params.credential.region}/${params.credential.service}/aws4_request`;

        // Create string to sign
        const stringToSign = await createStringToSign(
            params.algorithm,
            requestDate,
            credentialScope,
            canonicalRequest
        );

        // Derive signing key
        const signingKey = await deriveSigningKey(
            clientSecretKey,
            params.credential.date,
            params.credential.region,
            params.credential.service
        );

        // Calculate expected signature
        const expectedSignature = await calculateSignature(signingKey, stringToSign);

        // Compare signatures (constant-time comparison would be better for production)
        if (expectedSignature !== params.signature) {
            return { valid: false, error: 'Signature mismatch', isPresigned };
        }

        return { valid: true, isPresigned };
    } catch (error) {
        return { valid: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

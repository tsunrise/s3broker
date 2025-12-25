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
    };
}

/**
 * Build the canonical request from the incoming request
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */
export async function buildCanonicalRequest(
    request: Request,
    signedHeaders: string[],
    payloadHash: string
): Promise<string> {
    const url = new URL(request.url);
    const method = request.method;

    // Canonical URI (path)
    const canonicalUri = url.pathname || '/';

    // Canonical query string (sorted)
    const queryParams = Array.from(url.searchParams.entries())
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
 */
export async function verifySignature(
    request: Request,
    clientSecretKey: string,
    expectedAccessKeyId: string
): Promise<{ valid: boolean; error?: string }> {
    try {
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return { valid: false, error: 'Missing Authorization header' };
        }

        const params = parseAuthorizationHeader(authHeader);

        // Verify access key ID matches
        if (params.credential.accessKeyId !== expectedAccessKeyId) {
            console.log(`Access key ID mismatch: expected ${expectedAccessKeyId}, got ${params.credential.accessKeyId}`);
            return { valid: false, error: 'Access key ID mismatch' };
        }

        // Get the payload hash
        const payloadHash = request.headers.get('x-amz-content-sha256') || 'UNSIGNED-PAYLOAD';

        // Check for streaming payload (not supported)
        if (payloadHash === 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD') {
            return { valid: false, error: 'Streaming payload signatures are not supported' };
        }

        // Build canonical request
        const canonicalRequest = await buildCanonicalRequest(
            request,
            params.signedHeaders,
            payloadHash
        );

        // Get request date from x-amz-date header
        const requestDate = request.headers.get('x-amz-date');
        if (!requestDate) {
            return { valid: false, error: 'Missing x-amz-date header' };
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
            return { valid: false, error: 'Signature mismatch' };
        }

        return { valid: true };
    } catch (error) {
        return { valid: false, error: error instanceof Error ? error.message : 'Unknown error' };
    }
}

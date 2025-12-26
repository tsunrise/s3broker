export enum ErrorCode {
	Forbidden = 403,
	UpstreamFailure = 502,
}

export function textErrorResponse(text: string, errorCode: ErrorCode): Response {
	return new Response(text, { status: errorCode, headers: { 'Content-Type': 'text/plain' } });
}

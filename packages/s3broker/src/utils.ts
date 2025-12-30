export enum ErrorCode {
	Forbidden = 403,
	UpstreamFailure = 502,
}

export function textErrorResponse(text: string, errorCode: ErrorCode): Response {
	return new Response(text, { status: errorCode, headers: { 'Content-Type': 'text/plain' } });
}

/*
 * Given an async function, returns a function that will only call the provided function once, and return the same promise on subsequent calls.
 */
export function cached<T>(fn: () => Promise<T>): () => Promise<T> {
	let maybeDonePromise: Promise<T> | null = null;
	return () => {
		if (!maybeDonePromise) {
			maybeDonePromise = fn();
		}
		return maybeDonePromise;
	};
}

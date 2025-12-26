import { MockAgent } from 'cloudflare:test';

interface MockS3Object {
	body: string;
	headers: Headers;
	lastModified: Date;
}

export class S3Mock {
	private objects: Map<string, MockS3Object> = new Map();

	constructor(private endpoint: string) {}

	/**
	 * Store an object in the mock S3
	 */
	public putObject(
		path: string,
		body: string,
		headers: Headers,
		options: {
			currentTimestampMs: number;
		},
	): Response {
		const lastModified = new Date(options.currentTimestampMs);
		this.objects.set(path, {
			body,
			headers: new Headers(headers),
			lastModified,
		});
		return new Response(null, { status: 200 });
	}

	/**
	 * Get an object from the mock S3
	 */
	public getObject(path: string): Response {
		const obj = this.objects.get(path);
		if (!obj) {
			return new Response('NoSuchKey', { status: 404 });
		}
		const responseHeaders = new Headers(obj.headers);
		responseHeaders.set('Last-Modified', obj.lastModified.toUTCString());
		return new Response(obj.body, {
			status: 200,
			headers: responseHeaders,
		});
	}

	/**
	 * HEAD request - returns metadata without body
	 */
	public headObject(path: string): Response {
		const obj = this.objects.get(path);
		if (!obj) {
			return new Response(null, { status: 404 });
		}
		const responseHeaders = new Headers(obj.headers);
		responseHeaders.set('Last-Modified', obj.lastModified.toUTCString());
		return new Response(null, {
			status: 200,
			headers: responseHeaders,
		});
	}

	/**
	 * DELETE request - removes object
	 */
	public deleteObject(path: string): Response {
		if (!this.objects.has(path)) {
			return new Response(null, { status: 404 });
		}
		this.objects.delete(path);
		return new Response(null, { status: 204 });
	}

	/**
	 * Attach this mock to a MockAgent for fetch interception
	 * Note: Intercepts are limited to avoid conflicts between tests
	 */
	public attachToMock(mock: MockAgent) {
		const self = this;

		// Use .times() with a reasonable limit instead of .persist() for test isolation
		mock
			.get(this.endpoint)
			.intercept({
				path: /.*/,
				method: 'GET',
			})
			.reply((req) => {
				const url = new URL(req.path, self.endpoint);
				const obj = self.objects.get(url.pathname);
				if (!obj) {
					return { statusCode: 404, data: 'NoSuchKey' };
				}
				return {
					statusCode: 200,
					data: obj.body,
					responseOptions: {
						headers: { 'Last-Modified': obj.lastModified.toUTCString() },
					},
				};
			})
			.persist();

		mock
			.get(this.endpoint)
			.intercept({
				path: /.*/,
				method: 'HEAD',
			})
			.reply((req) => {
				const url = new URL(req.path, self.endpoint);
				const obj = self.objects.get(url.pathname);
				if (!obj) {
					return { statusCode: 404 };
				}
				return {
					statusCode: 200,
					responseOptions: {
						headers: { 'Last-Modified': obj.lastModified.toUTCString() },
					},
				};
			})
			.persist();

		mock
			.get(this.endpoint)
			.intercept({
				path: /.*/,
				method: 'DELETE',
			})
			.reply((req) => {
				const url = new URL(req.path, self.endpoint);
				if (!self.objects.has(url.pathname)) {
					return { statusCode: 404 };
				}
				self.objects.delete(url.pathname);
				return { statusCode: 204 };
			})
			.persist();

		mock
			.get(this.endpoint)
			.intercept({
				path: /.*/,
				method: 'PUT',
			})
			.reply(() => {
				return { statusCode: 200 };
			})
			.persist();
	}
}

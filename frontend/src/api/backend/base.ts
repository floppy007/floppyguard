import queryString, { type StringifiableRecord } from "query-string";
import AuthStore from "src/modules/AuthStore";

const contentTypeHeader = "Content-Type";

const decamelize = (value: string) => value.replace(/([a-z\d])([A-Z])/g, "$1_$2").toLowerCase();
const camelize = (value: string) => value.replace(/[_-](\w)/g, (_, char: string) => char.toUpperCase());

const mapObjectKeys = (input: Record<string, any>, transform: (key: string) => string): Record<string, any> => {
	const result: Record<string, any> = {};
	for (const [key, value] of Object.entries(input)) {
		result[transform(key)] = convertKeys(value, transform);
	}
	return result;
};

const convertKeys = (input: any, transform: (key: string) => string): any => {
	if (Array.isArray(input)) {
		return input.map((item) => convertKeys(item, transform));
	}
	if (input && typeof input === "object" && input.constructor === Object) {
		return mapObjectKeys(input, transform);
	}
	return input;
};

const camelizeKeys = (input: any) => convertKeys(input, camelize);
const decamelizeKeys = (input: any) => convertKeys(input, decamelize);

interface BuildUrlArgs {
	url: string;
	params?: StringifiableRecord;
}

function decamelizeParams(params?: StringifiableRecord): StringifiableRecord | undefined {
	if (!params) {
		return undefined;
	}
	const result: StringifiableRecord = {};
	for (const [key, value] of Object.entries(params)) {
		result[decamelize(key)] = value;
	}

	return result;
}

function buildUrl({ url, params }: BuildUrlArgs) {
	const endpoint = url.replace(/^\/|\/$/g, "");
	const baseUrl = `/api/${endpoint}`;
	const apiUrl = queryString.stringifyUrl({
		url: baseUrl,
		query: decamelizeParams(params),
	});
	return apiUrl;
}

function buildAuthHeader(): Record<string, string> | undefined {
	if (AuthStore.token) {
		return { Authorization: `Bearer ${AuthStore.token.token}` };
	}
	return {};
}

function buildBody(data?: Record<string, any>): string | undefined {
	if (data) {
		return JSON.stringify(decamelizeKeys(data));
	}
}

/**
 * @param logoutOn401  Only requests sent with the user's token may log the
 *   user out on 401. An unauthenticated call (noAuth, e.g. the SSO exchange)
 *   must report its own error instead of reloading the page.
 */
async function processResponse(response: Response, logoutOn401 = true) {
	if (!response.ok) await throwApiError(response, logoutOn401);
	let payload: any;
	try {
		payload = await response.json();
	} catch {
		throw new Error(`HTTP ${response.status} ${response.statusText}`);
	}
	return camelizeKeys(payload) as any;
}

/** Throw the backend's error message for a failed response (logs out on 401). */
async function throwApiError(response: Response, logoutOn401 = true): Promise<never> {
	let payload: any;
	try {
		payload = await response.json();
	} catch {
		payload = undefined;
	}
	if (response.status === 401 && logoutOn401) {
		// Force logout user and reload the page if Unauthorized. The reload also drops the
		// app's QueryClient cache (App.tsx), so no second client is needed here.
		AuthStore.clear();
		window.location.reload();
	}
	const e = payload?.error;
	throw new Error(
		e?.message_i18n ?? e?.messageI18n ?? e?.message ?? `HTTP ${response.status} ${response.statusText}`,
	);
}

interface GetArgs {
	url: string;
	params?: queryString.StringifiableRecord;
}

async function baseGet({ url, params }: GetArgs, abortController?: AbortController) {
	const apiUrl = buildUrl({ url, params });
	const method = "GET";
	const headers = buildAuthHeader();
	const signal = abortController?.signal;
	const response = await fetch(apiUrl, { method, headers, signal });
	return response;
}

export async function get(args: GetArgs, abortController?: AbortController) {
	return processResponse(await baseGet(args, abortController));
}

/** Authenticated GET of a binary response; errors carry the backend message like get(). */
export async function fetchBlob({ url, params }: GetArgs): Promise<Blob> {
	const res = await fetch(buildUrl({ url, params }), { headers: buildAuthHeader() });
	if (!res.ok) await throwApiError(res);
	return res.blob();
}

export async function download(args: GetArgs, filename = "download.file") {
	saveBlob(await fetchBlob(args), filename);
}

/** Hand a blob to the browser as a file download. */
export function saveBlob(bl: Blob, filename: string) {
	const u = window.URL.createObjectURL(bl);
	const a = document.createElement("a");
	a.href = u;
	a.download = filename;
	a.click();
	window.URL.revokeObjectURL(u);
}

interface PostArgs {
	url: string;
	params?: queryString.StringifiableRecord;
	data?: any;
	noAuth?: boolean;
	/** Skip camelCase→snake_case key conversion (e.g. for payloads with opaque keys like WireGuard public keys) */
	rawBody?: boolean;
}

export async function post({ url, params, data, noAuth, rawBody }: PostArgs, abortController?: AbortController) {
	const apiUrl = buildUrl({ url, params });
	const method = "POST";

	let headers: Record<string, string> = {};
	if (!noAuth) {
		headers = {
			...buildAuthHeader(),
		};
	}

	let body: string | FormData | undefined;
	// Check if the data is an instance of FormData
	// If data is FormData, let the browser set the Content-Type header
	if (data instanceof FormData) {
		body = data;
	} else {
		// If data is JSON, set the Content-Type header to 'application/json'
		headers = {
			...headers,
			[contentTypeHeader]: "application/json",
		};
		body = rawBody ? JSON.stringify(data) : buildBody(data);
	}

	const signal = abortController?.signal;
	const response = await fetch(apiUrl, { method, headers, body, signal });
	return processResponse(response, !noAuth);
}

interface PutArgs {
	url: string;
	params?: queryString.StringifiableRecord;
	data?: Record<string, any>;
}
export async function put({ url, params, data }: PutArgs, abortController?: AbortController) {
	const apiUrl = buildUrl({ url, params });
	const method = "PUT";
	const headers = {
		...buildAuthHeader(),
		[contentTypeHeader]: "application/json",
	};
	const signal = abortController?.signal;
	const body = buildBody(data);
	const response = await fetch(apiUrl, { method, headers, body, signal });
	return processResponse(response);
}

interface DeleteArgs {
	url: string;
	params?: queryString.StringifiableRecord;
	/** Optional JSON body, for values that must not appear in the URL (e.g. a 2FA code) */
	data?: Record<string, any>;
}
export async function del({ url, params, data }: DeleteArgs, abortController?: AbortController) {
	const apiUrl = buildUrl({ url, params });
	const method = "DELETE";
	const headers: Record<string, string> = {
		...buildAuthHeader(),
	};
	const body = buildBody(data);
	if (body !== undefined) {
		headers[contentTypeHeader] = "application/json";
	}
	const signal = abortController?.signal;
	const response = await fetch(apiUrl, { method, headers, body, signal });
	return processResponse(response);
}

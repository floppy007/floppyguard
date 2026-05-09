import { QueryClient } from "@tanstack/react-query";
import queryString, { type StringifiableRecord } from "query-string";
import AuthStore from "src/modules/AuthStore";

const queryClient = new QueryClient();
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

async function processResponse(response: Response) {
	let payload: any;
	try {
		payload = await response.json();
	} catch {
		if (response.status === 401) {
			AuthStore.clear();
			queryClient.clear();
			window.location.reload();
		}
		throw new Error("HTTP " + response.status + " " + response.statusText);
	}
	if (!response.ok) {
		if (response.status === 401) {
			// Force logout user and reload the page if Unauthorized
			AuthStore.clear();
			queryClient.clear();
			window.location.reload();
		}
		throw new Error(
			typeof payload.error.messageI18n !== "undefined" ? payload.error.messageI18n : payload.error.message,
		);
	}
	return camelizeKeys(payload) as any;
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

export async function download({ url, params }: GetArgs, filename = "download.file") {
	const headers = buildAuthHeader();
	const res = await fetch(buildUrl({ url, params }), { headers });
	if (!res.ok) throw new Error("Download failed: HTTP " + res.status);
	const bl = await res.blob();
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
	return processResponse(response);
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
}
export async function del({ url, params }: DeleteArgs, abortController?: AbortController) {
	const apiUrl = buildUrl({ url, params });
	const method = "DELETE";
	const headers = {
		...buildAuthHeader(),
	};
	const signal = abortController?.signal;
	const response = await fetch(apiUrl, { method, headers, signal });
	return processResponse(response);
}

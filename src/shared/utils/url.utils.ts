// https://nodejs.org/api/url.html#url_url_resolve_from_to
// resolve('/one/two/three', 'four');         // '/one/two/four'
// resolve('http://example.com/', '/one');    // 'http://example.com/one'

import { Response } from "node-fetch";
import { FetchError } from "../classes/error/internalerror.js";

// resolve('http://example.com/one', '/two'); // 'http://example.com/two'
export function resolve(from: string, to: string) {
  const a = new URL(from, 'resolve://');
  const resolvedUrl = new URL(to, a);
  if (resolvedUrl.protocol === 'resolve:') {
    // `from` is a relative URL.
    const {pathname, search, hash} = resolvedUrl;
    return pathname + search + hash;
  }
  return resolvedUrl.toString();
}

export function join(...paths: string[]): string {
  return paths.reduce(
    (acc, path) =>
      resolve(
        acc.endsWith('/') ? acc : acc + '/',
        path.startsWith('/') ? path.slice(1) : path,
      ),
    '',
  );
}

export function manageRedirection(response: Response, separator: string): Record<string, any> {
  if (response.status !== 302) {
    throw new FetchError(`Expected redirect but received ${response.status}`);
  }
  const redirectedUrl = response.headers.get('Location')?.split(`${separator}`)[1];
  const urlParams = new URLSearchParams(redirectedUrl!);
  const requestParams: Record<string, any> = {};
  urlParams.forEach((value, key) => {
    requestParams[key] = value;
  });
  return requestParams;
}

export function extractQueryParameters(url: string) {
  const urlObject = new URL(url);
  const params: Record<string, string> = {};
  urlObject.searchParams.forEach((value, key) => {
    params[key] = value;
  });

  return params;
}

import { authHeaders, describeError } from './lib/view.js';

// The access token (used when the backend runs in token mode) lives in this browser tab only: sessionStorage, not
// localStorage, so it is gone when the tab closes. Storage can be blocked, so every access is guarded.
const TOKEN_KEY = 'socmind.token';

export function readStoredToken() {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function storeToken(token) {
  try {
    if (token && token.trim()) window.sessionStorage.setItem(TOKEN_KEY, token.trim());
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage blocked: the token simply is not remembered */
  }
}

// Same backend address the app already used. Override with VITE_API_BASE (VITE_API_BASE_URL, used by
// docker-compose.yml, is accepted too). Only a public URL belongs here: Vite bundles these values into the page.
export const API_BASE = import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1';

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/** Calls the SOCMind backend. Resolves with parsed JSON; rejects with an ApiError carrying a readable message. */
export async function api(path, options = {}) {
  const { data } = await request(path, options);
  return data;
}

/**
 * Like api(), for list endpoints: also returns the number of matching records the server reported in X-Total-Count
 * (null when the header is absent). Resolves with { data, total }.
 */
export async function apiPage(path, options = {}) {
  const { data, total } = await request(path, options);
  return { data, total };
}

async function request(path, { method = 'GET', body } = {}) {
  let res;
  const headers = { ...authHeaders(readStoredToken()), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) };
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(`Cannot reach the backend at ${API_BASE}. Is the FastAPI server running?`, 0);
  }
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* empty or non-JSON body */
  }
  if (!res.ok) throw new ApiError(describeError(res.status, data), res.status);
  const header = res.headers && res.headers.get ? res.headers.get('X-Total-Count') : null;
  const parsed = header === null ? NaN : Number(header);
  return { data, total: Number.isFinite(parsed) ? parsed : null };
}

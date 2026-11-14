import { describeError } from './lib/view.js';
import { requestHeaders, signedOutAfter } from './lib/session.js';

// Two ways to prove who is calling, depending on the backend's AUTH_MODE (the app sets the mode from /auth/status before it
// requests any protected data):
//  - accounts: an HttpOnly session cookie that JavaScript cannot read. It is sent automatically (credentials: 'include').
//    Writes also carry the session's CSRF token, which is kept in memory only. A bearer token is never sent in this mode.
//  - token: a static bearer token that Settings → Access keeps in sessionStorage for this browser tab only.
//  - disabled (demo) and unknown: no authentication header.
const TOKEN_KEY = 'socmind.token';

// Dispatched on window when a request is refused with 401 in accounts mode, meaning the session has ended. The app listens for it
// and shows the sign-in page again.
export const SIGNED_OUT_EVENT = 'socmind:signed-out';

let authMode = 'unknown';
export function setAuthMode(mode) {
  authMode = typeof mode === 'string' && mode ? mode : 'unknown';
}
export function getAuthMode() {
  return authMode;
}

let csrfToken = '';
export function setCsrfToken(token) {
  csrfToken = typeof token === 'string' ? token : '';
}
export function getCsrfToken() {
  return csrfToken;
}

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
  const headers = requestHeaders({
    mode: authMode,
    storedToken: readStoredToken(),
    csrf: csrfToken,
    method,
    hasBody: body !== undefined,
  });
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: Object.keys(headers).length ? headers : undefined,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'include',           // sends the session cookie to the API (same site, see docs/SECURITY.md)
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
  if (!res.ok) {
    if (signedOutAfter({ mode: authMode, status: res.status, path })) {
      try {
        window.dispatchEvent(new Event(SIGNED_OUT_EVENT));
      } catch {
        /* no window (tests): nothing to notify */
      }
    }
    throw new ApiError(describeError(res.status, data), res.status);
  }
  const header = res.headers && res.headers.get ? res.headers.get('X-Total-Count') : null;
  const parsed = header === null ? NaN : Number(header);
  return { data, total: Number.isFinite(parsed) ? parsed : null };
}

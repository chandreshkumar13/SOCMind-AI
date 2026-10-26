import { describeError } from './lib/view.js';

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
export async function api(path, { method = 'GET', body } = {}) {
  let res;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method,
      headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
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
  return data;
}

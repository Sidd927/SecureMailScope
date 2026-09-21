/**
 * API client (doc 23 §6, §9, §11).
 *
 * The console talks only to the existing Phase-8/9 API. It never touches a PCAP,
 * never runs tshark, never reads the database, and makes no security decision.
 *
 * Every request path is built from a run id validated against the same 32-hex shape
 * the server enforces, so a malformed id never reaches a URL. That is defence in
 * depth — the API remains the security boundary.
 */

const BASE = '/api/v1';

/** Same shape the backend validates (`backend/api.py` `_RUN_ID`). */
const RUN_ID = /^[0-9a-f]{32}$/;

export class ApiError extends Error {
  constructor(code, message, detail, status) {
    super(message);
    this.code = code;
    this.detail = detail || {};
    this.status = status;
  }
}

export function isValidRunId(runId) {
  return typeof runId === 'string' && RUN_ID.test(runId);
}

function requireRunId(runId) {
  if (!isValidRunId(runId)) {
    throw new ApiError('INVALID_REQUEST', 'run identifier is not valid',
      { expected: '32 hex characters' }, 400);
  }
  return runId;
}

async function request(path, opts = {}) {
  let response;
  try {
    response = await fetch(path, { headers: { Accept: 'application/json' }, ...opts });
  } catch (cause) {
    // A transport failure is NOT "no data" — the UI must say which it is.
    throw new ApiError('NETWORK_UNAVAILABLE',
      'The console could not reach the SecureMailScope API.', {}, 0);
  }

  let payload = null;
  try {
    payload = await response.json();
  } catch (cause) {
    payload = null;
  }

  if (!response.ok) {
    const err = (payload && payload.error) || {};
    throw new ApiError(err.code || 'INTERNAL_ERROR',
      err.message || `Request failed with status ${response.status}`,
      err.detail, response.status);
  }
  if (payload === null) {
    throw new ApiError('MALFORMED_RESPONSE',
      'The API returned a response this console could not parse.', {},
      response.status);
  }
  return payload;
}

export function health() {
  return request(`${BASE}/health`);
}

export function listAnalyses({ limit = 25, offset = 0, state = null } = {}) {
  const params = new URLSearchParams();
  params.set('limit', String(limit));
  params.set('offset', String(offset));
  // Only a known lifecycle value is ever sent; free text never reaches the query.
  if (state) params.set('state', state);
  return request(`${BASE}/analyses?${params.toString()}`);
}

export function getRun(runId) {
  return request(`${BASE}/analyses/${requireRunId(runId)}`);
}

/**
 * The canonical detail source (doc 23 §6). Every screen that reasons about an
 * assessment reads this, never the listing projection.
 */
export function getAssessment(runId) {
  return request(`${BASE}/analyses/${requireRunId(runId)}/assessment`);
}

export function listReports(runId) {
  return request(`${BASE}/analyses/${requireRunId(runId)}/reports`);
}

export function listArtifacts(runId, { verify = false } = {}) {
  const suffix = verify ? '?verify=true' : '';
  return request(`${BASE}/analyses/${requireRunId(runId)}/artifacts${suffix}`);
}

/**
 * A report URL. Built from a validated run id and a FIXED format allowlist —
 * never from a string the API supplied (doc 23 §11).
 */
const FORMATS = new Set(['html', 'pdf', 'json']);

export function reportUrl(runId, format) {
  requireRunId(runId);
  if (!FORMATS.has(format)) {
    throw new ApiError('UNSUPPORTED_REPORT_FORMAT', 'unsupported report format',
      { format, supported: [...FORMATS] }, 400);
  }
  return `${BASE}/analyses/${runId}/reports/${format}`;
}

/**
 * SecureMailScope — Strongly-Typed API Client
 * Interfaces with FastAPI backend at /api/v1.
 */

import type {
  DashboardViewModel,
  HealthResponse,
  RunListResponse,
  RunResponse,
  SessionListResponse,
} from './types';

const BASE_URL = '/api/v1';

export class ApiError extends Error {
  code: string;
  detail: any;
  status: number;

  constructor(message: string, code: string, status: number, detail: any = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

async function request<T>(path: string, options?: RequestInit, retries = 2): Promise<T> {
  const url = `${BASE_URL}${path}`;
  let lastError: any = null;

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, options);

      if (!response.ok) {
        // If transient server error and we have retries left, wait and retry
        if ([502, 503, 504].includes(response.status) && attempt < retries) {
          await new Promise((res) => setTimeout(res, 350 * (attempt + 1)));
          continue;
        }

        let errorCode = 'HTTP_ERROR';
        let errorMessage =
          response.status === 502 || response.status === 503
            ? 'Forensic analysis engine temporarily unavailable'
            : response.status === 404
            ? 'Forensic case artifact not found'
            : `Analysis request failed with status ${response.status}`;
        let errorDetail = {};

        try {
          const data = await response.json();
          if (data?.error) {
            errorCode = data.error.code || errorCode;
            errorMessage = data.error.message || errorMessage;
            errorDetail = data.error.detail || errorDetail;
          }
        } catch {
          // response was not JSON
        }

        throw new ApiError(errorMessage, errorCode, response.status, errorDetail);
      }

      return (await response.json()) as Promise<T>;
    } catch (err: any) {
      lastError = err;
      if (err instanceof ApiError) {
        throw err;
      }
      if (attempt < retries) {
        await new Promise((res) => setTimeout(res, 350 * (attempt + 1)));
      }
    }
  }

  throw lastError || new ApiError('Network connection to forensic engine failed', 'NETWORK_ERROR', 0);
}

export const api = {
  /**
   * Health and limits check
   */
  async getHealth(): Promise<HealthResponse> {
    return request<HealthResponse>('/health');
  },

  /**
   * List recent analyses with pagination and filters
   */
  async getAnalyses(params?: {
    limit?: number;
    offset?: number;
    state?: string;
    capture_id?: string;
  }): Promise<RunListResponse> {
    const search = new URLSearchParams();
    if (params?.limit) search.set('limit', String(params.limit));
    if (params?.offset) search.set('offset', String(params.offset));
    if (params?.state) search.set('state', params.state);
    if (params?.capture_id) search.set('capture_id', params.capture_id);

    const query = search.toString();
    return request<RunListResponse>(`/analyses${query ? `?${query}` : ''}`);
  },

  /**
   * Get single analysis metadata
   */
  async getAnalysis(runId: string): Promise<RunResponse> {
    return request<RunResponse>(`/analyses/${runId}`);
  },

  /**
   * Get full presentation dashboard view-model for an analysis
   */
  async getDashboard(runId: string): Promise<DashboardViewModel> {
    return request<DashboardViewModel>(`/analyses/${runId}/dashboard`);
  },

  /**
   * Get canonical assessment document
   */
  async getAssessment(runId: string): Promise<any> {
    return request<any>(`/analyses/${runId}/assessment`);
  },

  /**
   * Get available reports list
   */
  async getReports(runId: string): Promise<any> {
    return request<any>(`/analyses/${runId}/reports`);
  },

  /**
   * Fetch raw report HTML
   */
  async getReportHtml(runId: string): Promise<string> {
    const url = `${BASE_URL}/analyses/${encodeURIComponent(runId)}/reports/html`;
    const res = await fetch(url);
    if (!res.ok) throw new ApiError('Failed to fetch report HTML', 'REPORT_ERROR', res.status);
    return res.text();
  },

  /**
   * Get live session dissection data for an analysis
   */
  async getSessions(runId: string): Promise<SessionListResponse> {
    return request<SessionListResponse>(`/analyses/${runId}/sessions`);
  },

  /**
   * Upload PCAP capture file. Note: This is synchronous in the backend.
   */
  async uploadCapture(
    file: File,
    options?: { ai?: boolean; force?: boolean; formula?: string }
  ): Promise<RunResponse> {
    const formData = new FormData();
    formData.append('file', file);

    const search = new URLSearchParams();
    if (options?.ai !== undefined) search.set('ai', String(options.ai));
    if (options?.force) search.set('force', 'true');
    if (options?.formula) search.set('formula', options.formula);

    const query = search.toString();
    return request<RunResponse>(`/analyses${query ? `?${query}` : ''}`, {
      method: 'POST',
      body: formData,
    });
  },

  /**
   * Safe URL constructor for reports
   */
  getReportUrl(runId: string, format: 'html' | 'pdf' | 'json', download = false): string {
    return `${BASE_URL}/analyses/${encodeURIComponent(runId)}/reports/${format}${download ? '?download=true' : ''}`;
  },
};

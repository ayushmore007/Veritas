import type {
  AnalysisResult,
  ModelInfo,
  PickedFile,
  ScanReport,
  ServerStatus,
} from './types';

/** An error the UI can show verbatim: the server's own explanation when there is one. */
export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number = 0,
    public readonly retryAfter?: number,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

/**
 * Turn what a person types into a base URL: "192.168.1.5:8000" -> "http://192.168.1.5:8000".
 * Returns '' for blank input. Trailing slashes and a pasted "/api" suffix are dropped.
 */
export function normalizeBaseUrl(input: string): string {
  let url = input.trim();
  if (!url) return '';
  if (!/^https?:\/\//i.test(url)) url = `http://${url}`;
  return url.replace(/\/+$/, '').replace(/\/api(\/v1)?$/i, '');
}

export interface ClientOptions {
  baseUrl: string;
  apiKey?: string;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
  /** Default per-request timeout. Scans probe a live host and legitimately take a while. */
  timeoutMs?: number;
}

export class VeritasClient {
  private readonly base: string;
  private readonly apiKey: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: ClientOptions) {
    this.base = normalizeBaseUrl(opts.baseUrl);
    this.apiKey = (opts.apiKey ?? '').trim();
    this.fetchImpl = opts.fetchImpl ?? ((...a) => fetch(...a));
    this.timeoutMs = opts.timeoutMs ?? 20_000;
  }

  get configured(): boolean {
    return this.base !== '';
  }

  private async request<T>(
    path: string,
    init: RequestInit = {},
    timeoutMs: number = this.timeoutMs,
  ): Promise<T> {
    if (!this.configured) {
      throw new ApiError('No server set. Open Settings and enter your Veritas server address.');
    }
    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...((init.headers as Record<string, string> | undefined) ?? {}),
    };
    if (this.apiKey) headers['X-API-Key'] = this.apiKey;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let res: Response;
    try {
      res = await this.fetchImpl(`${this.base}/api/v1${path}`, {
        ...init,
        headers,
        signal: controller.signal,
      });
    } catch (e) {
      if ((e as { name?: string }).name === 'AbortError') {
        throw new ApiError(`The server did not answer within ${Math.round(timeoutMs / 1000)}s.`);
      }
      throw new ApiError(`Could not reach ${this.base}. Check the address, Wi-Fi, and that the server is running.`);
    } finally {
      clearTimeout(timer);
    }

    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON error page */
    }
    if (!res.ok) {
      const b = (body ?? {}) as { error?: string; detail?: unknown };
      const detail = typeof b.error === 'string' ? b.error : typeof b.detail === 'string' ? b.detail : '';
      const retry = Number(res.headers?.get?.('Retry-After')) || undefined;
      throw new ApiError(detail || friendlyStatus(res.status), res.status, retry);
    }
    return body as T;
  }

  health(): Promise<{ status: string }> {
    return this.request('/health');
  }

  status(): Promise<ServerStatus> {
    return this.request('/status');
  }

  async scan(target: string): Promise<ScanReport> {
    const r = await this.request<{ report: ScanReport }>(
      '/scan',
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ target }) },
      90_000,
    );
    return r.report;
  }

  async history(): Promise<ScanReport[]> {
    return (await this.request<{ history: ScanReport[] }>('/scans/history')).history;
  }

  async clearHistory(): Promise<void> {
    await this.request('/scans/history', { method: 'DELETE' });
  }

  model(): Promise<ModelInfo> {
    return this.request('/model');
  }

  predict(flows: Array<Record<string, unknown>>, opts: { explain?: boolean; topK?: number } = {}): Promise<AnalysisResult> {
    return this.request('/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flows, explain: opts.explain ?? true, top_k: opts.topK ?? 5 }),
    });
  }

  analyzePcap(file: PickedFile): Promise<AnalysisResult> {
    const form = new FormData();
    if (file.file) {
      form.append('file', file.file, file.name); // web: a real Blob
    } else {
      // React Native's FormData accepts a {uri,name,type} descriptor in place of a Blob.
      form.append('file', { uri: file.uri, name: file.name, type: file.mimeType ?? 'application/octet-stream' } as unknown as Blob);
    }
    // No Content-Type header: fetch must add the multipart boundary itself.
    return this.request('/analyze/pcap', { method: 'POST', body: form }, 120_000);
  }
}

function friendlyStatus(status: number): string {
  switch (status) {
    case 401: return 'The server rejected the API key. Check it in Settings.';
    case 403: return 'The server refused this request.';
    case 429: return 'Too many requests. Wait a moment and try again.';
    case 503: return 'The server has no trained model yet.';
    default: return `Server error (HTTP ${status}).`;
  }
}

/** Parse the JSON a person pastes: one flow object or an array of them. */
export function parseFlowsJson(text: string): Array<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ApiError('That is not valid JSON.');
  }
  const list = Array.isArray(parsed) ? parsed : [parsed];
  if (list.length === 0 || !list.every((f) => f && typeof f === 'object' && !Array.isArray(f))) {
    throw new ApiError('Expected a flow object or a list of flow objects, e.g. [{"tot_fwd_pkts": 60, ...}].');
  }
  return list as Array<Record<string, unknown>>;
}

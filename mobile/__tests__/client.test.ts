import { ApiError, VeritasClient, normalizeBaseUrl, parseFlowsJson } from '../src/api/client';

function mockFetch(status: number, body: unknown, headers: Record<string, string> = {}) {
  return jest.fn(async () => ({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (k: string) => headers[k] ?? null },
    json: async () => {
      if (body === undefined) throw new Error('not json');
      return body;
    },
  })) as unknown as typeof fetch & jest.Mock;
}

describe('normalizeBaseUrl', () => {
  it.each([
    ['192.168.1.5:8000', 'http://192.168.1.5:8000'],
    ['  https://veritas.example.com/ ', 'https://veritas.example.com'],
    ['http://10.0.0.2:8000/api/v1', 'http://10.0.0.2:8000'],
    ['http://10.0.0.2:8000/api', 'http://10.0.0.2:8000'],
    ['', ''],
    ['   ', ''],
  ])('%j -> %j', (input, expected) => {
    expect(normalizeBaseUrl(input)).toBe(expected);
  });
});

describe('VeritasClient', () => {
  it('refuses to call out before a server is configured', async () => {
    const c = new VeritasClient({ baseUrl: '', fetchImpl: mockFetch(200, {}) });
    await expect(c.status()).rejects.toThrow(/No server set/);
  });

  it('sends the API key and targets /api/v1', async () => {
    const f = mockFetch(200, { status: 'online' });
    await new VeritasClient({ baseUrl: '10.0.0.2:8000', apiKey: ' k3y ', fetchImpl: f }).status();
    const [url, init] = f.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://10.0.0.2:8000/api/v1/status');
    expect((init.headers as Record<string, string>)['X-API-Key']).toBe('k3y');
  });

  it('omits the key header when none is set', async () => {
    const f = mockFetch(200, { status: 'ok' });
    await new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).health();
    expect((f.mock.calls[0] as [string, RequestInit])[1].headers).not.toHaveProperty('X-API-Key');
  });

  it('posts a scan and unwraps the report', async () => {
    const f = mockFetch(200, { success: true, report: { hostname: 'a.test', security_score: 90 } });
    const r = await new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).scan('a.test');
    expect(r.hostname).toBe('a.test');
    const init = (f.mock.calls[0] as [string, RequestInit])[1];
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ target: 'a.test' });
  });

  it("surfaces the server's own explanation", async () => {
    const f = mockFetch(403, { error: 'resolves to a non-public address' });
    await expect(new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).scan('10.0.0.1')).rejects.toMatchObject({
      status: 403,
      message: 'resolves to a non-public address',
    });
  });

  it('carries Retry-After on 429', async () => {
    const f = mockFetch(429, { error: 'Too many requests; retry in 4s.' }, { 'Retry-After': '4' });
    await expect(new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).scan('x.test')).rejects.toMatchObject({
      status: 429,
      retryAfter: 4,
    });
  });

  it.each([
    [401, /API key/],
    [503, /trained model/],
    [500, /HTTP 500/],
  ])('has a plain-language message for a bodyless %i', async (status, pattern) => {
    const f = mockFetch(status, undefined);
    await expect(new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).model()).rejects.toThrow(pattern);
  });

  it('maps network failure to an actionable message', async () => {
    const f = jest.fn(async () => {
      throw new TypeError('Network request failed');
    }) as unknown as typeof fetch;
    await expect(new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).status()).rejects.toThrow(/Could not reach/);
  });

  it('times out instead of hanging', async () => {
    const f = jest.fn(
      (_url: string, init: RequestInit) =>
        new Promise((_res, rej) => {
          init.signal?.addEventListener('abort', () => rej(Object.assign(new Error('aborted'), { name: 'AbortError' })));
        }),
    ) as unknown as typeof fetch;
    await expect(new VeritasClient({ baseUrl: 'h:1', fetchImpl: f, timeoutMs: 20 }).status()).rejects.toThrow(
      /did not answer/,
    );
  });

  it('uploads a PCAP as multipart without forcing a content type', async () => {
    const f = mockFetch(200, { summary: { flows: 0, malicious: 0 }, flows: [] });
    await new VeritasClient({ baseUrl: 'h:1', fetchImpl: f }).analyzePcap({
      uri: 'file:///x.pcap',
      name: 'x.pcap',
      file: new Blob(['abc']),
    });
    const init = (f.mock.calls[0] as [string, RequestInit])[1];
    expect(init.body).toBeInstanceOf(FormData);
    expect(init.headers).not.toHaveProperty('Content-Type');
  });
});

describe('parseFlowsJson', () => {
  it('accepts one object or a list', () => {
    expect(parseFlowsJson('{"a":1}')).toEqual([{ a: 1 }]);
    expect(parseFlowsJson('[{"a":1},{"b":2}]')).toHaveLength(2);
  });
  it.each(['nope', '[]', '[1,2]', '"x"', '[[1]]'])('rejects %j', (text) => {
    expect(() => parseFlowsJson(text)).toThrow(ApiError);
  });
});

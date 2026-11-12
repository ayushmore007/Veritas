import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';

import { VeritasClient, normalizeBaseUrl } from './api/client';
import { getItem, setItem } from './storage';

const URL_KEY = 'veritas.baseUrl';
const API_KEY = 'veritas.apiKey';

interface SettingsValue {
  ready: boolean;
  baseUrl: string;
  apiKey: string;
  client: VeritasClient;
  save: (baseUrl: string, apiKey: string) => Promise<void>;
}

const Ctx = createContext<SettingsValue | null>(null);

export function SettingsProvider({ children }: { children: React.ReactNode }) {
  const [ready, setReady] = useState(false);
  const [baseUrl, setBaseUrl] = useState('');
  const [apiKey, setApiKey] = useState('');

  useEffect(() => {
    let alive = true;
    (async () => {
      const [u, k] = await Promise.all([getItem(URL_KEY), getItem(API_KEY)]);
      if (!alive) return;
      setBaseUrl(u ?? '');
      setApiKey(k ?? '');
      setReady(true);
    })();
    return () => {
      alive = false;
    };
  }, []);

  const save = useCallback(async (url: string, key: string) => {
    const normalized = normalizeBaseUrl(url);
    await Promise.all([setItem(URL_KEY, normalized), setItem(API_KEY, key.trim())]);
    setBaseUrl(normalized);
    setApiKey(key.trim());
  }, []);

  const client = useMemo(() => new VeritasClient({ baseUrl, apiKey }), [baseUrl, apiKey]);
  const value = useMemo(() => ({ ready, baseUrl, apiKey, client, save }), [ready, baseUrl, apiKey, client, save]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useSettings(): SettingsValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useSettings must be used inside <SettingsProvider>');
  return v;
}

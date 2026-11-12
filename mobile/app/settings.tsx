import React, { useEffect, useState } from 'react';
import { ScrollView, Text } from 'react-native';

import { ApiError, VeritasClient, normalizeBaseUrl } from '../src/api/client';
import { Button, Card, ErrorBanner, Field } from '../src/components/ui';
import { useSettings } from '../src/settings';
import { colors, space } from '../src/theme';

export default function SettingsScreen() {
  const { baseUrl, apiKey, save, ready } = useSettings();
  const [url, setUrl] = useState('');
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (ready) {
      setUrl(baseUrl);
      setKey(apiKey);
    }
  }, [ready, baseUrl, apiKey]);

  async function testAndSave() {
    const normalized = normalizeBaseUrl(url);
    if (!normalized) {
      setMessage({ ok: false, text: 'Enter the address of your Veritas server.' });
      return;
    }
    setBusy(true);
    setMessage(null);
    try {
      // /health proves the address is right; /status is protected, so it proves the key is right.
      const probe = new VeritasClient({ baseUrl: normalized, apiKey: key, timeoutMs: 8000 });
      await probe.health();
      const status = await probe.status();
      await save(normalized, key);
      setUrl(normalized);
      setMessage({
        ok: true,
        text: `Connected to Veritas ${status.version}. ${status.model_ready ? 'A trained model is loaded.' : 'No trained model is loaded yet.'}`,
      });
    } catch (e) {
      setMessage({ ok: false, text: e instanceof ApiError ? e.message : 'Connection failed.' });
    } finally {
      setBusy(false);
    }
  }

  return (
    <ScrollView contentContainerStyle={{ padding: space.lg }} keyboardShouldPersistTaps="handled">
      <Card>
        <Field
          label="Server address"
          placeholder="192.168.1.20:8000"
          value={url}
          onChangeText={setUrl}
          keyboardType="url"
        />
        <Field label="API key" placeholder="VERITAS_API_KEY" value={key} onChangeText={setKey} secureTextEntry />
        <Button title="Test connection & save" onPress={testAndSave} busy={busy} />
      </Card>
      {message && message.ok ? (
        <Card>
          <Text style={{ color: colors.emerald }}>{message.text}</Text>
        </Card>
      ) : (
        <ErrorBanner message={message?.text ?? null} />
      )}
      <Text style={{ color: colors.textMuted, fontSize: 12 }}>
        On the Android emulator, your computer is 10.0.2.2. On a phone, use your computer's LAN address, and start the
        server with VERITAS_API_KEY set and --host 0.0.0.0. The key is stored in the device keychain. Use HTTPS if the
        network is not one you trust: the API key travels in a request header.
      </Text>
    </ScrollView>
  );
}

import { useRouter } from 'expo-router';
import React, { useState } from 'react';
import { KeyboardAvoidingView, Platform, ScrollView, Text } from 'react-native';

import { ApiError } from '../src/api/client';
import type { ScanReport } from '../src/api/types';
import { ReportView } from '../src/components/ReportView';
import { Button, Card, ErrorBanner, Field } from '../src/components/ui';
import { useSettings } from '../src/settings';
import { colors, space } from '../src/theme';

export default function ScanScreen() {
  const { client, ready } = useSettings();
  const router = useRouter();
  const [target, setTarget] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<ScanReport | null>(null);

  async function run() {
    const t = target.trim();
    if (!t) {
      setError('Enter a host, URL or host:port to scan.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      setReport(await client.scan(t));
    } catch (e) {
      setReport(null);
      setError(e instanceof ApiError ? e.message : 'Something went wrong.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <KeyboardAvoidingView style={{ flex: 1 }} behavior={Platform.OS === 'ios' ? 'padding' : undefined}>
      <ScrollView contentContainerStyle={{ padding: space.lg }} keyboardShouldPersistTaps="handled">
        <Card>
          <Field
            label="Target host or URL"
            placeholder="example.com or https://example.com:8443"
            value={target}
            onChangeText={setTarget}
            keyboardType="url"
            returnKeyType="go"
            onSubmitEditing={run}
          />
          <Button title="Run live scan" onPress={run} busy={busy} disabled={!ready} />
          <Text style={{ color: colors.textMuted, fontSize: 12, marginTop: space.sm }}>
            Only scan hosts you own or are authorised to test.
          </Text>
        </Card>
        <ErrorBanner message={error} />
        {error?.includes('No server set') && (
          <Button title="Open Settings" variant="outline" onPress={() => router.push('/settings')} />
        )}
        {report && <ReportView report={report} />}
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

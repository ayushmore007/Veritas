import * as DocumentPicker from 'expo-document-picker';
import React, { useCallback, useEffect, useState } from 'react';
import { ScrollView, Text, TextInput, View } from 'react-native';

import { ApiError, parseFlowsJson } from '../src/api/client';
import type { AnalysisResult, FlowVerdict, ModelInfo, Rate } from '../src/api/types';
import { Button, Card, ErrorBanner, Pill } from '../src/components/ui';
import { useSettings } from '../src/settings';
import { colors, space } from '../src/theme';

const SAMPLE = '[{"tot_fwd_pkts": 60, "tot_bwd_pkts": 30, "flow_duration": 8.0, "flow_iat_std": 0.01}]';

const pct = (r?: Rate) => (r && r.value != null ? `${(r.value * 100).toFixed(1)}%` : 'n/a');
const span = (r?: Rate) => (r?.ci95 ? ` (${Math.round(r.ci95[0] * 100)}–${Math.round(r.ci95[1] * 100)}%)` : '');

function ModelCard({ info }: { info: ModelInfo }) {
  const t = info.clean_test;
  return (
    <Card>
      <Text style={{ color: colors.text, fontWeight: '700', marginBottom: 6 }}>Trained model</Text>
      <Text style={{ color: colors.textDim }}>
        {info.estimator} · {info.profile} profile · v{info.version}
      </Text>
      <Text style={{ color: colors.textDim }}>
        {info.n_features} features · threshold {info.threshold} · {info.training_samples} training flows
      </Text>
      {t && (
        <Text style={{ color: colors.text, marginTop: 6 }}>
          Held-out recall {pct(t.recall)}
          {span(t.recall)} · false alarms {pct(t.false_positive_rate)}
          {span(t.false_positive_rate)}
        </Text>
      )}
      {t?.caveat && <Text style={{ color: colors.amber, fontSize: 12, marginTop: 4 }}>{t.caveat}</Text>}
      {(info.sklearn_mismatch || info.cicflowmeter_mismatch) && (
        <Text style={{ color: colors.amber, fontSize: 12, marginTop: 4 }}>
          Library versions differ from training time; results may shift.
        </Text>
      )}
      <Text style={{ color: colors.textMuted, fontSize: 11, marginTop: 6 }}>{info.limitations}</Text>
    </Card>
  );
}

function Verdict({ v }: { v: FlowVerdict }) {
  const bad = v.verdict === 'malicious';
  return (
    <Card style={{ borderLeftWidth: 3, borderLeftColor: bad ? colors.crimson : colors.emerald }}>
      <View style={{ flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' }}>
        <Text style={{ color: colors.text, fontWeight: '600', flex: 1 }} numberOfLines={1}>
          {v.flow_id}
        </Text>
        <Pill text={`${v.verdict} ${(v.malicious_probability * 100).toFixed(0)}%`} color={bad ? colors.crimson : colors.emerald} />
      </View>
      {v.warning && <Text style={{ color: colors.amber, fontSize: 12, marginTop: 4 }}>{v.warning}</Text>}
      {v.top_features?.map((f) => (
        <Text key={f.feature} style={{ color: colors.textDim, fontSize: 12, marginTop: 3 }}>
          {f.feature} = {f.value} → {f.contribution >= 0 ? 'malicious' : 'benign'} ({f.contribution.toFixed(3)})
        </Text>
      ))}
    </Card>
  );
}

export default function AnalyzeScreen() {
  const { client } = useSettings();
  const [info, setInfo] = useState<ModelInfo | null>(null);
  const [json, setJson] = useState('');
  const [busy, setBusy] = useState<'pcap' | 'json' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalysisResult | null>(null);

  const loadInfo = useCallback(async () => {
    try {
      setInfo(await client.model());
      setError(null);
    } catch (e) {
      setInfo(null);
      setError(e instanceof ApiError ? e.message : 'Could not load model info.');
    }
  }, [client]);

  useEffect(() => {
    void loadInfo();
  }, [loadInfo]);

  async function guarded(kind: 'pcap' | 'json', fn: () => Promise<AnalysisResult | null>) {
    setBusy(kind);
    setError(null);
    try {
      const r = await fn();
      if (r) setResult(r);
    } catch (e) {
      setResult(null);
      setError(e instanceof ApiError ? e.message : 'Something went wrong.');
    } finally {
      setBusy(null);
    }
  }

  const pickPcap = () =>
    guarded('pcap', async () => {
      const picked = await DocumentPicker.getDocumentAsync({ copyToCacheDirectory: true, multiple: false });
      if (picked.canceled || !picked.assets[0]) return null;
      const a = picked.assets[0];
      return client.analyzePcap({ uri: a.uri, name: a.name, mimeType: a.mimeType, file: a.file });
    });

  const scoreJson = () => guarded('json', async () => client.predict(parseFlowsJson(json)));

  const rows = result?.flows ?? result?.results ?? [];
  return (
    <ScrollView contentContainerStyle={{ padding: space.lg }} keyboardShouldPersistTaps="handled">
      {info && <ModelCard info={info} />}
      <ErrorBanner message={error} />
      <Card>
        <Text style={{ color: colors.text, fontWeight: '700', marginBottom: space.sm }}>Analyze a capture</Text>
        <Button title="Choose PCAP file…" onPress={pickPcap} busy={busy === 'pcap'} disabled={!info} />
      </Card>
      <Card>
        <Text style={{ color: colors.text, fontWeight: '700', marginBottom: space.sm }}>Or score flow features</Text>
        <TextInput
          multiline
          value={json}
          onChangeText={setJson}
          placeholder={SAMPLE}
          placeholderTextColor={colors.textMuted}
          autoCapitalize="none"
          autoCorrect={false}
          style={{
            color: colors.text,
            backgroundColor: colors.cardAlt,
            borderRadius: 10,
            borderWidth: 1,
            borderColor: colors.border,
            minHeight: 110,
            padding: space.md,
            fontFamily: 'Courier',
            fontSize: 12,
            marginBottom: space.md,
            textAlignVertical: 'top',
          }}
        />
        <Button title="Score flows" onPress={scoreJson} busy={busy === 'json'} disabled={!info || !json.trim()} />
      </Card>
      {result && (
        <Text style={{ color: colors.text, fontWeight: '700', marginBottom: space.sm }}>
          {result.summary.flows} flows · {result.summary.malicious} malicious
        </Text>
      )}
      {result?.note && <Text style={{ color: colors.textDim, marginBottom: space.sm }}>{result.note}</Text>}
      {rows.map((v, i) => (
        <Verdict key={`${v.flow_id}-${i}`} v={v} />
      ))}
    </ScrollView>
  );
}

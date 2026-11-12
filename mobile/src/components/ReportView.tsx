import React, { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';

import type { ScanReport, SecurityTest } from '../api/types';
import { colors, scoreColor, space, statusColor } from '../theme';
import { Card, Pill } from './ui';

function TestRow({ test }: { test: SecurityTest }) {
  const [open, setOpen] = useState(false);
  return (
    <Pressable onPress={() => setOpen((o) => !o)} accessibilityRole="button" accessibilityLabel={`${test.name}, ${test.status}`}>
      <View style={styles.row}>
        <View style={{ flex: 1, paddingRight: space.sm }}>
          <Text style={styles.testName}>{test.name}</Text>
          <Text style={styles.dim}>{test.category}</Text>
        </View>
        <Pill text={test.status} color={statusColor(test.status)} />
      </View>
      {open && (
        <View style={styles.detail}>
          <Text style={styles.dim}>{test.description}</Text>
          <Text style={styles.detailLine}>Observed: {test.observed_value}</Text>
          <Text style={styles.detailLine}>Expected: {test.baseline}</Text>
          {test.status !== 'passed' && test.status !== 'defended' && (
            <Text style={[styles.detailLine, { color: colors.amber }]}>Fix: {test.remediation}</Text>
          )}
        </View>
      )}
    </Pressable>
  );
}

export function ReportView({ report }: { report: ScanReport }) {
  const v = report.vulnerabilities_count;
  const when = new Date(report.scan_timestamp);
  return (
    <View>
      <Card>
        <Text style={styles.host}>{report.hostname}</Text>
        <Text style={styles.dim}>
          {report.protocol} · port {report.port} · {report.ip_addresses.join(', ') || 'unresolved'}
        </Text>
        <View style={styles.scoreRow}>
          <Text style={[styles.score, { color: scoreColor(report.security_score) }]}>{report.security_score}</Text>
          <View style={{ marginLeft: space.md }}>
            <Text style={styles.verdict}>{report.posture_verdict}</Text>
            <Text style={styles.dim}>
              {Number.isNaN(when.getTime()) ? '' : when.toLocaleString()} · {Math.round(report.scan_duration_ms)} ms
            </Text>
          </View>
        </View>
        <View style={styles.counts}>
          <Pill text={`${v.critical} critical`} color={colors.crimson} />
          <Pill text={`${v.high} high`} color={colors.amber} />
          <Pill text={`${v.medium} medium`} color={colors.violet} />
          <Pill text={`${v.passed} passed`} color={colors.emerald} />
        </View>
      </Card>
      <Card>
        <Text style={styles.section}>Tests ({report.tests.length})</Text>
        {report.tests.map((t) => (
          <TestRow key={t.id} test={t} />
        ))}
      </Card>
    </View>
  );
}

const styles = StyleSheet.create({
  host: { color: colors.text, fontSize: 20, fontWeight: '700' },
  dim: { color: colors.textDim, fontSize: 13, marginTop: 2 },
  scoreRow: { flexDirection: 'row', alignItems: 'center', marginVertical: space.md },
  score: { fontSize: 56, fontWeight: '800' },
  verdict: { color: colors.text, fontSize: 16, fontWeight: '700' },
  counts: { flexDirection: 'row', flexWrap: 'wrap', gap: space.sm },
  section: { color: colors.text, fontWeight: '700', marginBottom: space.sm },
  row: { flexDirection: 'row', alignItems: 'center', paddingVertical: 10, borderTopColor: colors.border, borderTopWidth: StyleSheet.hairlineWidth },
  testName: { color: colors.text, fontSize: 14 },
  detail: { paddingBottom: 10 },
  detailLine: { color: colors.textDim, fontSize: 12, marginTop: 4 },
});

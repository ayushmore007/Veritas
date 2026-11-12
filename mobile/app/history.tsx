import { useFocusEffect } from 'expo-router';
import React, { useCallback, useState } from 'react';
import { Alert, Platform, Pressable, RefreshControl, ScrollView, Text, View } from 'react-native';

import { ApiError } from '../src/api/client';
import type { ScanReport } from '../src/api/types';
import { ReportView } from '../src/components/ReportView';
import { Button, Card, ErrorBanner, Pill } from '../src/components/ui';
import { useSettings } from '../src/settings';
import { colors, scoreColor, space } from '../src/theme';

export default function HistoryScreen() {
  const { client } = useSettings();
  const [items, setItems] = useState<ScanReport[] | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      setItems(await client.history());
    } catch (e) {
      setItems(null);
      setError(e instanceof ApiError ? e.message : 'Could not load history.');
    }
  }, [client]);

  useFocusEffect(
    useCallback(() => {
      void load();
    }, [load]),
  );

  async function clear() {
    const doClear = async () => {
      try {
        await client.clearHistory();
        setOpen(null);
        await load();
      } catch (e) {
        setError(e instanceof ApiError ? e.message : 'Could not clear history.');
      }
    };
    if (Platform.OS === 'web') {
      if (globalThis.confirm?.('Delete all saved scans from the server?')) await doClear();
    } else {
      Alert.alert('Clear history', 'Delete all saved scans from the server?', [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Delete', style: 'destructive', onPress: () => void doClear() },
      ]);
    }
  }

  return (
    <ScrollView
      contentContainerStyle={{ padding: space.lg }}
      refreshControl={
        <RefreshControl
          refreshing={refreshing}
          tintColor={colors.cyan}
          onRefresh={async () => {
            setRefreshing(true);
            await load();
            setRefreshing(false);
          }}
        />
      }
    >
      <ErrorBanner message={error} />
      {items && items.length === 0 && (
        <Card>
          <Text style={{ color: colors.textDim }}>No scans yet. Run one from the Scan tab.</Text>
        </Card>
      )}
      {items?.map((r) => (
        <View key={r.hostname}>
          <Pressable onPress={() => setOpen(open === r.hostname ? null : r.hostname)} accessibilityRole="button">
            <Card style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
              <View style={{ flex: 1 }}>
                <Text style={{ color: colors.text, fontWeight: '700' }}>{r.hostname}</Text>
                <Text style={{ color: colors.textDim, fontSize: 12 }}>{new Date(r.scan_timestamp).toLocaleString()}</Text>
              </View>
              <Pill text={r.posture_verdict} color={scoreColor(r.security_score)} />
              <Text style={{ color: scoreColor(r.security_score), fontSize: 24, fontWeight: '800', marginLeft: space.md }}>
                {r.security_score}
              </Text>
            </Card>
          </Pressable>
          {open === r.hostname && <ReportView report={r} />}
        </View>
      ))}
      {items && items.length > 0 && <Button title="Clear history" variant="danger" onPress={clear} />}
    </ScrollView>
  );
}

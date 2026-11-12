import { Tabs } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import React from 'react';
import { Text } from 'react-native';

import { SettingsProvider } from '../src/settings';
import { colors } from '../src/theme';

const icon = (glyph: string) => () => <Text style={{ fontSize: 18 }}>{glyph}</Text>;

export default function RootLayout() {
  return (
    <SettingsProvider>
      <StatusBar style="light" />
      <Tabs
        screenOptions={{
          headerStyle: { backgroundColor: colors.bg },
          headerTintColor: colors.text,
          tabBarStyle: { backgroundColor: colors.bg, borderTopColor: colors.border },
          tabBarActiveTintColor: colors.cyan,
          tabBarInactiveTintColor: colors.textMuted,
          sceneStyle: { backgroundColor: colors.bg },
        }}
      >
        <Tabs.Screen name="index" options={{ title: 'Scan', tabBarIcon: icon('🛰️') }} />
        <Tabs.Screen name="history" options={{ title: 'History', tabBarIcon: icon('🗂️') }} />
        <Tabs.Screen name="analyze" options={{ title: 'ML Detector', tabBarIcon: icon('🧠') }} />
        <Tabs.Screen name="settings" options={{ title: 'Settings', tabBarIcon: icon('⚙️') }} />
      </Tabs>
    </SettingsProvider>
  );
}

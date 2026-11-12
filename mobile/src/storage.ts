import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

/**
 * Key-value storage for the server address and API key.
 * Native: the OS keychain/keystore (SecureStore). Web has no secure store, so it falls back to
 * sessionStorage — cleared when the tab closes — rather than silently persisting a secret.
 * Every call is best-effort: storage failing must never crash the app.
 */
export async function getItem(key: string): Promise<string | null> {
  try {
    if (Platform.OS === 'web') return globalThis.sessionStorage?.getItem(key) ?? null;
    return await SecureStore.getItemAsync(key);
  } catch {
    return null;
  }
}

export async function setItem(key: string, value: string): Promise<void> {
  try {
    if (Platform.OS === 'web') globalThis.sessionStorage?.setItem(key, value);
    else await SecureStore.setItemAsync(key, value);
  } catch {
    /* ignore */
  }
}

export async function deleteItem(key: string): Promise<void> {
  try {
    if (Platform.OS === 'web') globalThis.sessionStorage?.removeItem(key);
    else await SecureStore.deleteItemAsync(key);
  } catch {
    /* ignore */
  }
}

/**
 * Client-side per-IP traffic history accumulator.
 *
 * Since there is no backend endpoint for per-IP traffic history
 * (only global /stats/history), this hook accumulates per-IP snapshots
 * in a ring buffer as the dashboard polls per-IP stats every 2 seconds.
 */

import { useRef, useCallback, useState } from 'react';

export interface PerIPHistorySample {
  timestamp: number;
  timestamp_str: string;
  rx_bps: number;   // bytes_per_sec from per-IP features
  rx_pps: number;   // packets_per_sec
  tx_bps: number;   // not available per-IP, always 0
  tx_pps: number;   // not available per-IP, always 0
  drop_bps: number; // not available per-IP, always 0
  drop_pps: number; // not available per-IP, always 0
  fwd_bps: number;  // approximated as rx_bps
  fwd_pps: number;  // approximated as rx_pps
}

const MAX_SAMPLES = 120; // 4 minutes at 2s intervals
const MAX_IPS = 100;     // Evict oldest IPs beyond this limit

export function usePerIPHistory() {
  const historyRef = useRef<Map<string, PerIPHistorySample[]>>(new Map());
  // Incrementing version triggers re-renders when samples are added
  const [version, setVersion] = useState(0);

  const addSample = useCallback((ip: string, data: {
    packets_per_sec: number;
    bytes_per_sec: number;
  }) => {
    if (!ip) return;

    const now = Date.now();
    const sample: PerIPHistorySample = {
      timestamp: now,
      timestamp_str: new Date(now).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
      rx_bps: data.bytes_per_sec,
      rx_pps: data.packets_per_sec,
      tx_bps: 0,
      tx_pps: 0,
      drop_bps: 0,
      drop_pps: 0,
      fwd_bps: data.bytes_per_sec,
      fwd_pps: data.packets_per_sec,
    };

    let buffer = historyRef.current.get(ip);
    if (!buffer) {
      // Evict oldest entries if at capacity
      if (historyRef.current.size >= MAX_IPS) {
        const firstKey = historyRef.current.keys().next().value;
        if (firstKey) historyRef.current.delete(firstKey);
      }
      buffer = [];
      historyRef.current.set(ip, buffer);
    }
    buffer.push(sample);
    if (buffer.length > MAX_SAMPLES) {
      buffer.splice(0, buffer.length - MAX_SAMPLES);
    }
    setVersion(v => v + 1);
  }, []);

  const getHistory = useCallback((ip: string | null): PerIPHistorySample[] => {
    if (!ip) return [];
    return historyRef.current.get(ip) || [];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [version]);

  const clear = useCallback(() => {
    historyRef.current.clear();
    setVersion(0);
  }, []);

  return { addSample, getHistory, clear };
}

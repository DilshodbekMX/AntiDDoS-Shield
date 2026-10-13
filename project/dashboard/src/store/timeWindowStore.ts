/**
 * Time Window Store
 *
 * Controls how many seconds of data are shown on Feature Monitor charts.
 * Persisted to localStorage so the selection survives page refreshes.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

/** Preset time windows in seconds */
export const TIME_WINDOW_PRESETS = [30, 60, 90, 120, 300] as const;

interface TimeWindowState {
  /** Time window in seconds (how much history to show) */
  windowSeconds: number;
  setWindowSeconds: (seconds: number) => void;
}

export const useTimeWindowStore = create<TimeWindowState>()(
  persist(
    (set) => ({
      windowSeconds: 120,  // Default: 2 minutes
      setWindowSeconds: (seconds) =>
        set({ windowSeconds: Math.max(10, Math.min(600, seconds)) }),
    }),
    { name: 'time-window-storage' }
  )
);

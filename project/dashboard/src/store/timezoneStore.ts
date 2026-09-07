/**
 * Timezone Store
 *
 * Persists the user's chosen timezone offset for baseline charts
 * and any other time-dependent displays. Stored in localStorage.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface TimezoneOption {
  value: string;      // e.g. "UTC+5" or "auto"
  label: string;      // e.g. "UTC+5 (Uzbekistan, Pakistan)"
  offsetHours: number; // e.g. 5
}

export const TIMEZONE_OPTIONS: TimezoneOption[] = [
  { value: 'auto', label: 'Auto (browser)', offsetHours: 0 },
  { value: 'UTC-12', label: 'UTC-12 (Baker Island)', offsetHours: -12 },
  { value: 'UTC-11', label: 'UTC-11 (Samoa)', offsetHours: -11 },
  { value: 'UTC-10', label: 'UTC-10 (Hawaii)', offsetHours: -10 },
  { value: 'UTC-9', label: 'UTC-9 (Alaska)', offsetHours: -9 },
  { value: 'UTC-8', label: 'UTC-8 (Pacific Time)', offsetHours: -8 },
  { value: 'UTC-7', label: 'UTC-7 (Mountain Time)', offsetHours: -7 },
  { value: 'UTC-6', label: 'UTC-6 (Central Time)', offsetHours: -6 },
  { value: 'UTC-5', label: 'UTC-5 (Eastern Time)', offsetHours: -5 },
  { value: 'UTC-4', label: 'UTC-4 (Atlantic Time)', offsetHours: -4 },
  { value: 'UTC-3', label: 'UTC-3 (Argentina, Brazil)', offsetHours: -3 },
  { value: 'UTC-2', label: 'UTC-2 (South Georgia)', offsetHours: -2 },
  { value: 'UTC-1', label: 'UTC-1 (Azores)', offsetHours: -1 },
  { value: 'UTC+0', label: 'UTC+0 (London, Reykjavik)', offsetHours: 0 },
  { value: 'UTC+1', label: 'UTC+1 (Berlin, Paris)', offsetHours: 1 },
  { value: 'UTC+2', label: 'UTC+2 (Cairo, Helsinki)', offsetHours: 2 },
  { value: 'UTC+3', label: 'UTC+3 (Moscow, Riyadh)', offsetHours: 3 },
  { value: 'UTC+3:30', label: 'UTC+3:30 (Tehran)', offsetHours: 3.5 },
  { value: 'UTC+4', label: 'UTC+4 (Dubai, Baku)', offsetHours: 4 },
  { value: 'UTC+4:30', label: 'UTC+4:30 (Kabul)', offsetHours: 4.5 },
  { value: 'UTC+5', label: 'UTC+5 (Tashkent, Karachi)', offsetHours: 5 },
  { value: 'UTC+5:30', label: 'UTC+5:30 (India, Sri Lanka)', offsetHours: 5.5 },
  { value: 'UTC+5:45', label: 'UTC+5:45 (Nepal)', offsetHours: 5.75 },
  { value: 'UTC+6', label: 'UTC+6 (Almaty, Dhaka)', offsetHours: 6 },
  { value: 'UTC+6:30', label: 'UTC+6:30 (Myanmar)', offsetHours: 6.5 },
  { value: 'UTC+7', label: 'UTC+7 (Bangkok, Jakarta)', offsetHours: 7 },
  { value: 'UTC+8', label: 'UTC+8 (Beijing, Singapore)', offsetHours: 8 },
  { value: 'UTC+9', label: 'UTC+9 (Tokyo, Seoul)', offsetHours: 9 },
  { value: 'UTC+9:30', label: 'UTC+9:30 (Adelaide)', offsetHours: 9.5 },
  { value: 'UTC+10', label: 'UTC+10 (Sydney, Guam)', offsetHours: 10 },
  { value: 'UTC+11', label: 'UTC+11 (Solomon Islands)', offsetHours: 11 },
  { value: 'UTC+12', label: 'UTC+12 (Auckland, Fiji)', offsetHours: 12 },
  { value: 'UTC+13', label: 'UTC+13 (Samoa, Tonga)', offsetHours: 13 },
];

interface TimezoneState {
  timezone: string; // "auto" or "UTC+5" etc.
  setTimezone: (tz: string) => void;
  /** Returns the effective UTC offset in hours for chart rotation */
  getOffsetHours: () => number;
}

export const useTimezoneStore = create<TimezoneState>()(
  persist(
    (set, get) => ({
      timezone: 'auto',
      setTimezone: (tz) => set({ timezone: tz }),
      getOffsetHours: () => {
        const tz = get().timezone;
        if (tz === 'auto') {
          return -new Date().getTimezoneOffset() / 60;
        }
        const opt = TIMEZONE_OPTIONS.find((o) => o.value === tz);
        return opt ? opt.offsetHours : -new Date().getTimezoneOffset() / 60;
      },
    }),
    {
      name: 'timezone-storage',
    }
  )
);

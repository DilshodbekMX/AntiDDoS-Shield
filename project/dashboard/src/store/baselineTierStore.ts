/**
 * Baseline Tier Visibility Store
 *
 * Manages which EWMA baseline tiers are shown on Feature Monitor charts.
 * Persisted to localStorage so selections survive page refreshes.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type TierId = '1s' | '10s' | '60s' | 'hourly' | 'weekly';

const ALL_TIERS: TierId[] = ['1s', '10s', '60s', 'hourly', 'weekly'];

interface BaselineTierState {
  /** Set of enabled tier IDs */
  enabledTiers: TierId[];
  /** Toggle a single tier on/off */
  toggleTier: (id: TierId) => void;
  /** Enable all tiers */
  enableAll: () => void;
  /** Disable all tiers */
  disableAll: () => void;
  /** Check if a tier is enabled */
  isTierEnabled: (id: TierId) => boolean;
}

export const useBaselineTierStore = create<BaselineTierState>()(
  persist(
    (set, get) => ({
      enabledTiers: ['10s'] as TierId[],  // Default: only 10s EWMA shown
      toggleTier: (id) =>
        set((state) => {
          const idx = state.enabledTiers.indexOf(id);
          if (idx >= 0) {
            return { enabledTiers: state.enabledTiers.filter((t) => t !== id) };
          }
          return { enabledTiers: [...state.enabledTiers, id] };
        }),
      enableAll: () => set({ enabledTiers: [...ALL_TIERS] }),
      disableAll: () => set({ enabledTiers: [] }),
      isTierEnabled: (id) => get().enabledTiers.includes(id),
    }),
    { name: 'baseline-tier-storage' }
  )
);

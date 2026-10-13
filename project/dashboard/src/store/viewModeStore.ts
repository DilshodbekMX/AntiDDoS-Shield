/**
 * View Mode Store
 *
 * Controls whether Feature Monitor charts show EWMA baselines
 * or post-EWMA detection metrics (z-score, CUSUM, JSD, etc.).
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export type ViewMode = 'ewma' | 'detection';

interface ViewModeState {
  viewMode: ViewMode;
  setViewMode: (mode: ViewMode) => void;
}

export const useViewModeStore = create<ViewModeState>()(
  persist(
    (set) => ({
      viewMode: 'ewma' as ViewMode,
      setViewMode: (mode) => set({ viewMode: mode }),
    }),
    { name: 'view-mode-storage' }
  )
);

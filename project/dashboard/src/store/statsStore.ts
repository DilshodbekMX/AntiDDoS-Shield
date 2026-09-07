/**
 * Stats Store
 *
 * Global state for aggregated traffic and security statistics.
 * Components can subscribe to avoid redundant polling from multiple sources.
 */

import { create } from 'zustand';
import { SystemStats, TrafficHistorySample } from '../types';

interface StatsStore {
  currentStats: SystemStats | null;
  trafficHistory: TrafficHistorySample[];
  lastUpdated: number | null;
  setCurrentStats: (stats: SystemStats) => void;
  setTrafficHistory: (history: TrafficHistorySample[]) => void;
  clearStats: () => void;
}

export const useStatsStore = create<StatsStore>((set) => ({
  currentStats: null,
  trafficHistory: [],
  lastUpdated: null,
  setCurrentStats: (stats) => set({ currentStats: stats, lastUpdated: Date.now() }),
  setTrafficHistory: (history) => set({ trafficHistory: history }),
  clearStats: () => set({ currentStats: null, trafficHistory: [], lastUpdated: null }),
}));

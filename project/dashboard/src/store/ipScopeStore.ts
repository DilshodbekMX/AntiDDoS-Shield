/**
 * IP Scope Store
 *
 * Manages the currently selected protected IP for scoped views.
 * When selectedIP is null, pages show global aggregate data.
 * When set, pages show data for that specific protected IP.
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface IPScopeState {
  /** null means "All Protected IPs" (global view) */
  selectedIP: string | null;
  setSelectedIP: (ip: string | null) => void;
}

export const useIPScopeStore = create<IPScopeState>()(
  persist(
    (set) => ({
      selectedIP: null,
      setSelectedIP: (ip) => set({ selectedIP: ip || null }),
    }),
    { name: 'ip-scope-storage' }
  )
);

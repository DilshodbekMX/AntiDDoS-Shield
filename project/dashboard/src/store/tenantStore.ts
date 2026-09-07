/**
 * Tenant Store
 *
 * Global state for multi-tenant context: the tenant list and the currently
 * selected tenant. Components should call useTenantStore() to read/update
 * tenant selection without prop-drilling.
 */

import { create } from 'zustand';
import { Tenant } from '../types';

interface TenantStore {
  tenants: Tenant[];
  currentTenant: Tenant | null;
  currentTenantId: string | null;
  setTenants: (tenants: Tenant[]) => void;
  setCurrentTenant: (tenant: Tenant | null) => void;
}

export const useTenantStore = create<TenantStore>((set) => ({
  tenants: [],
  currentTenant: null,
  currentTenantId: null,
  setTenants: (tenants) => set({ tenants }),
  setCurrentTenant: (tenant) =>
    set({
      currentTenant: tenant,
      currentTenantId: tenant ? String(tenant.id) : null,
    }),
}));

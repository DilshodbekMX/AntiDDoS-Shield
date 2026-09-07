/**
 * TenantSelector Component (Multi-Tenant)
 *
 * Dropdown selector for switching between tenants.
 * Only visible to admin users with multi-tenant access.
 */

import { Fragment, useState, useEffect, useCallback } from 'react';
import { logError } from '../../utils/logger';
import { Combobox, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
  ChevronUpDownIcon,
  CheckIcon,
  BuildingOfficeIcon,
  MagnifyingGlassIcon,
  PlusIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline';
import { useTenantStore, useAuthStore } from '../../store';
import { Tenant, TenantStatus, TenantTier } from '../../types';

// ============================================================================
// Types
// ============================================================================

interface TenantSelectorProps {
  className?: string;
  compact?: boolean;
}

// ============================================================================
// Constants
// ============================================================================

const GLOBAL_TENANT: Partial<Tenant> = {
  id: 0,
  name: 'All Tenants (Global)',
  tier: TenantTier.ENTERPRISE,
  status: TenantStatus.ACTIVE,
};

const tierColors: Record<TenantTier, string> = {
  [TenantTier.FREE]: 'bg-slate-500',
  [TenantTier.BASIC]: 'bg-blue-500',
  [TenantTier.STANDARD]: 'bg-emerald-500',
  [TenantTier.PREMIUM]: 'bg-purple-500',
  [TenantTier.ENTERPRISE]: 'bg-amber-500',
  [TenantTier.CUSTOM]: 'bg-pink-500',
};

const statusIndicators: Record<TenantStatus, { color: string; pulse: boolean }> = {
  [TenantStatus.ACTIVE]: { color: 'bg-emerald-500', pulse: false },
  [TenantStatus.ATTACK_MODE]: { color: 'bg-red-500', pulse: true },
  [TenantStatus.PROVISIONING]: { color: 'bg-yellow-500', pulse: true },
  [TenantStatus.SUSPENDED]: { color: 'bg-orange-500', pulse: false },
  [TenantStatus.MAINTENANCE]: { color: 'bg-blue-500', pulse: false },
  [TenantStatus.MIGRATING]: { color: 'bg-purple-500', pulse: true },
  [TenantStatus.DISABLED]: { color: 'bg-slate-500', pulse: false },
};

// ============================================================================
// Helper Components
// ============================================================================

function TenantOption({ tenant, selected }: { tenant: Tenant | Partial<Tenant>; selected: boolean }) {
  const status = statusIndicators[tenant.status || TenantStatus.ACTIVE];
  const isGlobal = tenant.id === 0;

  return (
    <div className="flex items-center gap-3 py-1">
      {/* Icon */}
      <div
        className={clsx(
          'flex h-8 w-8 items-center justify-center rounded-lg',
          isGlobal ? 'bg-brand-500/20' : 'bg-slate-200 dark:bg-slate-700'
        )}
      >
        {isGlobal ? (
          <GlobeAltIcon className="h-4 w-4 text-brand-500 dark:text-brand-400" />
        ) : (
          <BuildingOfficeIcon className="h-4 w-4 text-slate-600 dark:text-slate-400" />
        )}
      </div>

      {/* Details */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span
            className={clsx(
              'text-sm font-medium truncate',
              selected ? 'text-brand-600 dark:text-white' : 'text-slate-700 dark:text-slate-300'
            )}
          >
            {tenant.name}
          </span>
          {!isGlobal && tenant.tier && (
            <span
              className={clsx(
                'inline-flex items-center rounded-full px-1.5 py-0.5 text-2xs font-medium text-slate-900 dark:text-white',
                tierColors[tenant.tier]
              )}
            >
              {tenant.tier}
            </span>
          )}
        </div>
        {!isGlobal && (
          <div className="flex items-center gap-2 mt-0.5">
            <span className="text-2xs text-slate-600 dark:text-slate-500">ID: {tenant.id}</span>
            <div className="flex items-center gap-1">
              <div className={clsx('h-1.5 w-1.5 rounded-full', status.color, status.pulse && 'animate-pulse')} />
              <span className="text-2xs text-slate-600 dark:text-slate-500 capitalize">
                {tenant.status?.replace('_', ' ')}
              </span>
            </div>
          </div>
        )}
      </div>

      {/* Selected Check */}
      {selected && (
        <CheckIcon className="h-5 w-5 text-brand-400 shrink-0" />
      )}
    </div>
  );
}

// ============================================================================
// Main Component
// ============================================================================

export function TenantSelector({ className, compact = false }: TenantSelectorProps) {
  const { user } = useAuthStore();
  const { currentTenant, tenants, setCurrentTenant, setTenants } = useTenantStore();
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);

  // Only show for admin users
  const isAdmin = user?.is_admin === true;

  // Fetch tenants on mount
  const fetchTenants = useCallback(async () => {
    if (!isAdmin) return;

    setLoading(true);
    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:8000/api/v2';
      const response = await fetch(`${apiUrl}/tenants`, {
        credentials: 'include',  // Send cookies for auth
      });

      if (response.ok) {
        const data = await response.json();
        setTenants(data.items || data);

        // Set default tenant if none selected
        if (!currentTenant && data.length > 0) {
          setCurrentTenant(data[0]);
        }
      }
    } catch (error) {
      logError('TenantSelector.fetchTenants', error);
    } finally {
      setLoading(false);
    }
  }, [isAdmin, currentTenant, setCurrentTenant, setTenants]);

  useEffect(() => {
    fetchTenants();
  }, [fetchTenants]);

  // Don't render for non-admin users
  if (!isAdmin) {
    return null;
  }

  // Filter out disabled/suspended tenants from the list
  const activeTenants = tenants.filter(
    (t) => t.status !== TenantStatus.DISABLED && t.status !== TenantStatus.SUSPENDED
  );

  // Filter tenants by search query
  const allTenants = [GLOBAL_TENANT as Tenant, ...activeTenants];
  const filteredTenants =
    query === ''
      ? allTenants
      : allTenants.filter((tenant) =>
          tenant.name.toLowerCase().includes(query.toLowerCase()) ||
          tenant.id.toString().includes(query)
        );

  // Count active tenants under attack (exclude disabled/suspended)
  const attackCount = activeTenants.filter(t => t.status === TenantStatus.ATTACK_MODE).length;

  const selectedTenant = currentTenant || GLOBAL_TENANT;

  return (
    <Combobox
      value={selectedTenant}
      onChange={(tenant) => {
        if (tenant) {
          setCurrentTenant(tenant.id === 0 ? null : tenant as Tenant);
        }
      }}
    >
      <div className={clsx('relative', className)}>
        <div className="relative">
          <Combobox.Button
            className={clsx(
              'relative w-full cursor-pointer rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-800 text-left transition-colors',
              'hover:border-slate-400 dark:hover:border-slate-300 dark:border-slate-600 focus:border-brand-500 focus:outline-none focus:ring-1 focus:ring-brand-500',
              compact ? 'py-1.5 pl-3 pr-8' : 'py-2 pl-3 pr-10'
            )}
          >
            <div className="flex items-center gap-2">
              {selectedTenant.id === 0 ? (
                <GlobeAltIcon className="h-4 w-4 text-brand-500 dark:text-brand-400" />
              ) : (
                <BuildingOfficeIcon className="h-4 w-4 text-slate-600 dark:text-slate-400" />
              )}
              <span className="block truncate text-sm text-slate-900 dark:text-white">
                {compact ? (selectedTenant.id === 0 ? 'Global' : `#${selectedTenant.id}`) : selectedTenant.name}
              </span>
              {attackCount > 0 && (
                <span className="flex h-5 min-w-[20px] items-center justify-center rounded-full bg-red-500 px-1.5 text-2xs font-bold text-white animate-pulse">
                  {attackCount}
                </span>
              )}
            </div>
            <span className="pointer-events-none absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronUpDownIcon className="h-5 w-5 text-slate-600 dark:text-slate-400" aria-hidden="true" />
            </span>
          </Combobox.Button>

          <Transition
            as={Fragment}
            leave="transition ease-in duration-100"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
            afterLeave={() => setQuery('')}
          >
            <Combobox.Options
              className={clsx(
                'absolute z-50 mt-2 max-h-80 w-[calc(100vw-2rem)] sm:w-72 overflow-auto rounded-lg',
                'bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-xl',
                'focus:outline-none'
              )}
            >
              {/* Search Input */}
              <div className="sticky top-0 z-10 bg-white dark:bg-slate-800 p-2 border-b border-slate-200 dark:border-slate-700">
                <div className="relative">
                  <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400 dark:text-slate-500" />
                  <Combobox.Input
                    className={clsx(
                      'w-full rounded-md border-0 bg-slate-100 dark:bg-slate-900 py-2 pl-9 pr-3 text-sm text-slate-900 dark:text-white',
                      'placeholder:text-slate-500 focus:ring-1 focus:ring-brand-500'
                    )}
                    placeholder="Search tenants..."
                    onChange={(event) => setQuery(event.target.value)}
                    displayValue={() => ''}
                  />
                </div>
              </div>

              {/* Loading State */}
              {loading && (
                <div className="px-4 py-8 text-center">
                  <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-brand-500 border-r-transparent" />
                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">Loading tenants...</p>
                </div>
              )}

              {/* Empty State */}
              {!loading && filteredTenants.length === 0 && (
                <div className="px-4 py-8 text-center">
                  <BuildingOfficeIcon className="mx-auto h-8 w-8 text-slate-400 dark:text-slate-600" />
                  <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">No tenants found</p>
                  {query && (
                    <p className="text-2xs text-slate-500">Try a different search term</p>
                  )}
                </div>
              )}

              {/* Tenant List */}
              {!loading && filteredTenants.length > 0 && (
                <div className="p-2">
                  {filteredTenants.map((tenant) => (
                    <Combobox.Option
                      key={tenant.id}
                      value={tenant}
                      className={({ active }) =>
                        clsx(
                          'cursor-pointer rounded-lg px-3 py-2 transition-colors',
                          active ? 'bg-slate-100 dark:bg-slate-700' : ''
                        )
                      }
                    >
                      {({ selected }) => (
                        <TenantOption tenant={tenant} selected={selected} />
                      )}
                    </Combobox.Option>
                  ))}
                </div>
              )}

              {/* Quick Actions */}
              <div className="sticky bottom-0 border-t border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-2">
                <a
                  href="/tenants"
                  className={clsx(
                    'flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-slate-600 dark:text-slate-400',
                    'hover:bg-slate-100 dark:hover:bg-slate-700 hover:text-slate-900 dark:hover:text-white transition-colors'
                  )}
                >
                  <PlusIcon className="h-4 w-4" />
                  Manage Tenants
                </a>
              </div>
            </Combobox.Options>
          </Transition>
        </div>
      </div>
    </Combobox>
  );
}

export default TenantSelector;

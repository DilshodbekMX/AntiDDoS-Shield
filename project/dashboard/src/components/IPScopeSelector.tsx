/**
 * IP Scope Selector
 *
 * Dropdown to switch between global (all IPs) and per-IP scoped views.
 * Fetches protected IP list from per-IP stats endpoint.
 * Stores selection in Zustand with localStorage persistence.
 */

import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import { clsx } from 'clsx';
import api from '../services/api';
import { useIPScopeStore } from '../store';

interface IPScopeSelectorProps {
  className?: string;
}

export function IPScopeSelector({ className }: IPScopeSelectorProps) {
  const { selectedIP, setSelectedIP } = useIPScopeStore();

  const { data: perIPStats } = useQuery({
    queryKey: ['per-ip-stats-selector'],
    queryFn: () => api.getPerIPStats(),
    refetchInterval: 5000,
  });

  const options = useMemo(() => {
    const ips = perIPStats?.protected_ips || [];
    return ips.map((ip) => ({
      value: ip.dst_ip_str,
      anomalyActive: !!ip.anomaly_active,
      hasTraffic: ip.packets_per_sec > 0 || ip.bytes_per_sec > 0,
    }));
  }, [perIPStats]);

  return (
    <div className={clsx('flex items-center gap-2', className)}>
      <select
        value={selectedIP || ''}
        onChange={(e) => setSelectedIP(e.target.value || null)}
        className={clsx(
          'rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm',
          'dark:border-slate-600 dark:bg-slate-800 dark:text-white',
          'focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20',
          'focus:outline-none transition-colors duration-150',
          'w-full sm:w-52'
        )}
      >
        <option value="">All Protected IPs</option>
        {options.map((opt: { value: string; anomalyActive: boolean; hasTraffic: boolean }) => (
          <option key={opt.value} value={opt.value}>
            {opt.anomalyActive ? '\u{1F534} ' : opt.hasTraffic ? '\u{1F7E2} ' : '\u26AA '}{opt.value}
          </option>
        ))}
      </select>
    </div>
  );
}

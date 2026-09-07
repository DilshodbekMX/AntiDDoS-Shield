/**
 * IP Lists Management Page
 *
 * Manages blacklist, whitelist, and protected IP entries using real DPDK rules engine.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ServerStackIcon,
  PlusIcon,
  TrashIcon,
  MagnifyingGlassIcon,
  XMarkIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';

type ListTab = 'blacklist' | 'whitelist' | 'protected';

interface RulesIPEntry {
  ip: string;
  description: string;
  added: string;
  expires: string | null;
}

interface RulesStats {
  whitelist_count: number;
  blacklist_count: number;
  protected_count: number;
  cidr_whitelist_count: number;
  last_sync: string | null;
  datapath_connected: boolean;
}

export function IPListsPage() {
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<ListTab>('blacklist');
  const [search, setSearch] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [newIP, setNewIP] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newDuration, setNewDuration] = useState('');

  // Fetch rules stats
  const { data: rulesStats } = useQuery({
    queryKey: ['rules-stats'],
    queryFn: () => api.getRulesStats() as unknown as Promise<RulesStats>,
    refetchInterval: 5000,
  });

  // Fetch blacklist
  const { data: blacklistData, isLoading: blacklistLoading } = useQuery({
    queryKey: ['rules-blacklist'],
    queryFn: () => api.getRulesBlacklist() as Promise<{ entries: RulesIPEntry[]; count: number }>,
    enabled: activeTab === 'blacklist',
    refetchInterval: 5000,
  });

  // Fetch whitelist
  const { data: whitelistData, isLoading: whitelistLoading } = useQuery({
    queryKey: ['rules-whitelist'],
    queryFn: () => api.getRulesWhitelist() as Promise<{ entries: RulesIPEntry[]; count: number }>,
    enabled: activeTab === 'whitelist',
    refetchInterval: 5000,
  });

  // Fetch protected IPs
  const { data: protectedData, isLoading: protectedLoading } = useQuery({
    queryKey: ['rules-protected'],
    queryFn: () => api.getRulesProtected() as Promise<{ entries: RulesIPEntry[]; count: number }>,
    enabled: activeTab === 'protected',
    refetchInterval: 5000,
  });

  // Add mutation
  const addMutation = useMutation({
    mutationFn: (data: { ip: string; description?: string; expires_hours?: number }) => {
      if (activeTab === 'blacklist') {
        return api.addRulesBlacklist(data);
      } else if (activeTab === 'whitelist') {
        return api.addRulesWhitelist(data);
      }
      return api.addRulesProtected({ ip: data.ip, description: data.description });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`rules-${activeTab}`] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success(`IP added to ${activeTab}`);
      setShowAddModal(false);
      setNewIP('');
      setNewDescription('');
      setNewDuration('');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to add IP');
    },
  });

  // Remove mutation
  const removeMutation = useMutation({
    mutationFn: (ip: string) => {
      if (activeTab === 'blacklist') {
        return api.removeRulesBlacklist(ip);
      } else if (activeTab === 'whitelist') {
        return api.removeRulesWhitelist(ip);
      }
      return api.removeRulesProtected(ip);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: [`rules-${activeTab}`] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success(`IP removed from ${activeTab}`);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to remove IP');
    },
  });

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: () => api.syncRules(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success(`Synced ${data.synced}/${data.total} rules to datapath`);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to sync rules');
    },
  });

  // Cleanup mutation
  const cleanupMutation = useMutation({
    mutationFn: () => api.cleanupRules(),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: ['rules-blacklist'] });
      queryClient.invalidateQueries({ queryKey: ['rules-whitelist'] });
      queryClient.invalidateQueries({ queryKey: ['rules-stats'] });
      toast.success(`Cleaned up ${data.count} expired entries`);
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to cleanup expired rules');
    },
  });

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    const expires_hours = newDuration ? parseInt(newDuration) : undefined;
    addMutation.mutate({
      ip: newIP,
      description: newDescription || undefined,
      expires_hours,
    });
  };

  // Get current data based on active tab
  const getCurrentData = () => {
    switch (activeTab) {
      case 'blacklist':
        return blacklistData;
      case 'whitelist':
        return whitelistData;
      case 'protected':
        return protectedData;
    }
  };

  const isLoading = () => {
    switch (activeTab) {
      case 'blacklist':
        return blacklistLoading;
      case 'whitelist':
        return whitelistLoading;
      case 'protected':
        return protectedLoading;
    }
  };

  const currentData = getCurrentData();

  // Filter entries by search
  const filteredEntries = currentData?.entries.filter(entry =>
    entry.ip.includes(search) || entry.description.toLowerCase().includes(search.toLowerCase())
  ) || [];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            IP Lists
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Manage blacklist, whitelist, and protected IP entries
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* Connection status */}
          <div className="flex items-center gap-2 text-sm">
            <span className={clsx(
              'h-2 w-2 rounded-full',
              rulesStats?.datapath_connected ? 'bg-green-500' : 'bg-red-500'
            )} />
            <span className="text-gray-500 dark:text-gray-400">
              {rulesStats?.datapath_connected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-gray-600 px-3 py-2 text-sm font-semibold text-slate-900 dark:text-white shadow-sm hover:bg-gray-500"
          >
            <ArrowPathIcon className={clsx('h-4 w-4', syncMutation.isPending && 'animate-spin')} />
            Sync
          </button>
          <button
            onClick={() => cleanupMutation.mutate()}
            disabled={cleanupMutation.isPending}
            className="inline-flex items-center gap-2 rounded-md bg-yellow-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-yellow-500"
          >
            Cleanup Expired
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
          >
            <PlusIcon className="h-4 w-4" />
            Add IP
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-4 sm:space-x-8 overflow-x-auto">
          <button
            onClick={() => setActiveTab('blacklist')}
            className={clsx(
              'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'blacklist'
                ? 'border-red-500 text-red-600 dark:text-red-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            )}
          >
            <ShieldExclamationIcon className="h-5 w-5" />
            Blacklist
            <span className="ml-2 rounded-full bg-red-100 px-2.5 py-0.5 text-xs font-medium text-red-800">
              {rulesStats?.blacklist_count || 0}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('whitelist')}
            className={clsx(
              'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'whitelist'
                ? 'border-green-500 text-green-600 dark:text-green-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            )}
          >
            <ShieldCheckIcon className="h-5 w-5" />
            Whitelist
            <span className="ml-2 rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800">
              {rulesStats?.whitelist_count || 0}
            </span>
          </button>
          <button
            onClick={() => setActiveTab('protected')}
            className={clsx(
              'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm',
              activeTab === 'protected'
                ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            )}
          >
            <ServerStackIcon className="h-5 w-5" />
            Protected Servers
            <span className="ml-2 rounded-full bg-blue-100 px-2.5 py-0.5 text-xs font-medium text-blue-800">
              {rulesStats?.protected_count || 0}
            </span>
          </button>
        </nav>
      </div>

      {/* Search */}
      <div className="relative">
        <MagnifyingGlassIcon className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-400" />
        <input
          type="text"
          placeholder="Search by IP address or description..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-10 pr-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-indigo-500"
        />
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-x-auto">
        {isLoading() ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto"></div>
            <p className="mt-2 text-sm text-gray-500">Loading...</p>
          </div>
        ) : filteredEntries.length > 0 ? (
          <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
            <thead className="bg-gray-50 dark:bg-gray-700">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  IP Address
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Description
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Added
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Expires
                </th>
                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                  Actions
                </th>
              </tr>
            </thead>
            <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
              {filteredEntries.map((entry: RulesIPEntry) => {
                const isExpired = entry.expires && new Date(entry.expires) < new Date();
                return (
                  <tr key={entry.ip} className={isExpired ? 'opacity-50' : ''}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className="font-mono text-sm text-gray-900 dark:text-white">
                        {entry.ip}
                      </span>
                    </td>
                    <td className="px-6 py-4">
                      <span className="text-sm text-gray-500 dark:text-gray-400">
                        {entry.description || '-'}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {entry.added ? new Date(entry.added).toLocaleString() : '-'}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm">
                      {entry.expires ? (
                        <span className={isExpired ? 'text-red-500' : 'text-gray-500 dark:text-gray-400'}>
                          {isExpired ? 'Expired' : new Date(entry.expires).toLocaleString()}
                        </span>
                      ) : (
                        <span className="text-gray-400">Never</span>
                      )}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <button
                        onClick={() => removeMutation.mutate(entry.ip)}
                        disabled={removeMutation.isPending}
                        className="text-red-600 hover:text-red-900 dark:hover:text-red-400"
                      >
                        <TrashIcon className="h-5 w-5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="p-8 text-center">
            <ShieldCheckIcon className="h-12 w-12 mx-auto text-gray-400" />
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              No entries in {activeTab}
            </p>
          </div>
        )}
      </div>

      {/* Add Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowAddModal(false)} />
            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                  Add to {activeTab === 'blacklist' ? 'Blacklist' : activeTab === 'whitelist' ? 'Whitelist' : 'Protected Servers'}
                </h3>
                <button onClick={() => setShowAddModal(false)}>
                  <XMarkIcon className="h-6 w-6 text-gray-400 hover:text-gray-500" />
                </button>
              </div>
              <form onSubmit={handleAdd} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    IP Address or CIDR
                  </label>
                  <input
                    type="text"
                    value={newIP}
                    onChange={(e) => setNewIP(e.target.value)}
                    placeholder="192.168.1.1 or 10.0.0.0/24"
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description (optional)
                  </label>
                  <input
                    type="text"
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    placeholder="Reason for adding"
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                  />
                </div>
                {activeTab !== 'protected' && (
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Duration (hours, empty for permanent)
                    </label>
                    <input
                      type="number"
                      value={newDuration}
                      onChange={(e) => setNewDuration(e.target.value)}
                      placeholder="24"
                      min="1"
                      max="8760"
                      className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                    />
                  </div>
                )}
                <div className="flex justify-end gap-3 pt-4">
                  <button
                    type="button"
                    onClick={() => setShowAddModal(false)}
                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={addMutation.isPending}
                    className={clsx(
                      'px-4 py-2 text-sm font-medium text-slate-900 dark:text-white rounded-md',
                      activeTab === 'blacklist'
                        ? 'bg-red-600 hover:bg-red-700'
                        : activeTab === 'whitelist'
                          ? 'bg-green-600 hover:bg-green-700'
                          : 'bg-blue-600 hover:bg-blue-700',
                      addMutation.isPending && 'opacity-50'
                    )}
                  >
                    {addMutation.isPending ? 'Adding...' : 'Add'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default IPListsPage;

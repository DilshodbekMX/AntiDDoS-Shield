/**
 * Policies Page
 *
 * Manage tenant security policies.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldCheckIcon,
  PlusIcon,
  PencilIcon,
  TrashIcon,
  XMarkIcon,
  PlayIcon,
  PauseIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { useTenantStore } from '../store';
import { Policy, PolicyCreate, PolicyAction } from '../types';

const actionColors: Record<string, string> = {
  allow: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
  block: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
  rate_limit: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
  challenge: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
  log: 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300',
};

const sourceLabels: Record<string, string> = {
  manual: 'Manual',
  ml_generated: 'ML Generated',
  auto_response: 'Auto Response',
  threat_intel: 'Threat Intel',
};

export function PoliciesPage() {
  const { currentTenant } = useTenantStore();
  const tenantId = currentTenant?.id || 1;
  const queryClient = useQueryClient();

  const [page, setPage] = useState(1);
  const [showModal, setShowModal] = useState(false);
  const [editingPolicy, setEditingPolicy] = useState<Policy | null>(null);
  const [formData, setFormData] = useState({
    name: '',
    description: '',
    action: PolicyAction.BLOCK,
    priority: 100,
    conditions: '{}',
    rate_limit_pps: undefined as number | undefined,
    rate_limit_bps: undefined as number | undefined,
  });

  // Fetch policies
  const { data: policiesData, isLoading } = useQuery({
    queryKey: ['policies', tenantId, page],
    queryFn: () => api.getPolicies({ page, per_page: 20 }),
  });

  // Create mutation
  const createMutation = useMutation({
    mutationFn: (data: PolicyCreate) => api.createPolicy(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies', tenantId] });
      toast.success('Policy created successfully');
      closeModal();
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to create policy');
    },
  });

  // Update mutation
  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<PolicyCreate> }) =>
      api.updatePolicy(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies', tenantId] });
      toast.success('Policy updated successfully');
      closeModal();
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to update policy');
    },
  });

  // Toggle mutation
  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: number; enabled: boolean }) =>
      api.togglePolicy(id, enabled),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies', tenantId] });
      toast.success('Policy updated');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to toggle policy');
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.deletePolicy(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['policies', tenantId] });
      toast.success('Policy deleted');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to delete policy');
    },
  });

  const openCreateModal = () => {
    setEditingPolicy(null);
    setFormData({
      name: '',
      description: '',
      action: PolicyAction.BLOCK,
      priority: 100,
      conditions: '{}',
      rate_limit_pps: undefined,
      rate_limit_bps: undefined,
    });
    setShowModal(true);
  };

  const openEditModal = (policy: Policy) => {
    setEditingPolicy(policy);
    setFormData({
      name: policy.name,
      description: policy.description || '',
      action: policy.action,
      priority: policy.priority,
      conditions: JSON.stringify(policy.conditions, null, 2),
      rate_limit_pps: policy.rate_limit_pps,
      rate_limit_bps: policy.rate_limit_bps,
    });
    setShowModal(true);
  };

  const closeModal = () => {
    setShowModal(false);
    setEditingPolicy(null);
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    let conditions;
    try {
      conditions = JSON.parse(formData.conditions);
    } catch {
      toast.error('Invalid JSON in conditions');
      return;
    }

    const data: PolicyCreate = {
      name: formData.name,
      description: formData.description || undefined,
      action: formData.action,
      priority: formData.priority,
      conditions,
      rate_limit_pps: formData.action === 'rate_limit' ? formData.rate_limit_pps : undefined,
      rate_limit_bps: formData.action === 'rate_limit' ? formData.rate_limit_bps : undefined,
    };

    if (editingPolicy) {
      updateMutation.mutate({ id: editingPolicy.id, data });
    } else {
      createMutation.mutate(data);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Policies
          </h1>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Manage security policies and rules
          </p>
        </div>
        <button
          onClick={openCreateModal}
          className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
        >
          <PlusIcon className="h-4 w-4" />
          Create Policy
        </button>
      </div>

      {/* Policies Table */}
      <div className="bg-white dark:bg-gray-800 shadow rounded-lg overflow-x-auto">
        {isLoading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto"></div>
            <p className="mt-2 text-sm text-gray-500">Loading policies...</p>
          </div>
        ) : policiesData && policiesData.items.length > 0 ? (
          <>
            <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
              <thead className="bg-gray-50 dark:bg-gray-700">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Name
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Action
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Priority
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Source
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Matches
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                {policiesData.items.map((policy: Policy) => (
                  <tr key={policy.id} className={!policy.enabled ? 'opacity-50' : ''}>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <button
                        onClick={() => toggleMutation.mutate({ id: policy.id, enabled: !policy.enabled })}
                        disabled={toggleMutation.isPending}
                        className={clsx(
                          'p-1 rounded-full',
                          policy.enabled
                            ? 'text-green-600 hover:bg-green-100 dark:hover:bg-green-900'
                            : 'text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700'
                        )}
                      >
                        {policy.enabled ? (
                          <PlayIcon className="h-5 w-5" />
                        ) : (
                          <PauseIcon className="h-5 w-5" />
                        )}
                      </button>
                    </td>
                    <td className="px-6 py-4">
                      <div>
                        <p className="text-sm font-medium text-gray-900 dark:text-white">
                          {policy.name}
                        </p>
                        {policy.description && (
                          <p className="text-xs text-gray-500 dark:text-gray-400 truncate max-w-xs">
                            {policy.description}
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={clsx(
                        'px-2 py-1 rounded-full text-xs font-medium',
                        actionColors[policy.action] || actionColors.log
                      )}>
                        {policy.action.replace('_', ' ')}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {policy.priority}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                      {sourceLabels[policy.source] || policy.source}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-white">
                      {policy.match_count?.toLocaleString() || 0}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => openEditModal(policy)}
                          className="text-indigo-600 hover:text-indigo-900 dark:hover:text-indigo-400"
                        >
                          <PencilIcon className="h-5 w-5" />
                        </button>
                        <button
                          onClick={() => {
                            if (confirm('Delete this policy?')) {
                              deleteMutation.mutate(policy.id);
                            }
                          }}
                          disabled={deleteMutation.isPending}
                          className="text-red-600 hover:text-red-900 dark:hover:text-red-400"
                        >
                          <TrashIcon className="h-5 w-5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>

            {/* Pagination */}
            {policiesData.pages > 1 && (
              <div className="px-6 py-4 bg-gray-50 dark:bg-gray-700 border-t border-gray-200 dark:border-gray-600 flex items-center justify-between">
                <span className="text-sm text-gray-500 dark:text-gray-400">
                  Page {policiesData.page} of {policiesData.pages} ({policiesData.total} policies)
                </span>
                <div className="flex gap-2">
                  <button
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                    disabled={page === 1}
                    className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50"
                  >
                    Previous
                  </button>
                  <button
                    onClick={() => setPage(p => Math.min(policiesData.pages, p + 1))}
                    disabled={page === policiesData.pages}
                    className="px-3 py-1 border border-gray-300 dark:border-gray-600 rounded-md text-sm disabled:opacity-50"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="p-8 text-center">
            <ShieldCheckIcon className="h-12 w-12 mx-auto text-gray-400" />
            <p className="mt-2 text-sm text-gray-500 dark:text-gray-400">
              No policies configured
            </p>
            <button
              onClick={openCreateModal}
              className="mt-4 text-indigo-600 hover:text-indigo-500 text-sm"
            >
              Create your first policy
            </button>
          </div>
        )}
      </div>

      {/* Create/Edit Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/50" onClick={closeModal} />
            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-lg w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                  {editingPolicy ? 'Edit Policy' : 'Create Policy'}
                </h3>
                <button onClick={closeModal}>
                  <XMarkIcon className="h-6 w-6 text-gray-400 hover:text-gray-500" />
                </button>
              </div>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Name
                  </label>
                  <input
                    type="text"
                    value={formData.name}
                    onChange={(e) => setFormData(f => ({ ...f, name: e.target.value }))}
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Description
                  </label>
                  <input
                    type="text"
                    value={formData.description}
                    onChange={(e) => setFormData(f => ({ ...f, description: e.target.value }))}
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Action
                    </label>
                    <select
                      value={formData.action}
                      onChange={(e) => setFormData(f => ({ ...f, action: e.target.value as PolicyAction }))}
                      className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                    >
                      <option value="allow">Allow</option>
                      <option value="block">Block</option>
                      <option value="rate_limit">Rate Limit</option>
                      <option value="challenge">Challenge</option>
                      <option value="log">Log Only</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                      Priority
                    </label>
                    <input
                      type="number"
                      value={formData.priority}
                      onChange={(e) => setFormData(f => ({ ...f, priority: parseInt(e.target.value) || 100 }))}
                      min="1"
                      max="1000"
                      className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                    />
                  </div>
                </div>
                {formData.action === 'rate_limit' && (
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Rate Limit PPS
                      </label>
                      <input
                        type="number"
                        value={formData.rate_limit_pps || ''}
                        onChange={(e) => setFormData(f => ({ ...f, rate_limit_pps: parseInt(e.target.value) || undefined }))}
                        placeholder="Packets per second"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                      />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                        Rate Limit BPS
                      </label>
                      <input
                        type="number"
                        value={formData.rate_limit_bps || ''}
                        onChange={(e) => setFormData(f => ({ ...f, rate_limit_bps: parseInt(e.target.value) || undefined }))}
                        placeholder="Bytes per second"
                        className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white"
                      />
                    </div>
                  </div>
                )}
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Conditions (JSON)
                  </label>
                  <textarea
                    value={formData.conditions}
                    onChange={(e) => setFormData(f => ({ ...f, conditions: e.target.value }))}
                    rows={5}
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md text-gray-900 dark:text-white font-mono text-sm"
                    placeholder='{"src_ip": "192.168.1.0/24", "protocol": "tcp"}'
                  />
                </div>
                <div className="flex justify-end gap-3 pt-4">
                  <button
                    type="button"
                    onClick={closeModal}
                    className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-md"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={createMutation.isPending || updateMutation.isPending}
                    className="px-4 py-2 text-sm font-medium text-slate-900 dark:text-white bg-indigo-600 rounded-md hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {createMutation.isPending || updateMutation.isPending
                      ? 'Saving...'
                      : editingPolicy ? 'Update' : 'Create'}
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

export default PoliciesPage;

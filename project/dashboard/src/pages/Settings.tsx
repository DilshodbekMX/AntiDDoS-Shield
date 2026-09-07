/**
 * Settings Page
 *
 * User settings, API tokens, and webhooks management.
 */

import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  UserCircleIcon,
  KeyIcon,
  BellIcon,
  PlusIcon,
  TrashIcon,
  XMarkIcon,
  ClipboardDocumentIcon,
  CheckIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { useAuthStore } from '../store';
import { TokenInfo, TokenCreate, Webhook, WebhookCreate, WebhookEvent } from '../types';

const webhookEventLabels: Record<WebhookEvent, string> = {
  [WebhookEvent.ATTACK_STARTED]: 'Attack Started',
  [WebhookEvent.ATTACK_ENDED]: 'Attack Ended',
  [WebhookEvent.ATTACK_MITIGATED]: 'Attack Mitigated',
  [WebhookEvent.THRESHOLD_EXCEEDED]: 'Threshold Exceeded',
  [WebhookEvent.CONFIG_CHANGED]: 'Config Changed',
  [WebhookEvent.SLA_BREACH]: 'SLA Breach',
};

export function SettingsPage() {
  const { user } = useAuthStore();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<'profile' | 'tokens' | 'webhooks'>('profile');
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [showWebhookModal, setShowWebhookModal] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [copiedToken, setCopiedToken] = useState(false);

  const [tokenForm, setTokenForm] = useState<TokenCreate>({
    name: '',
    permissions: ['read'],
    expires_in_hours: 720,
  });

  const [webhookForm, setWebhookForm] = useState<WebhookCreate>({
    url: '',
    events: [WebhookEvent.ATTACK_STARTED],
    secret: '',
    enabled: true,
  });

  // Fetch tokens
  const { data: tokens, isLoading: tokensLoading } = useQuery({
    queryKey: ['tokens'],
    queryFn: () => api.getTokens(),
    enabled: activeTab === 'tokens',
  });

  // Fetch webhooks
  const { data: webhooks, isLoading: webhooksLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: () => api.getWebhooks(),
    enabled: activeTab === 'webhooks',
  });

  // Create token mutation
  const createTokenMutation = useMutation({
    mutationFn: (data: TokenCreate) => api.createToken(data),
    onSuccess: (response) => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
      setNewToken(response.token);
      setShowTokenModal(false);
      setTokenForm({ name: '', permissions: ['read'], expires_in_hours: 720 });
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to create token');
    },
  });

  // Revoke token mutation
  const revokeTokenMutation = useMutation({
    mutationFn: (tokenId: string) => api.revokeToken(tokenId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tokens'] });
      toast.success('Token revoked');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to revoke token');
    },
  });

  // Create webhook mutation
  const createWebhookMutation = useMutation({
    mutationFn: (data: WebhookCreate) => api.createWebhook(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      toast.success('Webhook created');
      setShowWebhookModal(false);
      setWebhookForm({
        url: '',
        events: [WebhookEvent.ATTACK_STARTED],
        secret: '',
        enabled: true,
      });
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to create webhook');
    },
  });

  // Delete webhook mutation
  const deleteWebhookMutation = useMutation({
    mutationFn: (webhookId: string) => api.deleteWebhook(webhookId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] });
      toast.success('Webhook deleted');
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to delete webhook');
    },
  });

  // Test webhook mutation
  const testWebhookMutation = useMutation({
    mutationFn: (webhookId: string) => api.testWebhook(webhookId),
    onSuccess: (result) => {
      if (result.success) {
        toast.success('Webhook test successful');
      } else {
        toast.error(`Webhook test failed: ${result.message}`);
      }
    },
    onError: (error: Error) => {
      toast.error(error.message || 'Failed to test webhook');
    },
  });

  const copyToken = () => {
    if (newToken) {
      navigator.clipboard.writeText(newToken);
      setCopiedToken(true);
      setTimeout(() => setCopiedToken(false), 2000);
    }
  };

  const handleCreateToken = (e: React.FormEvent) => {
    e.preventDefault();
    createTokenMutation.mutate(tokenForm);
  };

  const handleCreateWebhook = (e: React.FormEvent) => {
    e.preventDefault();
    createWebhookMutation.mutate(webhookForm);
  };

  const toggleWebhookEvent = (event: WebhookEvent) => {
    setWebhookForm(f => ({
      ...f,
      events: f.events.includes(event)
        ? f.events.filter(e => e !== event)
        : [...f.events, event],
    }));
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          Settings
        </h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Manage your account and integrations
        </p>
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700">
        <nav className="-mb-px flex space-x-4 sm:space-x-8 overflow-x-auto">
          {[
            { key: 'profile', label: 'Profile', icon: UserCircleIcon },
            { key: 'tokens', label: 'API Tokens', icon: KeyIcon },
            { key: 'webhooks', label: 'Webhooks', icon: BellIcon },
          ].map((tab) => (
            <button
              key={tab.key}
              onClick={() => setActiveTab(tab.key as typeof activeTab)}
              className={clsx(
                'flex items-center gap-2 py-4 px-1 border-b-2 font-medium text-sm',
                activeTab === tab.key
                  ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
              )}
            >
              <tab.icon className="h-5 w-5" />
              {tab.label}
            </button>
          ))}
        </nav>
      </div>

      {/* Profile Tab */}
      {activeTab === 'profile' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                User Information
              </h3>
              <div className="mt-4 space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                      User ID
                    </label>
                    <p className="text-gray-900 dark:text-white">{user?.user_id || 'N/A'}</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                      Role
                    </label>
                    <p className="text-gray-900 dark:text-white">
                      {user?.is_admin ? 'Administrator' : 'User'}
                    </p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-500 dark:text-gray-400">
                      Auth Type
                    </label>
                    <p className="text-gray-900 dark:text-white uppercase">{user?.auth_type || 'JWT'}</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="border-t border-gray-200 dark:border-gray-700 pt-6">
              <h3 className="text-lg font-medium text-gray-900 dark:text-white">
                Permissions
              </h3>
              <div className="mt-4 flex flex-wrap gap-2">
                {user?.permissions.map((perm) => (
                  <span
                    key={perm}
                    className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-sm"
                  >
                    {perm}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tokens Tab */}
      {activeTab === 'tokens' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => setShowTokenModal(true)}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
            >
              <PlusIcon className="h-4 w-4" />
              Create Token
            </button>
          </div>

          {/* New Token Display */}
          {newToken && (
            <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
              <div className="flex items-start gap-3">
                <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600 dark:text-yellow-500 mt-0.5" />
                <div className="flex-1">
                  <p className="text-sm font-medium text-yellow-800 dark:text-yellow-300">
                    Copy your new API token now. You won't be able to see it again!
                  </p>
                  <div className="mt-2 flex items-center gap-2">
                    <code className="flex-1 px-3 py-2 bg-yellow-100 dark:bg-yellow-900 rounded text-sm font-mono text-yellow-900 dark:text-yellow-200 break-all">
                      {newToken}
                    </code>
                    <button
                      onClick={copyToken}
                      className="p-2 bg-yellow-100 dark:bg-yellow-900 rounded hover:bg-yellow-200 dark:hover:bg-yellow-800"
                    >
                      {copiedToken ? (
                        <CheckIcon className="h-5 w-5 text-green-600" />
                      ) : (
                        <ClipboardDocumentIcon className="h-5 w-5 text-yellow-700 dark:text-yellow-300" />
                      )}
                    </button>
                  </div>
                  <button
                    onClick={() => setNewToken(null)}
                    className="mt-2 text-sm text-yellow-700 dark:text-yellow-400 hover:underline"
                  >
                    I've copied my token
                  </button>
                </div>
              </div>
            </div>
          )}

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-x-auto">
            {tokensLoading ? (
              <div className="p-8 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto"></div>
              </div>
            ) : tokens && tokens.length > 0 ? (
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Name</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Permissions</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Created</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Expires</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Last Used</th>
                    <th className="px-3 sm:px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {tokens.map((token: TokenInfo) => (
                    <tr key={token.id}>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                        {token.name}
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap">
                        <div className="flex gap-1">
                          {token.permissions.slice(0, 3).map((p) => (
                            <span key={p} className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-xs rounded">
                              {p}
                            </span>
                          ))}
                          {token.permissions.length > 3 && (
                            <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-xs rounded">
                              +{token.permissions.length - 3}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {new Date(token.created_at).toLocaleDateString()}
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {token.expires_at ? new Date(token.expires_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                        {token.last_used_at ? new Date(token.last_used_at).toLocaleDateString() : 'Never'}
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-right">
                        <button
                          onClick={() => {
                            if (confirm('Revoke this token?')) {
                              revokeTokenMutation.mutate(token.id);
                            }
                          }}
                          className="text-red-600 hover:text-red-900"
                        >
                          <TrashIcon className="h-5 w-5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-8 text-center">
                <KeyIcon className="h-12 w-12 mx-auto text-gray-400" />
                <p className="mt-2 text-sm text-gray-500">No API tokens created</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Webhooks Tab */}
      {activeTab === 'webhooks' && (
        <div className="space-y-4">
          <div className="flex justify-end">
            <button
              onClick={() => setShowWebhookModal(true)}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-3 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
            >
              <PlusIcon className="h-4 w-4" />
              Add Webhook
            </button>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-x-auto">
            {webhooksLoading ? (
              <div className="p-8 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-600 mx-auto"></div>
              </div>
            ) : webhooks && webhooks.length > 0 ? (
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                <thead className="bg-gray-50 dark:bg-gray-700">
                  <tr>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">URL</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Events</th>
                    <th className="px-3 sm:px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Status</th>
                    <th className="px-3 sm:px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-gray-300 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                  {webhooks.map((webhook: Webhook) => (
                    <tr key={webhook.id}>
                      <td className="px-3 sm:px-6 py-4 text-sm text-gray-500 dark:text-gray-400 truncate max-w-xs">
                        {webhook.url}
                      </td>
                      <td className="px-3 sm:px-6 py-4">
                        <div className="flex flex-wrap gap-1">
                          {webhook.events.slice(0, 2).map((e) => (
                            <span key={e} className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-xs rounded">
                              {webhookEventLabels[e as WebhookEvent] || e}
                            </span>
                          ))}
                          {webhook.events.length > 2 && (
                            <span className="px-1.5 py-0.5 bg-gray-100 dark:bg-gray-700 text-xs rounded">
                              +{webhook.events.length - 2}
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap">
                        <span className={clsx(
                          'px-2 py-1 rounded-full text-xs font-medium',
                          webhook.enabled
                            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
                            : 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300'
                        )}>
                          {webhook.enabled ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td className="px-3 sm:px-6 py-4 whitespace-nowrap text-right">
                        <div className="flex justify-end gap-2">
                          <button
                            onClick={() => testWebhookMutation.mutate(webhook.id)}
                            disabled={testWebhookMutation.isPending}
                            className="text-indigo-600 hover:text-indigo-900 text-sm"
                          >
                            Test
                          </button>
                          <button
                            onClick={() => {
                              if (confirm('Delete this webhook?')) {
                                deleteWebhookMutation.mutate(webhook.id);
                              }
                            }}
                            className="text-red-600 hover:text-red-900"
                          >
                            <TrashIcon className="h-5 w-5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-8 text-center">
                <BellIcon className="h-12 w-12 mx-auto text-gray-400" />
                <p className="mt-2 text-sm text-gray-500">No webhooks configured</p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Create Token Modal */}
      {showTokenModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowTokenModal(false)} />
            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Create API Token</h3>
                <button onClick={() => setShowTokenModal(false)}>
                  <XMarkIcon className="h-6 w-6 text-gray-400" />
                </button>
              </div>
              <form onSubmit={handleCreateToken} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Name</label>
                  <input
                    type="text"
                    value={tokenForm.name}
                    onChange={(e) => setTokenForm(f => ({ ...f, name: e.target.value }))}
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Expires In (hours)</label>
                  <input
                    type="number"
                    value={tokenForm.expires_in_hours || ''}
                    onChange={(e) => setTokenForm(f => ({ ...f, expires_in_hours: parseInt(e.target.value) || undefined }))}
                    placeholder="Leave empty for no expiration"
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md"
                  />
                </div>
                <div className="flex justify-end gap-3 pt-4">
                  <button type="button" onClick={() => setShowTokenModal(false)} className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300">Cancel</button>
                  <button type="submit" disabled={createTokenMutation.isPending} className="px-4 py-2 text-sm text-slate-900 dark:text-white bg-indigo-600 rounded-md hover:bg-indigo-700 disabled:opacity-50">
                    {createTokenMutation.isPending ? 'Creating...' : 'Create'}
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}

      {/* Create Webhook Modal */}
      {showWebhookModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <div className="fixed inset-0 bg-black/50" onClick={() => setShowWebhookModal(false)} />
            <div className="relative bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-md w-full p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-medium text-gray-900 dark:text-white">Add Webhook</h3>
                <button onClick={() => setShowWebhookModal(false)}>
                  <XMarkIcon className="h-6 w-6 text-gray-400" />
                </button>
              </div>
              <form onSubmit={handleCreateWebhook} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">URL</label>
                  <input
                    type="url"
                    value={webhookForm.url}
                    onChange={(e) => setWebhookForm(f => ({ ...f, url: e.target.value }))}
                    placeholder="https://example.com/webhook"
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md"
                    required
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Events</label>
                  <div className="space-y-2">
                    {Object.entries(webhookEventLabels).map(([value, label]) => (
                      <label key={value} className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={webhookForm.events.includes(value as WebhookEvent)}
                          onChange={() => toggleWebhookEvent(value as WebhookEvent)}
                          className="rounded border-gray-300 text-indigo-600"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">{label}</span>
                      </label>
                    ))}
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Secret (optional)</label>
                  <input
                    type="text"
                    value={webhookForm.secret}
                    onChange={(e) => setWebhookForm(f => ({ ...f, secret: e.target.value }))}
                    placeholder="For HMAC signature validation"
                    className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded-md"
                  />
                </div>
                <div className="flex justify-end gap-3 pt-4">
                  <button type="button" onClick={() => setShowWebhookModal(false)} className="px-4 py-2 text-sm text-gray-700 dark:text-gray-300">Cancel</button>
                  <button type="submit" disabled={createWebhookMutation.isPending} className="px-4 py-2 text-sm text-slate-900 dark:text-white bg-indigo-600 rounded-md hover:bg-indigo-700 disabled:opacity-50">
                    {createWebhookMutation.isPending ? 'Creating...' : 'Create'}
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

export default SettingsPage;

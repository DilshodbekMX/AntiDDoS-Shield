/**
 * API Service for Anti-DDoS Dashboard
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import {
  APIResponse,
  PaginatedResponse,
  PaginationParams,
  StatsSummary,
  StatsHistoryPoint,
  Attack,
  AttackSummary,
  IPListEntry,
  IPListEntryCreate,
  IPListBulkAdd,
  Policy,
  PolicyCreate,
  PolicyUpdate,
  LoginCredentials,
  LoginResponse,
  User,
  StatsPeriod,
  Report,
  ReportRequest,
  Token,
  TokenCreate,
  TokenInfo,
  Webhook,
  WebhookCreate,
  WebhookUpdate,
  ConfigHistoryEntry,
  RealtimeStats,
  TrafficHistorySample,
  AnomalyStatus,
  PerIPAnomalyResponse,
  PerIPAnomalySummary,
  PerIPStatsResponse,
  PerIPStatsEntry,
} from '../types';
import type {
  SystemStats,
  RealtimeMetrics,
  TrafficResponse,
  SysmonResponse,
  ScheduledReport,
  PerIPAnomalyDict,
  PortStatsHistorySample,
  // re-exported for convenience
} from '../types/api';
import { API_BASE_URL, AUTH_CONFIG } from '../config';

class ApiService {
  private client: AxiosInstance;
  // Token stored in memory only (not localStorage) as fallback for non-cookie scenarios
  private token: string | null = null;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      headers: {
        'Content-Type': 'application/json',
      },
      // SECURITY: Enable credentials to send/receive httpOnly cookies
      // This is essential for cookie-based authentication
      withCredentials: AUTH_CONFIG.useCookieAuth,
    });

    // Request interceptor for auth + CSRF
    this.client.interceptors.request.use((config) => {
      // Only add Authorization header if we have a token in memory
      // (for API key scenarios or backwards compatibility)
      // Cookie auth is handled automatically by browser
      if (this.token) {
        config.headers.Authorization = `Bearer ${this.token}`;
      }
      // CSRF double-submit: read csrf_token cookie and echo in X-CSRF-Token header
      // Required for state-changing requests when using cookie auth
      if (config.method && !['get', 'head', 'options'].includes(config.method.toLowerCase())) {
        const csrfToken = document.cookie
          .split('; ')
          .find(row => row.startsWith('csrf_token='))
          ?.split('=')[1];
        if (csrfToken) {
          config.headers['X-CSRF-Token'] = csrfToken;
        }
      }
      return config;
    });

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          // Handle unauthorized - clear any in-memory token
          // The httpOnly cookie (if any) will be cleared by the logout endpoint
          this.token = null;
          // Dispatch a custom event that auth components can listen to
          window.dispatchEvent(new CustomEvent('auth:unauthorized'));
        }
        return Promise.reject(error);
      }
    );

    // SECURITY: We no longer store tokens in localStorage (XSS vulnerable)
    // Authentication is handled via httpOnly cookies set by the backend
    // The cookie cannot be accessed by JavaScript, protecting against XSS
  }

  /**
   * Set token in memory (for API key auth or special scenarios).
   * Regular browser sessions should use cookie auth instead.
   */
  setToken(token: string) {
    this.token = token;
  }

  /**
   * Clear in-memory token. Note: httpOnly cookie must be cleared
   * by calling the logout endpoint.
   */
  clearToken() {
    this.token = null;
  }

  /**
   * Check if we have authentication (either cookie or token).
   * Note: We can't check httpOnly cookies from JS, so we rely on
   * API responses to know if we're authenticated.
   */
  hasToken(): boolean {
    return this.token !== null;
  }

  // ==================== Auth ====================

  /**
   * Login with credentials.
   * The backend sets an httpOnly cookie automatically.
   * The token is also returned in the response for legacy/API scenarios.
   */
  async login(credentials: LoginCredentials): Promise<LoginResponse> {
    // use_cookie=true (default) tells backend to set httpOnly cookie
    const response = await this.client.post<LoginResponse>('/auth/login?use_cookie=true', credentials);
    // Note: We don't store the token in localStorage anymore for security
    // The httpOnly cookie handles authentication automatically
    return response.data;
  }

  /**
   * Logout - clears both the httpOnly cookie (server-side) and in-memory token.
   */
  async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } finally {
      // Always clear in-memory token even if request fails
      this.clearToken();
    }
  }

  async getCurrentUser(): Promise<User> {
    const response = await this.client.get<APIResponse<User>>('/auth/me');
    return response.data.data!;
  }

  /**
   * Check if currently authenticated (useful for httpOnly cookie auth).
   * Returns user info if authenticated, null otherwise.
   */
  async checkAuth(): Promise<User | null> {
    try {
      return await this.getCurrentUser();
    } catch {
      return null;
    }
  }

  // ==================== Stats ====================

  async getStats(period: StatsPeriod = StatsPeriod.REALTIME): Promise<SystemStats> {
    const response = await this.client.get<APIResponse<SystemStats>>(
      '/stats',
      { params: { period } }
    );
    return response.data.data!;
  }

  async getStatsSummary(): Promise<StatsSummary> {
    const response = await this.client.get<APIResponse<StatsSummary>>(
      '/stats/summary'
    );
    return response.data.data!;
  }

  async getTrafficHistory(
    start?: string,
    end?: string,
    resolution?: string
  ): Promise<StatsHistoryPoint[]> {
    const response = await this.client.get<APIResponse<StatsHistoryPoint[]>>(
      '/stats/traffic/history',
      { params: { start, end, resolution } }
    );
    return response.data.data!;
  }

  async getRealtimeMetrics(): Promise<RealtimeMetrics> {
    const response = await this.client.get<APIResponse<RealtimeMetrics>>(
      '/stats/realtime'
    );
    return response.data.data!;
  }

  // ==================== Attacks ====================

  async getAttacks(
    params?: {
      is_active?: boolean;
      attack_type?: string;
      severity?: string;
      page?: number;
      per_page?: number;
    }
  ): Promise<PaginatedResponse<AttackSummary>> {
    const response = await this.client.get<APIResponse<PaginatedResponse<AttackSummary>>>(
      '/security/attacks',
      { params }
    );
    return response.data.data!;
  }

  async getActiveAttacks(): Promise<Attack[]> {
    const response = await this.client.get<APIResponse<Attack[]>>(
      '/security/attacks/active'
    );
    return response.data.data!;
  }

  async getAttack(attackId: string): Promise<Attack> {
    const response = await this.client.get<APIResponse<Attack>>(
      `/security/attacks/${attackId}`
    );
    return response.data.data!;
  }

  // ==================== IP Lists ====================

  async getBlacklist(
    params?: { search?: string; page?: number; per_page?: number }
  ): Promise<PaginatedResponse<IPListEntry>> {
    const response = await this.client.get<APIResponse<PaginatedResponse<IPListEntry>>>(
      '/security/blacklist',
      { params }
    );
    return response.data.data!;
  }

  async addToBlacklist(
    data: IPListEntryCreate
  ): Promise<IPListEntry> {
    const response = await this.client.post<APIResponse<IPListEntry>>(
      '/security/blacklist',
      data
    );
    return response.data.data!;
  }

  async addBulkToBlacklist(
    data: IPListBulkAdd
  ): Promise<{ added: number; failed: number }> {
    const response = await this.client.post<APIResponse<{ added: number; failed: number }>>(
      '/security/blacklist/bulk',
      data
    );
    return response.data.data!;
  }

  async removeFromBlacklist(ip: string): Promise<void> {
    await this.client.delete('/security/blacklist', { params: { ip } });
  }

  async getWhitelist(
    params?: { search?: string; page?: number; per_page?: number }
  ): Promise<PaginatedResponse<IPListEntry>> {
    const response = await this.client.get<APIResponse<PaginatedResponse<IPListEntry>>>(
      '/security/whitelist',
      { params }
    );
    return response.data.data!;
  }

  async addToWhitelist(
    data: IPListEntryCreate
  ): Promise<IPListEntry> {
    const response = await this.client.post<APIResponse<IPListEntry>>(
      '/security/whitelist',
      data
    );
    return response.data.data!;
  }

  async addBulkToWhitelist(
    data: IPListBulkAdd
  ): Promise<{ added: number; failed: number }> {
    const response = await this.client.post<APIResponse<{ added: number; failed: number }>>(
      '/security/whitelist/bulk',
      data
    );
    return response.data.data!;
  }

  async removeFromWhitelist(ip: string): Promise<void> {
    await this.client.delete('/security/whitelist', { params: { ip } });
  }

  // ==================== Policies ====================

  async getPolicies(
    params?: {
      enabled?: boolean;
      action?: string;
      source?: string;
      page?: number;
      per_page?: number;
    }
  ): Promise<PaginatedResponse<Policy>> {
    const response = await this.client.get<APIResponse<PaginatedResponse<Policy>>>(
      '/policies',
      { params }
    );
    return response.data.data!;
  }

  async getPolicy(policyId: number): Promise<Policy> {
    const response = await this.client.get<APIResponse<Policy>>(
      `/policies/${policyId}`
    );
    return response.data.data!;
  }

  async createPolicy(data: PolicyCreate): Promise<Policy> {
    const response = await this.client.post<APIResponse<Policy>>(
      '/policies',
      data
    );
    return response.data.data!;
  }

  async updatePolicy(policyId: number, data: PolicyUpdate): Promise<Policy> {
    const response = await this.client.put<APIResponse<Policy>>(
      `/policies/${policyId}`,
      data
    );
    return response.data.data!;
  }

  async deletePolicy(policyId: number): Promise<void> {
    await this.client.delete(`/policies/${policyId}`);
  }

  async togglePolicy(policyId: number, enabled: boolean): Promise<Policy> {
    const response = await this.client.patch<APIResponse<Policy>>(
      `/policies/${policyId}`,
      { enabled }
    );
    return response.data.data!;
  }

  // ==================== Configuration ====================

  async getConfig(): Promise<Record<string, unknown>> {
    const response = await this.client.get<APIResponse<Record<string, unknown>>>(
      '/config'
    );
    return response.data.data!;
  }

  async updateConfig(data: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.client.put<APIResponse<Record<string, unknown>>>(
      '/config',
      data
    );
    return response.data.data!;
  }

  // ==================== Investigation ====================

  async investigateIP(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.get<APIResponse<Record<string, unknown>>>(
      `/security/investigate/${ip}`
    );
    return response.data.data!;
  }

  async blockIP(
    ip: string,
    duration_seconds: number,
    reason: string
  ): Promise<void> {
    await this.client.post(`/security/investigate/${ip}/block`, null, {
      params: { duration_seconds, reason },
    });
  }

  async unblockIP(ip: string): Promise<void> {
    await this.client.post(`/security/investigate/${ip}/unblock`);
  }

  // ==================== Reports ====================

  async getReports(
    params?: PaginationParams & { report_type?: string }
  ): Promise<PaginatedResponse<Report>> {
    const response = await this.client.get<APIResponse<PaginatedResponse<Report>>>(
      '/reports',
      { params }
    );
    return response.data.data!;
  }

  async getReport(reportId: string): Promise<Report> {
    const response = await this.client.get<APIResponse<Report>>(
      `/reports/${reportId}`
    );
    return response.data.data!;
  }

  async generateReport(request: ReportRequest): Promise<Report> {
    const response = await this.client.post<APIResponse<Report>>(
      '/reports',
      request
    );
    return response.data.data!;
  }

  async downloadReport(reportId: string): Promise<Blob> {
    const response = await this.client.get(
      `/reports/${reportId}/download`,
      { responseType: 'blob' }
    );
    return response.data;
  }

  async deleteReport(reportId: string): Promise<void> {
    await this.client.delete(`/reports/${reportId}`);
  }

  async getScheduledReports(): Promise<ScheduledReport[]> {
    const response = await this.client.get<APIResponse<ScheduledReport[]>>(
      '/reports/scheduled'
    );
    return response.data.data ?? [];
  }

  // ==================== API Tokens ====================

  async getTokens(): Promise<TokenInfo[]> {
    const response = await this.client.get<APIResponse<TokenInfo[]>>(
      '/security/tokens'
    );
    return response.data.data!;
  }

  async createToken(data: TokenCreate): Promise<Token> {
    const response = await this.client.post<APIResponse<Token>>(
      '/security/tokens',
      data
    );
    return response.data.data!;
  }

  async revokeToken(tokenId: string): Promise<void> {
    await this.client.delete(`/security/tokens/${tokenId}`);
  }

  // ==================== Webhooks ====================

  async getWebhooks(): Promise<Webhook[]> {
    const response = await this.client.get<APIResponse<Webhook[]>>(
      '/security/webhooks'
    );
    return response.data.data!;
  }

  async getWebhook(webhookId: string): Promise<Webhook> {
    const response = await this.client.get<APIResponse<Webhook>>(
      `/security/webhooks/${webhookId}`
    );
    return response.data.data!;
  }

  async createWebhook(data: WebhookCreate): Promise<Webhook> {
    const response = await this.client.post<APIResponse<Webhook>>(
      '/security/webhooks',
      data
    );
    return response.data.data!;
  }

  async updateWebhook(webhookId: string, data: WebhookUpdate): Promise<Webhook> {
    const response = await this.client.put<APIResponse<Webhook>>(
      `/security/webhooks/${webhookId}`,
      data
    );
    return response.data.data!;
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.client.delete(`/security/webhooks/${webhookId}`);
  }

  async testWebhook(webhookId: string): Promise<{ success: boolean; message: string }> {
    const response = await this.client.post<APIResponse<{ success: boolean; message: string }>>(
      `/security/webhooks/${webhookId}/test`
    );
    return response.data.data!;
  }

  // ==================== Protected IPs ====================

  async getProtectedIPs(): Promise<{ ips: Array<{ ip: string; prefix_len: number; description?: string; created_at?: string }> }> {
    const response = await this.client.get<APIResponse<{ ips: Array<{ ip: string; prefix_len: number; description?: string; created_at?: string }> }>>(
      '/security/protected-ips'
    );
    return response.data.data!;
  }

  async addProtectedIP(ip: string, description?: string): Promise<void> {
    await this.client.post('/security/protected-ips', null, {
      params: { ip, description },
    });
  }

  async removeProtectedIP(ip: string): Promise<void> {
    await this.client.delete('/security/protected-ips', {
      params: { ip },
    });
  }

  // ==================== Real-time DPDK Data ====================

  async getRealtimeStats(): Promise<RealtimeStats> {
    const response = await this.client.get('/realtime/stats');
    return response.data;
  }

  async getRealtimeStatsHistory(limit: number = 60): Promise<TrafficHistorySample[]> {
    const response = await this.client.get('/realtime/stats/history', { params: { limit } });
    return response.data;
  }

  async getPortStatsHistory(limit: number = 60): Promise<PortStatsHistorySample[]> {
    const response = await this.client.get<PortStatsHistorySample[]>('/realtime/stats/port-history', { params: { limit } });
    return response.data;
  }

  async getRealtimeTraffic(limit: number = 100): Promise<TrafficResponse> {
    const response = await this.client.get<TrafficResponse>('/realtime/traffic', { params: { limit } });
    return response.data;
  }

  async clearRealtimeTraffic(): Promise<void> {
    await this.client.post('/realtime/traffic/clear');
  }

  async getRealtimeSysmon(): Promise<SysmonResponse> {
    const response = await this.client.get<SysmonResponse>('/realtime/sysmon');
    return response.data;
  }

  async getRealtimeAnomaly(): Promise<AnomalyStatus> {
    const response = await this.client.get('/realtime/anomaly');
    return response.data;
  }

  async getPerIPAnomaly(): Promise<PerIPAnomalyResponse> {
    const response = await this.client.get('/realtime/anomaly/per-ip');
    return response.data;
  }

  /**
   * Get per-IP anomaly data as a dictionary keyed by IP address.
   */
  async getRealtimeAnomalyPerIP(_tenantId?: number): Promise<PerIPAnomalyDict> {
    const response = await this.client.get<PerIPAnomalyResponse>('/realtime/anomaly/per-ip');
    const data = response.data;

    // Transform array to dictionary keyed by IP
    const result: PerIPAnomalyDict = {};
    if (data.per_ip_anomalies && Array.isArray(data.per_ip_anomalies)) {
      for (const entry of data.per_ip_anomalies) {
        if (entry.dst_ip_str) {
          result[entry.dst_ip_str] = entry;
        }
      }
    }
    return result;
  }

  async getPerIPAnomalySummary(): Promise<PerIPAnomalySummary> {
    const response = await this.client.get('/realtime/anomaly/per-ip/summary');
    return response.data;
  }

  async getPerIPStats(): Promise<PerIPStatsResponse> {
    const response = await this.client.get('/realtime/stats/per-ip');
    return response.data;
  }

  async getPerIPStatsSingle(ip: string): Promise<PerIPStatsEntry> {
    const response = await this.client.get(`/realtime/stats/per-ip/${encodeURIComponent(ip)}`);
    return response.data;
  }

  async getDPDKConnectionStatus(): Promise<{ connected: boolean }> {
    const response = await this.client.get('/realtime/connected');
    return response.data;
  }

  // ==================== Rules Engine ====================

  async getRulesWhitelist(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/rules/whitelist');
    return response.data;
  }

  async addRulesWhitelist(ipOrData: string | { ip: string; description?: string; expires_hours?: number; mode?: string }, description?: string, expires_hours?: number, mode?: string): Promise<void> {
    if (typeof ipOrData === 'object') {
      await this.client.post('/rules/whitelist', ipOrData);
    } else {
      await this.client.post('/rules/whitelist', { ip: ipOrData, description, expires_hours, mode });
    }
  }

  async removeRulesWhitelist(ip: string): Promise<void> {
    await this.client.delete(`/rules/whitelist/${encodeURIComponent(ip)}`);
  }

  async clearRulesWhitelist(): Promise<void> {
    await this.client.post('/rules/whitelist/clear');
  }

  async getRulesBlacklist(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/rules/blacklist');
    return response.data;
  }

  async addRulesBlacklist(ipOrData: string | { ip: string; description?: string; expires_hours?: number }, description?: string, expires_hours?: number): Promise<void> {
    if (typeof ipOrData === 'object') {
      await this.client.post('/rules/blacklist', ipOrData);
    } else {
      await this.client.post('/rules/blacklist', { ip: ipOrData, description, expires_hours });
    }
  }

  async removeRulesBlacklist(ip: string): Promise<void> {
    await this.client.delete(`/rules/blacklist/${encodeURIComponent(ip)}`);
  }

  async clearRulesBlacklist(): Promise<void> {
    await this.client.post('/rules/blacklist/clear');
  }

  async getRulesProtected(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/rules/protected');
    return response.data;
  }

  async addRulesProtected(ipOrData: string | { ip: string; description?: string; profile?: string; overrides?: Record<string, unknown> }, description?: string): Promise<void> {
    if (typeof ipOrData === 'object') {
      await this.client.post('/rules/protected', ipOrData);
    } else {
      await this.client.post('/rules/protected', { ip: ipOrData, description });
    }
  }

  async removeRulesProtected(ip: string): Promise<void> {
    // Preserve the '/' for CIDR subnets (e.g. 10.0.5.0/24) so the value matches
    // the backend's {ip:path} route; encode each segment but keep the slash.
    const path = ip.split('/').map(encodeURIComponent).join('/');
    await this.client.delete(`/rules/protected/${path}`);
  }

  async clearRulesProtected(): Promise<void> {
    await this.client.post('/rules/protected/clear');
  }

  async getProfileTemplates(): Promise<{ templates: Array<Record<string, unknown>>; count: number }> {
    const response = await this.client.get('/rules/profiles');
    return response.data;
  }

  async getProtectedProfile(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/rules/protected/${encodeURIComponent(ip)}/profile`);
    return response.data;
  }

  async updateProtectedProfile(ip: string, profileName: string, overrides?: Record<string, unknown>): Promise<void> {
    await this.client.put(`/rules/protected/${encodeURIComponent(ip)}/profile`, overrides || {}, {
      params: { profile_name: profileName }
    });
  }

  async checkIP(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/rules/check/${encodeURIComponent(ip)}`);
    return response.data;
  }

  async syncRules(): Promise<Record<string, unknown>> {
    const response = await this.client.post('/rules/sync');
    return response.data;
  }

  async cleanupExpiredRules(): Promise<Record<string, unknown>> {
    const response = await this.client.post('/rules/cleanup');
    return response.data;
  }

  // Alias for backward compatibility
  async cleanupRules(): Promise<Record<string, unknown>> {
    return this.cleanupExpiredRules();
  }

  async getRulesStats(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/rules/stats');
    return response.data;
  }

  /**
   * Check if an IP is in whitelist, blacklist, or protected IPs.
   */
  async checkRulesIP(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/rules/check/${encodeURIComponent(ip)}`);
    return response.data;
  }

  // ==================== Layer 1 Config ====================

  async getLayer1Config(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/config');
    return response.data;
  }

  async getLayer1ConfigSchema(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/config/schema');
    return response.data;
  }

  async getLayer1ConfigSection(section: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/layer1/config/section/${section}`);
    return response.data;
  }

  async updateLayer1ConfigSection(section: string, data: Record<string, unknown>): Promise<void> {
    await this.client.put(`/layer1/config/section/${section}`, data);
  }

  async updateLayer1ConfigValue(section: string, key: string, value: unknown): Promise<{ applied: boolean }> {
    const res = await this.client.put(`/layer1/config/value/${section}/${key}`, { value });
    return res.data;
  }

  async updateLayer1TopLevel(key: string, value: unknown): Promise<{ applied: boolean }> {
    const res = await this.client.put('/layer1/config/top-level', { key, value });
    return res.data;
  }

  async updateLayer1Config(data: Record<string, unknown>): Promise<void> {
    await this.client.put('/layer1/config', data);
  }

  async resetLayer1Config(): Promise<void> {
    await this.client.post('/layer1/config/reset');
  }

  async reloadLayer1Config(): Promise<void> {
    await this.client.post('/layer1/config/reload');
  }

  // Layer 1 Config History
  async getLayer1ConfigHistory(limit = 20): Promise<{ history: ConfigHistoryEntry[] }> {
    const response = await this.client.get('/layer1/config/history', { params: { limit } });
    return response.data;
  }

  async getLayer1Snapshot(snapshotId: number): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/layer1/config/history/${snapshotId}`);
    return response.data;
  }

  async restoreLayer1Snapshot(snapshotId: number): Promise<void> {
    await this.client.post(`/layer1/config/history/${snapshotId}/restore`);
  }

  // Layer 1 Stages
  async getLayer1Stages(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/stages');
    return response.data;
  }

  async getLayer1StagesByCategory(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/stages/categories');
    return response.data;
  }

  async enableLayer1Stage(stageId: string): Promise<void> {
    await this.client.post(`/layer1/stages/${stageId}/enable`);
  }

  async disableLayer1Stage(stageId: string): Promise<void> {
    await this.client.post(`/layer1/stages/${stageId}/disable`);
  }

  async toggleLayer1Stage(stageId: string): Promise<Record<string, unknown>> {
    const response = await this.client.post(`/layer1/stages/${stageId}/toggle`);
    return response.data;
  }

  // Layer 1 Geo-blocking
  async getGeoBlocking(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/geo');
    return response.data;
  }

  async setGeoBlockingEnabled(enabled: boolean): Promise<void> {
    await this.client.post('/layer1/geo/enabled', { enabled });
  }

  async setGeoBlockingMode(mode: 'blacklist' | 'whitelist'): Promise<void> {
    await this.client.post('/layer1/geo/mode', { mode });
  }

  async setGeoBlockUnknown(enabled: boolean): Promise<void> {
    await this.client.post('/layer1/geo/block-unknown', { enabled });
  }

  async getGeoCountries(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/geo/countries');
    return response.data;
  }

  async setGeoCountries(countries: string[]): Promise<void> {
    await this.client.post('/layer1/geo/countries', { countries });
  }

  async addGeoCountry(country: string): Promise<void> {
    await this.client.post('/layer1/geo/countries/add', { country });
  }

  async removeGeoCountry(country: string): Promise<void> {
    await this.client.post('/layer1/geo/countries/remove', { country });
  }

  async clearGeoCountries(): Promise<void> {
    await this.client.post('/layer1/geo/countries/clear');
  }

  // Layer 1 Signatures
  async getSignatures(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/signatures');
    return response.data;
  }

  async setSignaturesEnabled(enabled: boolean): Promise<void> {
    await this.client.post('/layer1/signatures/enabled', { enabled });
  }

  async setSignatureEnabled(sigId: number, enabled: boolean): Promise<void> {
    await this.client.post(`/layer1/signatures/${sigId}/enabled`, { enabled });
  }

  async setSignatureCategoryEnabled(category: string, enabled: boolean): Promise<void> {
    await this.client.post(`/layer1/signatures/category/${category}/enabled`, { enabled });
  }

  // Layer 1 Protocols
  async getProtocols(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer1/protocols');
    return response.data;
  }

  async setProtocolsEnabled(enabled: boolean): Promise<void> {
    await this.client.post('/layer1/protocols/enabled', { enabled });
  }

  async setProtocolsAction(action: 'drop' | 'accept' | 'rate_limit'): Promise<void> {
    await this.client.post('/layer1/protocols/action', { action });
  }

  async addProtocol(protocol: number | string): Promise<void> {
    await this.client.post('/layer1/protocols/add', { protocol });
  }

  async removeProtocol(protocol: number | string): Promise<void> {
    await this.client.post('/layer1/protocols/remove', { protocol });
  }

  // ==================== Layer 3 ML ====================

  async getLayer3Summary(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer3/summary');
    return response.data;
  }

  async getLayer3Signatures(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer3/signatures');
    return response.data;
  }

  async getLayer3Attackers(limit?: number): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer3/attackers', { params: { limit } });
    return response.data;
  }

  async generateLayer3Signatures(): Promise<{ generated: number }> {
    const response = await this.client.post('/layer3/signatures/generate');
    return response.data;
  }

  async addLayer3Signature(sig: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.client.post('/layer3/signatures', sig);
    return response.data;
  }

  async deleteLayer3Signature(sigId: number): Promise<void> {
    await this.client.delete(`/layer3/signatures/${sigId}`);
  }

  async enableLayer3Signature(sigId: number): Promise<void> {
    await this.client.post(`/layer3/signatures/${sigId}/enable`);
  }

  async disableLayer3Signature(sigId: number): Promise<void> {
    await this.client.post(`/layer3/signatures/${sigId}/disable`);
  }

  // ==================== Layer 2 Learning Status ====================

  async getLearningStatus(): Promise<{
    state: string;
    phase: number;
    progress_pct: number;
    tier1_ready: boolean;
    tier2_ready: boolean;
    tier3_ready: boolean;
    tier1_progress: number;
    tier2_progress: number;
    tier3_progress: number;
    tier1_eta_sec: number;
    tier2_eta_sec: number;
    tier3_eta_sec: number;
    tier2_slots_ready: number;
    tier3_slots_ready: number;
    baseline_age_sec: number;
    eta_mature_seconds: number;
    total_updates: number;
    mitigation_active: boolean;
    learning_action: number;
    suppressed_count: number;
    trust_multiplier: number;
  }> {
    const response = await this.client.get('/layer2/learning-status');
    return response.data;
  }

  // ==================== Layer 2 Config ====================

  async getLayer2Config(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer2/config');
    return response.data;
  }

  async updateLayer2Config(data: Record<string, unknown>): Promise<void> {
    await this.client.put('/layer2/config', data);
  }

  async updateLayer2ConfigValue(key: string, value: unknown): Promise<{ applied: boolean }> {
    const res = await this.client.put(`/layer2/config/value/${key}`, { value });
    return res.data;
  }

  async resetLayer2Config(): Promise<void> {
    await this.client.post('/layer2/config/reset');
  }

  async reloadLayer2Config(): Promise<void> {
    await this.client.post('/layer2/config/reload');
  }

  // Layer 2 Feature Selection
  async getLayer2Features(): Promise<{
    features: Array<{
      index: number; name: string; group: string; enabled: boolean;
      quality: { cv: number; range_ratio: number; zero_dominant: boolean; score: number | null; auto_disabled: boolean };
    }>;
    auto_select: { enabled: boolean; min_quality: number; min_samples: number };
  }> {
    const response = await this.client.get('/layer2/features');
    return response.data;
  }

  async setLayer2FeaturesEnabled(featureEnabled: boolean[]): Promise<void> {
    await this.client.put('/layer2/features/enabled', { feature_enabled: featureEnabled });
  }

  async setLayer2AutoSelect(enabled: boolean, minQuality?: number): Promise<void> {
    await this.client.put('/layer2/features/auto-select', {
      enabled,
      ...(minQuality !== undefined && { min_quality: minQuality }),
    });
  }

  // Layer 2 Adaptive Thresholds
  async getAdaptiveConfig(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/layer2/adaptive');
    return response.data;
  }

  async updateAdaptiveConfig(data: Record<string, unknown>): Promise<void> {
    await this.client.put('/layer2/adaptive', data);
  }

  async setAdaptiveEnabled(enabled: boolean): Promise<void> {
    await this.client.post('/layer2/adaptive/enabled', { enabled });
  }

  // Alias for backward compatibility
  async getLayer2Adaptive(): Promise<Record<string, unknown>> {
    return this.getAdaptiveConfig();
  }

  // ==================== Layer 2 Profiles ====================

  async getLayer2Profiles(): Promise<{ profiles: { id: string; name: string; description: string; source: string }[] }> {
    const response = await this.client.get('/layer2/profiles');
    return response.data;
  }

  async applyLayer2Profile(name: string): Promise<void> {
    await this.client.post('/layer2/profiles/apply', { name });
  }

  async exportLayer2Profile(name: string, description: string): Promise<{ status: string; id: string; name: string }> {
    const response = await this.client.post('/layer2/profiles/export', { name, description });
    return response.data;
  }

  // ==================== Baseline Management ====================

  async saveLayer2Baselines(): Promise<{ status: string }> {
    const response = await this.client.post('/layer2/baselines/save');
    return response.data;
  }

  async resetLayer2Baselines(): Promise<{ status: string }> {
    const response = await this.client.post('/layer2/baselines/reset');
    return response.data;
  }

  async forceLayer2Mature(): Promise<{ status: string }> {
    const response = await this.client.post('/layer2/baselines/force-mature');
    return response.data;
  }

  async getLayer2BaselinesData(feature: string = 'packets_per_sec', ip?: string): Promise<import('../types').BaselinesData> {
    const params: Record<string, string> = { feature };
    if (ip) params.ip = ip;
    const response = await this.client.get('/layer2/baselines/data', { params });
    return response.data;
  }

  async getLayer2BaselinesSummary(): Promise<import('../types').BaselinesSummary> {
    const response = await this.client.get('/layer2/baselines/summary');
    return response.data;
  }

  // ==================== System Operations ====================

  async systemReset(options?: {
    clear_per_ip_data?: boolean;
    clear_attacks?: boolean;
    clear_traffic?: boolean;
    reset_configs?: boolean;
    specific_ips?: string[];
    reason?: string;
  }): Promise<{
    timestamp: string;
    per_ip_data: { status: string; message?: string; cleared_ips?: string[] };
    attacks: { status: string; message?: string };
    traffic: { status: string; message?: string };
    configs?: { status: string; message?: string };
    overall_status: string;
  }> {
    const response = await this.client.post('/system/reset', {
      clear_per_ip_data: options?.clear_per_ip_data ?? true,
      clear_attacks: options?.clear_attacks ?? true,
      clear_traffic: options?.clear_traffic ?? true,
      reset_configs: options?.reset_configs ?? true,
      specific_ips: options?.specific_ips,
      reason: options?.reason,
    });
    return response.data;
  }

  async resetIPData(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.delete(`/system/reset/ip/${encodeURIComponent(ip)}`);
    return response.data;
  }

  async getSystemHealth(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/system/health');
    return response.data;
  }

  async getSystemStatus(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/system/status');
    return response.data;
  }

  async systemReload(options?: {
    layer1?: boolean;
    layer2?: boolean;
    notify_datapath?: boolean;
  }): Promise<Record<string, unknown>> {
    const response = await this.client.post('/system/reload', options ?? {});
    return response.data;
  }

  // ==================== Per-IP Layer 2 Config ====================

  async getPerIPL2Config(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.get(`/layer2/per-ip-config/${encodeURIComponent(ip)}`);
    return response.data;
  }

  async updatePerIPL2Config(ip: string, data: Record<string, unknown>): Promise<Record<string, unknown>> {
    const response = await this.client.put(`/layer2/per-ip-config/${encodeURIComponent(ip)}`, data);
    return response.data;
  }

  async deletePerIPL2Config(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.delete(`/layer2/per-ip-config/${encodeURIComponent(ip)}`);
    return response.data;
  }

  // ==================== Per-IP Feature Selection ====================

  async getPerIPFeatures(ip: string): Promise<{
    success: boolean;
    ip_address: string;
    source: 'per_ip' | 'global';
    features: Array<{ index: number; name: string; group: string; enabled: boolean; weight: number }>;
  }> {
    const response = await this.client.get(`/layer2/per-ip-config/${encodeURIComponent(ip)}/features`);
    return response.data;
  }

  async setPerIPFeatures(ip: string, featureEnabled: boolean[]): Promise<{
    success: boolean;
    ip_address: string;
    features: Array<{ index: number; name: string; enabled: boolean; weight: number }>;
    datapath_notified: boolean;
  }> {
    const response = await this.client.put(
      `/layer2/per-ip-config/${encodeURIComponent(ip)}/features`,
      { feature_enabled: featureEnabled }
    );
    return response.data;
  }

  async resetPerIPFeatures(ip: string): Promise<Record<string, unknown>> {
    const response = await this.client.delete(
      `/layer2/per-ip-config/${encodeURIComponent(ip)}/features`
    );
    return response.data;
  }

  // ==================== Organization Settings ====================

  async getOrgSettings(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/org/settings');
    return response.data;
  }

  async updateOrganization(data: { name: string; contact_email: string; alert_webhook: string }): Promise<void> {
    await this.client.put('/org/settings/organization', data);
  }

  async getProtectedNetworks(): Promise<{ networks: Array<{ network: string; description: string }> }> {
    const response = await this.client.get('/org/settings/networks');
    return response.data;
  }

  async updateProtectedNetworks(networks: Array<{ network: string; description: string }>): Promise<void> {
    await this.client.put('/org/settings/networks', networks);
  }

  async getAlertingConfig(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/org/settings/alerting');
    return response.data;
  }

  async updateAlertingConfig(data: Record<string, unknown>): Promise<void> {
    await this.client.put('/org/settings/alerting', data);
  }

  async getTelemetryConfig(): Promise<Record<string, unknown>> {
    const response = await this.client.get('/org/settings/telemetry');
    return response.data;
  }

  async updatePrometheusConfig(data: { enabled: boolean; port: number; path: string }): Promise<void> {
    await this.client.put('/org/settings/telemetry/prometheus', data);
  }

  async updateLoggingConfig(data: { level: string; path: string; max_size_mb: number; max_files: number }): Promise<void> {
    await this.client.put('/org/settings/telemetry/logging', data);
  }

  async getForwardingConfig(): Promise<{
    enabled: boolean;
    bind_ip: string;
    dest_ip: string;
    dest_port: number;
    protocol: string;
    streams: { stats: boolean; traffic: boolean; anomaly: boolean; per_ip_features: boolean; sysmon: boolean };
    interval_ms: number;
  }> {
    const response = await this.client.get('/org/settings/telemetry/forwarding');
    return response.data;
  }

  async updateForwardingConfig(data: {
    enabled: boolean;
    bind_ip: string;
    dest_ip: string;
    dest_port: number;
    protocol: string;
    streams: { stats: boolean; traffic: boolean; anomaly: boolean; per_ip_features: boolean; sysmon: boolean };
    interval_ms: number;
  }): Promise<void> {
    await this.client.put('/org/settings/telemetry/forwarding', data);
  }

  async getNetworkInterfaces(): Promise<{ interfaces: Array<{ name: string; ip: string }> }> {
    const response = await this.client.get('/org/settings/interfaces');
    return response.data;
  }

  async getForwardingStatus(): Promise<{
    running: boolean;
    enabled: boolean;
    connected_to_remote: boolean;
    connected_to_stats: boolean;
    connected_to_traffic: boolean;
    packets_sent: number;
    bytes_sent: number;
    send_errors: number;
    last_send_ago_sec: number | null;
    last_error: string;
    dest_ip?: string;
    dest_port?: number;
    protocol?: string;
  }> {
    const response = await this.client.get('/org/settings/telemetry/forwarding/status');
    return response.data;
  }

  async getTelemetryFeatures(params: {
    dst_ip?: string;
    since_minutes?: number;
    limit?: number;
    label?: string;
  }): Promise<{
    count: number;
    samples: Array<{
      id: number;
      timestamp: number;
      dst_ip: string;
      feat_values: string;
      baseline_means: string | null;
      baseline_stds: string | null;
      baselines_all: string | null;
      anomaly_active: number;
      label: string | null;
      attack_type: string | null;
    }>;
  }> {
    const response = await this.client.get('/telemetry/features', { params });
    return response.data;
  }
}

export const api = new ApiService();
export default api;

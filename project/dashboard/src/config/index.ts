/**
 * Application Configuration
 *
 * Centralized configuration for the dashboard application.
 * All environment-dependent values should be configured here.
 */

// Environment detection
export const IS_DEV = import.meta.env?.DEV === true;
export const MODE = import.meta.env?.MODE || 'production';
export const IS_PROD = import.meta.env?.PROD === true || MODE === 'production';

// API Configuration
const envApiUrl = import.meta.env?.VITE_API_URL;

/**
 * API base URL.
 * Uses environment variable in production, fallback for development.
 */
export const API_BASE_URL = envApiUrl || '/api/v2';

/**
 * WebSocket URL for real-time updates.
 * Automatically derives from API_BASE_URL.
 * Handles both absolute URLs (http://...) and relative paths (/api/v2).
 */
export const WS_BASE_URL = (() => {
  if (/^https?:\/\//.test(API_BASE_URL)) {
    return API_BASE_URL.replace(/^http/, 'ws');
  }
  // Relative URL -- construct absolute WebSocket URL from current window location
  const proto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss' : 'ws';
  const host = typeof window !== 'undefined' ? window.location.host : 'localhost';
  return `${proto}://${host}${API_BASE_URL}`;
})();

// Authentication Configuration
export const AUTH_CONFIG = {
  /** Use httpOnly cookies for token storage (more secure than localStorage) */
  useCookieAuth: true,
  /** Session timeout in seconds (should match backend JWT_EXPIRY_HOURS) */
  sessionTimeoutSeconds: 24 * 60 * 60, // 24 hours
  /** Time before expiry to show warning (in seconds) */
  sessionWarningSeconds: 5 * 60, // 5 minutes
} as const;

// Polling intervals (in milliseconds)
export const POLLING_INTERVALS = {
  /** Real-time stats polling */
  realtimeStats: 2000,
  /** Standard metrics polling */
  metrics: 5000,
  /** Attack updates polling */
  attacks: 10000,
  /** Configuration refresh */
  config: 60000,
  /** ML model updates */
  mlUpdates: 30000,
} as const;

// UI Configuration
export const UI_CONFIG = {
  /** Default page size for paginated lists */
  defaultPageSize: 25,
  /** Maximum items to show in dropdown selectors */
  maxDropdownItems: 100,
  /** Debounce delay for search inputs (ms) */
  searchDebounceMs: 300,
  /** Toast notification duration (ms) */
  toastDuration: 4000,
  /** Chart animation duration (ms) */
  chartAnimationMs: 750,
} as const;

// Feature flags
export const FEATURES = {
  /** Enable real-time WebSocket updates */
  realtimeUpdates: true,
  /** Enable ML-based detection features */
  mlDetection: true,
  /** Enable analytics (admin only) */
  analytics: true,
  /** Enable debug mode features */
  debugMode: IS_DEV,
} as const;

// Export all as a single config object for convenience
export const config = {
  IS_DEV,
  IS_PROD,
  MODE,
  API_BASE_URL,
  WS_BASE_URL,
  AUTH: AUTH_CONFIG,
  POLLING: POLLING_INTERVALS,
  UI: UI_CONFIG,
  FEATURES,
} as const;

export default config;

/**
 * Main Application Component
 *
 * Features:
 * - Code splitting with React.lazy for improved initial load time
 * - Error boundaries for crash protection
 * - Cookie-based authentication
 */

import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'react-hot-toast';
import { Layout } from './components/Layout';
import { PageErrorBoundary } from './components/ErrorBoundary';
import { useAuthStore } from './store';
import { API_BASE_URL, UI_CONFIG } from './config';

// ==================== Code Splitting ====================
// Lazy load pages for better initial load performance
// Each page is loaded on-demand when the route is accessed

const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const TrafficPage = lazy(() => import('./pages/Traffic').then(m => ({ default: m.TrafficPage })));
const ConfigPage = lazy(() => import('./pages/Config').then(m => ({ default: m.ConfigPage })));
const ReportsPage = lazy(() => import('./pages/Reports').then(m => ({ default: m.ReportsPage })));
const SettingsPage = lazy(() => import('./pages/Settings').then(m => ({ default: m.SettingsPage })));
const OrgSettingsPage = lazy(() => import('./pages/OrgSettings').then(m => ({ default: m.OrgSettingsPage })));
const SystemPage = lazy(() => import('./pages/System'));
const RulesPage = lazy(() => import('./pages/Rules'));
const ProtocolValidationPage = lazy(() => import('./pages/ProtocolValidation'));
const GeoBlockingPage = lazy(() => import('./pages/GeoBlocking'));
const AssetsPage = lazy(() => import('./pages/Assets').then(m => ({ default: m.AssetsPage })));
const AssetDetailPage = lazy(() => import('./pages/AssetDetail').then(m => ({ default: m.AssetDetailPage })));
const BaselinesPage = lazy(() => import('./pages/Baselines').then(m => ({ default: m.BaselinesPage })));
const RunningConfigPage = lazy(() => import('./pages/RunningConfig').then(m => ({ default: m.RunningConfigPage })));
const FeaturesPage = lazy(() => import('./pages/Features').then(m => ({ default: m.FeaturesPage })));
const FeatureHistoryPage = lazy(() => import('./pages/FeatureHistory').then(m => ({ default: m.FeatureHistoryPage })));
const AttackHistoryPage = lazy(() => import('./pages/AttackHistory').then(m => ({ default: m.AttackHistoryPage })));
const LoginPageComponent = lazy(() => import('./pages/Login').then(m => ({ default: m.LoginPage })));
const TenantsPage = lazy(() => import('./pages/Tenants').then(m => ({ default: m.TenantsPage })));
const CrossTenantAnalyticsPage = lazy(() => import('./pages/CrossTenantAnalytics').then(m => ({ default: m.CrossTenantAnalyticsPage })));
const ThreatCenterPage = lazy(() => import('./pages/ThreatCenter').then(m => ({ default: m.ThreatCenter })));
const PoliciesPage = lazy(() => import('./pages/Policies').then(m => ({ default: m.PoliciesPage })));

// Loading fallback component for lazy-loaded pages
const PageLoader = () => (
  <div className="flex items-center justify-center h-64">
    <div className="flex flex-col items-center gap-2">
      <div className="w-8 h-8 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin" />
      <span className="text-gray-400 text-sm">Loading...</span>
    </div>
  </div>
);

// Wrap each page with error boundary and suspense for isolation
const withPageBoundary = (Component: React.LazyExoticComponent<React.ComponentType>) => (
  <PageErrorBoundary>
    <Suspense fallback={<PageLoader />}>
      <Component />
    </Suspense>
  </PageErrorBoundary>
);

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10000,
      retry: 1,
    },
  },
});

// Protected route wrapper with auth event listener and cookie verification
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const navigate = useNavigate();
  const { isAuthenticated, setUser, logout: clearUser } = useAuthStore();
  const [isVerifying, setIsVerifying] = React.useState(!isAuthenticated);

  // Listen for unauthorized events from API service
  React.useEffect(() => {
    const handleUnauthorized = () => {
      clearUser();
      navigate('/login', { replace: true });
    };

    window.addEventListener('auth:unauthorized', handleUnauthorized);
    return () => window.removeEventListener('auth:unauthorized', handleUnauthorized);
  }, [navigate, clearUser]);

  // Verify authentication status with backend on mount
  // This handles the case where we have an httpOnly cookie but no local state
  React.useEffect(() => {
    if (!isAuthenticated) {
      const verifyAuth = async () => {
        try {
          const response = await fetch(`${API_BASE_URL}/auth/me`, {
            credentials: 'include', // Send httpOnly cookies
          });

          if (response.ok) {
            const data = await response.json();
            if (data.success && data.data) {
              // We have a valid session via cookie
              setUser({
                user_id: data.data.user_id,
                permissions: data.data.permissions || [],
                is_admin: data.data.is_admin || false,
                auth_type: 'cookie',
              });
            }
          }
        } catch {
          // Auth check failed, stay on login
        } finally {
          setIsVerifying(false);
        }
      };

      verifyAuth();
    }
  }, [isAuthenticated, setUser]);

  // Branded splash screen while verifying cookie auth
  if (isVerifying) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-slate-50 dark:bg-slate-950 relative overflow-hidden">
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute -top-40 -right-40 w-96 h-96 bg-brand-500/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-40 -left-40 w-96 h-96 bg-emerald-500/8 rounded-full blur-3xl" />
        </div>
        <div className="relative z-10 flex flex-col items-center gap-4">
          <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-700 flex items-center justify-center shadow-lg shadow-brand-500/20 animate-pulse">
            <svg className="h-8 w-8 text-white" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z" />
            </svg>
          </div>
          <div className="text-center">
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">ShieldNet</h1>
            <p className="text-sm text-slate-500 mt-1">Initializing protection...</p>
          </div>
          <div className="w-48 h-1 bg-slate-200 dark:bg-slate-800 rounded-full overflow-hidden mt-2">
            <div className="h-full bg-gradient-to-r from-brand-500 to-brand-400 rounded-full animate-shimmer" style={{ width: '60%' }} />
          </div>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-slate-950"><div className="text-slate-400">Loading...</div></div>}>
              <LoginPageComponent />
            </Suspense>
          } />

          <Route
            path="/"
            element={
              <ProtectedRoute>
                <Layout />
              </ProtectedRoute>
            }
          >
            {/* Core pages */}
            <Route index element={withPageBoundary(Dashboard)} />
            <Route path="traffic" element={withPageBoundary(TrafficPage)} />
            <Route path="rules" element={withPageBoundary(RulesPage)} />
            <Route path="geo" element={withPageBoundary(GeoBlockingPage)} />
            <Route path="validation" element={withPageBoundary(ProtocolValidationPage)} />
            <Route path="config" element={withPageBoundary(ConfigPage)} />
            <Route path="running-config" element={withPageBoundary(RunningConfigPage)} />
            <Route path="baselines" element={withPageBoundary(BaselinesPage)} />
            <Route path="features" element={withPageBoundary(FeaturesPage)} />
            <Route path="features/history" element={withPageBoundary(FeatureHistoryPage)} />
            <Route path="system" element={withPageBoundary(SystemPage)} />
            <Route path="attack-history" element={withPageBoundary(AttackHistoryPage)} />
            <Route path="reports" element={withPageBoundary(ReportsPage)} />
            <Route path="assets" element={withPageBoundary(AssetsPage)} />
            <Route path="assets/:ip" element={withPageBoundary(AssetDetailPage)} />

            {/* Admin pages */}
            <Route path="settings" element={withPageBoundary(SettingsPage)} />
            <Route path="settings/org" element={withPageBoundary(OrgSettingsPage)} />

            {/* Multi-tenant pages */}
            <Route path="tenants" element={withPageBoundary(TenantsPage)} />
            <Route path="tenants/analytics" element={withPageBoundary(CrossTenantAnalyticsPage)} />
            <Route path="threats" element={withPageBoundary(ThreatCenterPage)} />
            <Route path="policies" element={withPageBoundary(PoliciesPage)} />

            {/* Redirects for old routes - backwards compatibility */}
            <Route path="security" element={<Navigate to="/threats" replace />} />
            <Route path="attacks" element={<Navigate to="/attack-history" replace />} />
            <Route path="ip-lists" element={<Navigate to="/rules" replace />} />
            <Route path="config/detection" element={<Navigate to="/config" replace />} />
            <Route path="config/geo" element={<Navigate to="/geo" replace />} />
            <Route path="network" element={<Navigate to="/traffic" replace />} />
            <Route path="alerts" element={<Navigate to="/system" replace />} />

            {/* Consolidated navigation aliases */}
            <Route path="overview" element={<Navigate to="/" replace />} />
            <Route path="rules/geo" element={<Navigate to="/geo" replace />} />
            <Route path="rules/validation" element={<Navigate to="/validation" replace />} />
            <Route path="rules/config" element={<Navigate to="/config" replace />} />
            <Route path="rules/running" element={<Navigate to="/running-config" replace />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>

      <Toaster
        position="top-right"
        toastOptions={{
          duration: UI_CONFIG.toastDuration,
          style: {
            background: '#1F2937',
            color: '#F9FAFB',
          },
        }}
      />
    </QueryClientProvider>
  );
}

export default App;

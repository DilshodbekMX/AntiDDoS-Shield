/**
 * Login Page -- Enterprise authentication screen
 *
 * Split-panel design with animated branding on left,
 * clean login form on right. Fully responsive.
 */

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQueryClient } from '@tanstack/react-query';
import { ShieldCheckIcon, LockClosedIcon, UserIcon, EyeIcon, EyeSlashIcon } from '@heroicons/react/24/outline';
import { useAuthStore } from '../store';
import { API_BASE_URL } from '../config';
import { validateLoginCredentials, getFieldError, ValidationError } from '../utils/validation';

export function LoginPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { setUser } = useAuthStore();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [fieldErrors, setFieldErrors] = useState<ValidationError[]>([]);
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [touched, setTouched] = useState<{ username: boolean; password: boolean }>({
    username: false,
    password: false,
  });

  const handleBlur = (field: 'username' | 'password') => {
    setTouched((prev) => ({ ...prev, [field]: true }));
    const result = validateLoginCredentials(username, password);
    setFieldErrors(result.errors);
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setFieldErrors([]);

    const validation = validateLoginCredentials(username, password);
    if (!validation.valid) {
      setFieldErrors(validation.errors);
      setTouched({ username: true, password: true });
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(`${API_BASE_URL}/auth/login?use_cookie=true`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ username, password }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.detail || 'Login failed');
      }

      // Clear stale cached data from previous session/user
      queryClient.clear();

      setUser({
        user_id: data.user,
        permissions: data.permissions,
        is_admin: data.permissions.includes('*'),
        auth_type: 'cookie',
      });

      navigate('/', { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const usernameError = touched.username ? getFieldError(fieldErrors, 'Username') : undefined;
  const passwordError = touched.password ? getFieldError(fieldErrors, 'Password') : undefined;

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950">
      {/* Left Panel -- Branding (hidden on mobile) */}
      <div className="hidden lg:flex lg:w-[55%] relative overflow-hidden bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 flex-col justify-between p-12">
        {/* Animated background elements */}
        <div className="absolute inset-0">
          <div className="absolute top-0 left-0 w-full h-full bg-[radial-gradient(ellipse_at_top_left,rgba(14,165,233,0.15),transparent_50%)]" />
          <div className="absolute bottom-0 right-0 w-full h-full bg-[radial-gradient(ellipse_at_bottom_right,rgba(14,165,233,0.1),transparent_50%)]" />
          {/* Grid pattern */}
          <div className="absolute inset-0 bg-[linear-gradient(rgba(148,163,184,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(148,163,184,0.03)_1px,transparent_1px)] bg-[size:64px_64px]" />
          {/* Floating orbs */}
          <div className="absolute top-1/4 left-1/4 w-64 h-64 bg-brand-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '4s' }} />
          <div className="absolute bottom-1/3 right-1/4 w-48 h-48 bg-cyan-500/8 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '6s', animationDelay: '2s' }} />
        </div>

        {/* Top content */}
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-2">
            <div className="h-10 w-10 rounded-xl bg-brand-500/20 border border-brand-500/30 flex items-center justify-center backdrop-blur-sm">
              <ShieldCheckIcon className="h-6 w-6 text-brand-400" />
            </div>
            <span className="text-lg font-semibold text-white/90 tracking-tight">ShieldNet</span>
          </div>
        </div>

        {/* Center content */}
        <div className="relative z-10 max-w-lg">
          <h2 className="text-4xl font-bold text-white leading-tight mb-6">
            Enterprise-Grade<br />
            <span className="text-brand-400">DDoS Protection</span>
          </h2>
          <p className="text-lg text-slate-400 leading-relaxed mb-10">
            Multi-layer defense powered by DPDK, real-time ML analysis, and adaptive threat mitigation across layers 1 through 5.
          </p>

          {/* Feature highlights */}
          <div className="grid grid-cols-2 gap-4">
            {[
              { label: 'Packet Processing', value: '100M+ pps' },
              { label: 'Detection Latency', value: '<1ms' },
              { label: 'ML Models Active', value: '5 layers' },
              { label: 'Uptime SLA', value: '99.999%' },
            ].map((stat) => (
              <div key={stat.label} className="bg-white/5 backdrop-blur-sm rounded-xl border border-white/10 p-4">
                <p className="text-2xl font-bold text-white">{stat.value}</p>
                <p className="text-sm text-slate-400 mt-0.5">{stat.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Bottom content */}
        <div className="relative z-10 flex items-center gap-6 text-sm text-slate-500">
          <span>DPDK Accelerated</span>
          <span className="w-1 h-1 rounded-full bg-slate-600" />
          <span>ML-Driven Detection</span>
          <span className="w-1 h-1 rounded-full bg-slate-600" />
          <span>Real-Time Analytics</span>
        </div>
      </div>

      {/* Right Panel -- Login Form */}
      <div className="flex-1 flex flex-col items-center justify-center p-6 sm:p-8 relative">
        {/* Subtle background for light mode */}
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(14,165,233,0.04),transparent_70%)] dark:bg-[radial-gradient(ellipse_at_center,rgba(14,165,233,0.06),transparent_70%)]" />

        <div className="relative z-10 w-full max-w-sm">
          {/* Mobile-only branding */}
          <div className="lg:hidden flex flex-col items-center mb-8">
            <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-brand-500 to-brand-600 flex items-center justify-center mb-4 shadow-lg shadow-brand-500/25">
              <ShieldCheckIcon className="h-8 w-8 text-white" />
            </div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white">ShieldNet</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">Enterprise DDoS Protection</p>
          </div>

          {/* Welcome text */}
          <div className="mb-8">
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">
              Welcome back
            </h1>
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              Sign in to access the ShieldNet control plane
            </p>
          </div>

          {/* Form */}
          <form onSubmit={handleLogin} className="space-y-5">
            {error && (
              <div className="flex items-start gap-3 rounded-xl bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/20 px-4 py-3">
                <svg className="h-5 w-5 text-red-500 dark:text-red-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.28 7.22a.75.75 0 00-1.06 1.06L8.94 10l-1.72 1.72a.75.75 0 101.06 1.06L10 11.06l1.72 1.72a.75.75 0 101.06-1.06L11.06 10l1.72-1.72a.75.75 0 00-1.06-1.06L10 8.94 8.28 7.22z" clipRule="evenodd" />
                </svg>
                <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
              </div>
            )}

            {/* Username field */}
            <div>
              <label htmlFor="username" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Username
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5">
                  <UserIcon className="h-5 w-5 text-slate-400 dark:text-slate-500" />
                </div>
                <input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onBlur={() => handleBlur('username')}
                  className={`w-full rounded-xl border bg-white dark:bg-slate-800/50 pl-11 pr-4 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-0 ${
                    usernameError
                      ? 'border-red-300 dark:border-red-500/50 focus:border-red-500 focus:ring-red-500/20'
                      : 'border-slate-300 dark:border-slate-700 focus:border-brand-500 focus:ring-brand-500/20'
                  }`}
                  placeholder="Enter your username"
                  autoComplete="username"
                  aria-invalid={!!usernameError}
                  aria-describedby={usernameError ? 'username-error' : undefined}
                />
              </div>
              {usernameError && (
                <p id="username-error" className="mt-1.5 text-xs text-red-500 dark:text-red-400">
                  {usernameError}
                </p>
              )}
            </div>

            {/* Password field */}
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">
                Password
              </label>
              <div className="relative">
                <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3.5">
                  <LockClosedIcon className="h-5 w-5 text-slate-400 dark:text-slate-500" />
                </div>
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onBlur={() => handleBlur('password')}
                  className={`w-full rounded-xl border bg-white dark:bg-slate-800/50 pl-11 pr-12 py-3 text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-0 ${
                    passwordError
                      ? 'border-red-300 dark:border-red-500/50 focus:border-red-500 focus:ring-red-500/20'
                      : 'border-slate-300 dark:border-slate-700 focus:border-brand-500 focus:ring-brand-500/20'
                  }`}
                  placeholder="Enter your password"
                  autoComplete="current-password"
                  aria-invalid={!!passwordError}
                  aria-describedby={passwordError ? 'password-error' : undefined}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute inset-y-0 right-0 flex items-center pr-3.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 transition-colors"
                  tabIndex={-1}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                >
                  {showPassword ? (
                    <EyeSlashIcon className="h-5 w-5" />
                  ) : (
                    <EyeIcon className="h-5 w-5" />
                  )}
                </button>
              </div>
              {passwordError && (
                <p id="password-error" className="mt-1.5 text-xs text-red-500 dark:text-red-400">
                  {passwordError}
                </p>
              )}
            </div>

            {/* Submit */}
            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-xl bg-brand-500 hover:bg-brand-600 active:bg-brand-700 disabled:opacity-60 disabled:cursor-not-allowed text-white font-semibold py-3 text-sm transition-all duration-200 shadow-lg shadow-brand-500/25 hover:shadow-brand-500/40 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2 dark:focus:ring-offset-slate-950"
            >
              {loading ? (
                <span className="flex items-center justify-center gap-2">
                  <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg>
                  Signing in...
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </form>

          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-slate-200 dark:border-slate-800">
            <p className="text-center text-xs text-slate-400 dark:text-slate-500">
              Protected by ShieldNet v2.0
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;

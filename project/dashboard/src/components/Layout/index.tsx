/**
 * Main Layout Component (Enterprise Edition)
 *
 * Responsive layout with collapsible sidebar, modern header,
 * and smooth transitions.
 */

import { useState, useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { Breadcrumbs } from './Breadcrumbs';
import { useUIStore } from '../../store';
import { clsx } from 'clsx';

export function Layout() {
  const { sidebarOpen, darkMode } = useUIStore();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false);
  }, [location.pathname]);

  return (
    <div className={clsx(darkMode && 'dark')}>
      <div className="min-h-screen bg-slate-50 dark:bg-slate-950">
        {/* Mobile backdrop */}
        {mobileMenuOpen && (
          <div
            className="fixed inset-0 z-40 bg-slate-900/60 dark:bg-slate-900/60 backdrop-blur-sm lg:hidden"
            onClick={() => setMobileMenuOpen(false)}
          />
        )}

        {/* Sidebar -- always visible on desktop, overlay on mobile */}
        <div className={clsx(
          'lg:block',
          mobileMenuOpen ? 'block' : 'hidden'
        )}>
          <Sidebar />
        </div>

        {/* Main Content Area */}
        <div
          className={clsx(
            'flex flex-col min-h-screen transition-all duration-300 ease-in-out',
            // Desktop: respect sidebar width
            sidebarOpen ? 'lg:pl-64' : 'lg:pl-16',
            // Mobile: no padding (sidebar is overlay)
            'pl-0'
          )}
        >
          {/* Header */}
          <Header onMobileMenuToggle={() => setMobileMenuOpen(!mobileMenuOpen)} />

          {/* Page Content */}
          <main className="flex-1 p-4 lg:p-6">
            <div className="mx-auto max-w-7xl">
              <Breadcrumbs />
              <div key={location.pathname} className="animate-fade-in">
                <Outlet />
              </div>
            </div>
          </main>

          {/* Footer */}
          <footer className="border-t border-slate-200 dark:border-slate-800 py-4 px-4 lg:px-6">
            <div className="mx-auto max-w-7xl flex items-center justify-between text-xs text-slate-500">
              <span>ShieldNet v2.0 (research prototype)</span>
              <span className="hidden sm:inline">
                DPDK packet I/O &bull; Statistical detection &bull; Throughput not measured
              </span>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default Layout;

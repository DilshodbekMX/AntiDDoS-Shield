/**
 * Header Component (Enterprise Edition)
 *
 * Modern header with search, notifications, dark mode toggle,
 * and attack status indicators.
 */

import { Fragment, useState, useRef } from 'react';
import { Menu, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
  BellIcon,
  MoonIcon,
  SunIcon,
  ArrowRightOnRectangleIcon,
  Cog6ToothIcon,
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  CommandLineIcon,
  CheckCircleIcon,
  InformationCircleIcon,
  Bars3Icon,
} from '@heroicons/react/24/outline';
import { useAuthStore, useUIStore, useNotificationStore } from '../../store';

// ============================================================================
// Types
// ============================================================================

interface SearchResult {
  id: string;
  type: 'page' | 'action' | 'ip';
  label: string;
  href?: string;
  shortcut?: string;
}

// ============================================================================
// Constants
// ============================================================================

const quickNavigation: SearchResult[] = [
  { id: 'dashboard',      type: 'page', label: 'Dashboard',           href: '/',               shortcut: 'G D' },
  { id: 'traffic',        type: 'page', label: 'Traffic Analysis',    href: '/traffic',        shortcut: 'G T' },
  { id: 'features',       type: 'page', label: 'Feature Monitor',     href: '/features',       shortcut: 'G F' },
  { id: 'assets',         type: 'page', label: 'Protected Assets',    href: '/assets',         shortcut: 'G A' },
  { id: 'attack-history', type: 'page', label: 'Attack History',      href: '/attack-history', shortcut: 'G H' },
  { id: 'rules',          type: 'page', label: 'Access Rules',        href: '/rules',          shortcut: 'G R' },
  { id: 'geo',            type: 'page', label: 'Geo-Blocking',        href: '/geo',            shortcut: 'G G' },
  { id: 'config',         type: 'page', label: 'Configuration',       href: '/config',         shortcut: 'G C' },
  { id: 'system',         type: 'page', label: 'Health & Alerts',     href: '/system',         shortcut: 'G S' },
  { id: 'reports',        type: 'page', label: 'Reports',             href: '/reports',        shortcut: 'G E' },
];

// ============================================================================
// Main Component
// ============================================================================

export function Header({ onMobileMenuToggle }: { onMobileMenuToggle?: () => void }) {
  const { user, logout } = useAuthStore();
  const { darkMode, toggleDarkMode } = useUIStore();
  const { notifications, unreadCount, markAllAsRead, markAsRead } = useNotificationStore();

  const [searchQuery, setSearchQuery] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const handleLogout = () => {
    logout();
    window.location.href = '/login';
  };

  // Filter search results
  const filteredResults = searchQuery
    ? quickNavigation.filter((item) =>
        item.label.toLowerCase().includes(searchQuery.toLowerCase())
      )
    : quickNavigation;

  // Keyboard navigation for search
  const handleSearchKeyDown = (e: React.KeyboardEvent) => {
    if (!searchOpen) return;
    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        setSelectedIndex((i) => Math.min(i + 1, filteredResults.length - 1));
        break;
      case 'ArrowUp':
        e.preventDefault();
        setSelectedIndex((i) => Math.max(i - 1, 0));
        break;
      case 'Enter':
        e.preventDefault();
        if (filteredResults[selectedIndex]?.href) {
          window.location.href = filteredResults[selectedIndex].href!;
        }
        break;
      case 'Escape':
        e.preventDefault();
        setSearchOpen(false);
        searchInputRef.current?.blur();
        break;
    }
  };

  // Get notification icon based on type
  const getNotificationIcon = (type: string) => {
    switch (type) {
      case 'error':
        return <ExclamationTriangleIcon className="h-4 w-4 text-red-400" />;
      case 'warning':
        return <ExclamationTriangleIcon className="h-4 w-4 text-orange-400" />;
      case 'success':
        return <CheckCircleIcon className="h-4 w-4 text-emerald-400" />;
      default:
        return <InformationCircleIcon className="h-4 w-4 text-brand-400" />;
    }
  };

  return (
    <header className="sticky top-0 z-40 flex h-16 shrink-0 items-center gap-x-4 border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-900/95 backdrop-blur-sm px-4 lg:px-6">
      {/* Mobile menu button */}
      {onMobileMenuToggle && (
        <button
          onClick={onMobileMenuToggle}
          className="lg:hidden p-2 -ml-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
          aria-label="Toggle navigation menu"
        >
          <Bars3Icon className="h-6 w-6" />
        </button>
      )}

      {/* Search */}
      <div className="flex-1 max-w-xl">
        <div className="relative">
          <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-500" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search or jump to... (Ctrl+K)"
            className="w-full pl-10 pr-20 py-2 bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-white placeholder-slate-400 dark:placeholder-slate-500 focus:border-brand-500 focus:ring-1 focus:ring-brand-500 transition-colors"
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setSelectedIndex(0); }}
            onFocus={() => setSearchOpen(true)}
            onBlur={() => setTimeout(() => setSearchOpen(false), 200)}
            onKeyDown={handleSearchKeyDown}
          />
          <kbd className="absolute right-3 top-1/2 -translate-y-1/2 hidden sm:inline-flex items-center gap-1 px-2 py-0.5 bg-slate-200 dark:bg-slate-700 rounded text-xs text-slate-500 dark:text-slate-400">
            <CommandLineIcon className="h-3 w-3" />K
          </kbd>

          {/* Search Results Dropdown */}
          {searchOpen && (
            <div className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg shadow-xl overflow-hidden">
              <div className="p-2 border-b border-slate-200 dark:border-slate-700">
                <p className="text-xs text-slate-500 font-medium uppercase tracking-wider px-2">
                  Quick Navigation
                </p>
              </div>
              <div className="max-h-64 overflow-y-auto">
                {filteredResults.map((result, idx) => (
                  <a
                    key={result.id}
                    href={result.href}
                    className={clsx(
                      'flex items-center justify-between px-4 py-2.5 transition-colors',
                      idx === selectedIndex ? 'bg-slate-100 dark:bg-slate-700' : 'hover:bg-slate-100 dark:hover:bg-slate-700'
                    )}
                    onMouseEnter={() => setSelectedIndex(idx)}
                  >
                    <span className="text-sm text-slate-700 dark:text-slate-300">{result.label}</span>
                    {result.shortcut && (
                      <kbd className="text-xs text-slate-500 bg-slate-100 dark:bg-slate-900 px-1.5 py-0.5 rounded">
                        {result.shortcut}
                      </kbd>
                    )}
                  </a>
                ))}
                {filteredResults.length === 0 && (
                  <div className="px-4 py-8 text-center text-sm text-slate-500">
                    No results found
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right Section */}
      <div className="flex items-center gap-x-4">
        {/* Dark Mode Toggle */}
        <button
          type="button"
          className="p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors"
          onClick={toggleDarkMode}
          aria-label={darkMode ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          <span className="sr-only">Toggle dark mode</span>
          {darkMode ? (
            <SunIcon className="h-5 w-5" aria-hidden="true" />
          ) : (
            <MoonIcon className="h-5 w-5" aria-hidden="true" />
          )}
        </button>

        {/* Notifications */}
        <Menu as="div" className="relative">
          <Menu.Button className="relative p-2 text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" aria-label="View notifications">
            <span className="sr-only">View notifications</span>
            <BellIcon className="h-5 w-5" aria-hidden="true" />
            {unreadCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 flex h-4 w-4 items-center justify-center rounded-full bg-red-500 text-2xs font-bold text-white ring-2 ring-white dark:ring-slate-900">
                {unreadCount > 9 ? '9+' : unreadCount}
              </span>
            )}
          </Menu.Button>
          <Transition
            as={Fragment}
            enter="transition ease-out duration-100"
            enterFrom="transform opacity-0 scale-95"
            enterTo="transform opacity-100 scale-100"
            leave="transition ease-in duration-75"
            leaveFrom="transform opacity-100 scale-100"
            leaveTo="transform opacity-0 scale-95"
          >
            <Menu.Items className="absolute right-0 z-10 mt-2 w-[calc(100vw-2rem)] sm:w-80 origin-top-right rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-xl focus:outline-none overflow-hidden">
              <div className="flex items-center justify-between px-4 py-3 border-b border-slate-200 dark:border-slate-700">
                <span className="text-sm font-semibold text-slate-900 dark:text-white">Notifications</span>
                {unreadCount > 0 && (
                  <button
                    onClick={markAllAsRead}
                    className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                  >
                    Mark all as read
                  </button>
                )}
              </div>
              <div className="max-h-80 overflow-y-auto">
                {notifications.length === 0 ? (
                  <div className="px-4 py-8 text-center">
                    <BellIcon className="h-8 w-8 mx-auto text-slate-400 dark:text-slate-600 mb-2" />
                    <p className="text-sm text-slate-500">No notifications</p>
                  </div>
                ) : (
                  notifications.slice(0, 10).map((notification) => (
                    <Menu.Item key={notification.id}>
                      {({ active }) => (
                        <div
                          onClick={() => !notification.read && markAsRead(notification.id)}
                          className={clsx(
                            'px-4 py-3 cursor-pointer border-l-2 transition-colors',
                            active ? 'bg-slate-100 dark:bg-slate-700/50' : '',
                            !notification.read
                              ? 'border-l-brand-500 bg-brand-500/5'
                              : 'border-l-transparent'
                          )}
                        >
                          <div className="flex items-start gap-3">
                            <div
                              className={clsx(
                                'p-1.5 rounded-lg',
                                notification.type === 'error'
                                  ? 'bg-red-500/20'
                                  : notification.type === 'warning'
                                    ? 'bg-orange-500/20'
                                    : notification.type === 'success'
                                      ? 'bg-emerald-500/20'
                                      : 'bg-brand-500/20'
                              )}
                            >
                              {getNotificationIcon(notification.type)}
                            </div>
                            <div className="flex-1 min-w-0">
                              <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
                                {notification.title}
                              </p>
                              {notification.message && (
                                <p className="text-xs text-slate-500 dark:text-slate-400 truncate mt-0.5">
                                  {notification.message}
                                </p>
                              )}
                              <p className="text-2xs text-slate-500 mt-1">
                                {new Date(notification.timestamp).toLocaleString()}
                              </p>
                            </div>
                          </div>
                        </div>
                      )}
                    </Menu.Item>
                  ))
                )}
              </div>
            </Menu.Items>
          </Transition>
        </Menu>

        {/* Separator */}
        <div className="hidden lg:block h-6 w-px bg-slate-200 dark:bg-slate-700" aria-hidden="true" />

        {/* Profile Dropdown */}
        <Menu as="div" className="relative">
          <Menu.Button className="flex items-center gap-3 p-1.5 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg transition-colors" aria-label="User menu">
            <div className="h-8 w-8 rounded-full bg-gradient-to-br from-brand-500 to-purple-600 flex items-center justify-center">
              <span className="text-sm font-bold text-white">
                {(user?.user_id || 'U').charAt(0).toUpperCase()}
              </span>
            </div>
            <div className="hidden lg:block text-left">
              <p className="text-sm font-medium text-slate-900 dark:text-white">
                {user?.user_id || 'User'}
              </p>
              <p className="text-2xs text-slate-500">Administrator</p>

            </div>
          </Menu.Button>
          <Transition
            as={Fragment}
            enter="transition ease-out duration-100"
            enterFrom="transform opacity-0 scale-95"
            enterTo="transform opacity-100 scale-100"
            leave="transition ease-in duration-75"
            leaveFrom="transform opacity-100 scale-100"
            leaveTo="transform opacity-0 scale-95"
          >
            <Menu.Items className="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-xl focus:outline-none overflow-hidden">
              <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
                <p className="text-sm font-medium text-slate-900 dark:text-white">{user?.user_id || 'User'}</p>
                <p className="text-xs text-slate-500">admin@shieldnet.io</p>
              </div>
              <div className="py-1">
                <Menu.Item>
                  {({ active }) => (
                    <a
                      href="/settings"
                      className={clsx(
                        'flex items-center gap-3 px-4 py-2 text-sm transition-colors',
                        active ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white' : 'text-slate-600 dark:text-slate-300'
                      )}
                    >
                      <Cog6ToothIcon className="h-5 w-5 text-slate-400" />
                      Settings
                    </a>
                  )}
                </Menu.Item>
                <Menu.Item>
                  {({ active }) => (
                    <button
                      onClick={handleLogout}
                      className={clsx(
                        'flex items-center gap-3 w-full px-4 py-2 text-sm transition-colors',
                        active ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white' : 'text-slate-600 dark:text-slate-300'
                      )}
                    >
                      <ArrowRightOnRectangleIcon className="h-5 w-5 text-slate-400" />
                      Sign out
                    </button>
                  )}
                </Menu.Item>
              </div>
            </Menu.Items>
          </Transition>
        </Menu>
      </div>
    </header>
  );
}

export default Header;

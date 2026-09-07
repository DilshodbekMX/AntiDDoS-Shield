/**
 * Global State Management with Zustand
 */

import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { User } from '../types';

// ==================== Auth Store ====================

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  setUser: (user: User | null) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isAuthenticated: false,
      setUser: (user) => set({ user, isAuthenticated: !!user }),
      logout: () => set({ user: null, isAuthenticated: false }),
    }),
    {
      name: 'auth-storage',
    }
  )
);

// ==================== UI Store ====================

interface UIState {
  sidebarOpen: boolean;
  darkMode: boolean;
  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  toggleDarkMode: () => void;
  setDarkMode: (dark: boolean) => void;
}

export const useUIStore = create<UIState>()(
  persist(
    (set) => ({
      sidebarOpen: true,
      darkMode: false,
      toggleSidebar: () => set((state) => ({ sidebarOpen: !state.sidebarOpen })),
      setSidebarOpen: (open) => set({ sidebarOpen: open }),
      toggleDarkMode: () => set((state) => ({ darkMode: !state.darkMode })),
      setDarkMode: (dark) => set({ darkMode: dark }),
    }),
    {
      name: 'ui-storage',
    }
  )
);

// ==================== Notification Store ====================

export interface Notification {
  id: string;
  type: 'info' | 'success' | 'warning' | 'error';
  title: string;
  message?: string;
  timestamp: Date;
  read: boolean;
}

interface NotificationState {
  notifications: Notification[];
  unreadCount: number;
  addNotification: (notification: Omit<Notification, 'id' | 'timestamp' | 'read'>) => void;
  markAsRead: (id: string) => void;
  markAllAsRead: () => void;
  removeNotification: (id: string) => void;
  clearAll: () => void;
}

export const useNotificationStore = create<NotificationState>()((set) => ({
  notifications: [],
  unreadCount: 0,
  addNotification: (notification) =>
    set((state) => {
      const newNotification: Notification = {
        ...notification,
        id: Math.random().toString(36).substring(7),
        timestamp: new Date(),
        read: false,
      };
      return {
        notifications: [newNotification, ...state.notifications].slice(0, 100),
        unreadCount: state.unreadCount + 1,
      };
    }),
  markAsRead: (id) =>
    set((state) => ({
      notifications: state.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      ),
      unreadCount: Math.max(0, state.unreadCount - 1),
    })),
  markAllAsRead: () =>
    set((state) => ({
      notifications: state.notifications.map((n) => ({ ...n, read: true })),
      unreadCount: 0,
    })),
  removeNotification: (id) =>
    set((state) => {
      const notification = state.notifications.find((n) => n.id === id);
      return {
        notifications: state.notifications.filter((n) => n.id !== id),
        unreadCount: notification?.read ? state.unreadCount : state.unreadCount - 1,
      };
    }),
  clearAll: () => set({ notifications: [], unreadCount: 0 }),
}));

// ==================== IP Scope Store ====================

export { useIPScopeStore } from './ipScopeStore';

// ==================== Baseline Tier Store ====================

export { useBaselineTierStore } from './baselineTierStore';
export type { TierId } from './baselineTierStore';

// ==================== Time Window Store ====================

export { useTimeWindowStore, TIME_WINDOW_PRESETS } from './timeWindowStore';

// ==================== View Mode Store ====================

export { useViewModeStore } from './viewModeStore';
export type { ViewMode } from './viewModeStore';

// ==================== Timezone Store ====================

export { useTimezoneStore, TIMEZONE_OPTIONS } from './timezoneStore';
export type { TimezoneOption } from './timezoneStore';

// ==================== Tenant Store ====================

export { useTenantStore } from './tenantStore';

// ==================== Stats Store ====================

export { useStatsStore } from './statsStore';

/**
 * Form Controls - Shared UI Component Library
 *
 * Accessible, animated form components built on HeadlessUI:
 * - Toggle: Accessible switch with optimistic visual updates
 * - NumberInput: Styled number field
 * - SelectInput: Styled dropdown
 * - SectionCard: Card wrapper with optional animated collapse
 * - FieldRow: Label + description + control layout
 * - InfoBanner: Contextual info/warning messages
 * - Modal: Accessible dialog with animated transitions
 */

import { Fragment, useState, useEffect, useCallback } from 'react';
import { Switch, Dialog, Transition } from '@headlessui/react';
import { clsx } from 'clsx';
import {
  ExclamationTriangleIcon,
  InformationCircleIcon,
  XMarkIcon,
  ChevronDownIcon,
} from '@heroicons/react/24/outline';

// ==================== Toggle ====================

export interface ToggleProps {
  enabled: boolean;
  onChange: (value: boolean) => void | Promise<void>;
  size?: 'sm' | 'md';
  label?: string;
  disabled?: boolean;
}

/**
 * Accessible toggle switch with optimistic visual updates.
 * Uses HeadlessUI Switch for proper ARIA attributes, keyboard support,
 * and focus management. Visually updates immediately on click;
 * rolls back if onChange throws. Syncs from parent props via useEffect.
 */
export function Toggle({ enabled, onChange, size = 'md', label, disabled }: ToggleProps) {
  const [local, setLocal] = useState(enabled);
  useEffect(() => { setLocal(enabled); }, [enabled]);

  const handle = useCallback(async (value: boolean) => {
    setLocal(value);
    try { await onChange(value); } catch { setLocal(!value); }
  }, [onChange]);

  return (
    <Switch
      checked={local}
      onChange={handle}
      disabled={disabled}
      className={clsx(
        'relative inline-flex shrink-0 cursor-pointer rounded-full transition-colors duration-200',
        'focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-500 focus-visible:ring-offset-2 dark:focus-visible:ring-offset-slate-900',
        size === 'sm' ? 'h-5 w-9' : 'h-6 w-11',
        local ? 'bg-green-600' : 'bg-slate-300 dark:bg-slate-600',
        disabled && 'opacity-50 cursor-not-allowed'
      )}
    >
      {label && <span className="sr-only">{label}</span>}
      <span
        aria-hidden="true"
        className={clsx(
          'pointer-events-none inline-block transform rounded-full bg-white shadow-sm ring-0 transition-transform duration-200',
          size === 'sm' ? 'h-3 w-3' : 'h-4 w-4',
          local ? (size === 'sm' ? 'translate-x-5' : 'translate-x-6') : 'translate-x-1'
        )}
      />
    </Switch>
  );
}

// ==================== NumberInput ====================

export interface NumberInputProps {
  value: number | undefined;
  onChange: (value: number) => void;
  step?: number;
  min?: number;
  max?: number;
  className?: string;
  placeholder?: string;
}

export function NumberInput({ value, onChange, step, min, max, className, placeholder }: NumberInputProps) {
  return (
    <input
      type="number"
      step={step}
      min={min}
      max={max}
      value={value ?? ''}
      placeholder={placeholder}
      onChange={(e) => {
        const v = step && step < 1 ? parseFloat(e.target.value) : parseInt(e.target.value);
        if (!isNaN(v)) onChange(v);
      }}
      className={clsx(
        'rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm',
        'dark:border-slate-600 dark:bg-slate-800 dark:text-white',
        'focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 focus:outline-none',
        'transition-colors duration-150',
        className || 'w-32'
      )}
    />
  );
}

// ==================== SelectInput ====================

export interface SelectOption {
  value: string | number;
  label: string;
}

export interface SelectInputProps {
  value: string | number;
  onChange: (value: string) => void;
  options: SelectOption[];
  className?: string;
}

export function SelectInput({ value, onChange, options, className }: SelectInputProps) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className={clsx(
        'rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm',
        'dark:border-slate-600 dark:bg-slate-800 dark:text-white',
        'focus:border-brand-500 focus:ring-2 focus:ring-brand-500/20 focus:outline-none',
        'transition-colors duration-150',
        className
      )}
    >
      {options.map(opt => (
        <option key={opt.value} value={opt.value}>{opt.label}</option>
      ))}
    </select>
  );
}

// ==================== SectionCard ====================

export interface SectionCardProps {
  title: string;
  description?: string;
  badge?: React.ReactNode;
  children: React.ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
}

/**
 * Card wrapper with optional animated collapse.
 * Uses CSS grid-template-rows transition for smooth height animation.
 * Keyboard accessible when collapsible (Enter/Space to toggle).
 */
export function SectionCard({ title, description, badge, children, collapsible, defaultOpen = false }: SectionCardProps) {
  const [isOpen, setIsOpen] = useState(!collapsible || defaultOpen);

  return (
    <div className="card overflow-hidden">
      <div
        className={clsx(
          'card-header',
          collapsible && 'cursor-pointer select-none hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors'
        )}
        onClick={collapsible ? () => setIsOpen(o => !o) : undefined}
        role={collapsible ? 'button' : undefined}
        aria-expanded={collapsible ? isOpen : undefined}
        tabIndex={collapsible ? 0 : undefined}
        onKeyDown={collapsible ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setIsOpen(o => !o); } } : undefined}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {collapsible && (
              <ChevronDownIcon
                className={clsx(
                  'h-4 w-4 text-slate-500 dark:text-slate-400 transition-transform duration-200',
                  !isOpen && '-rotate-90'
                )}
              />
            )}
            <h3 className="text-base font-semibold text-slate-900 dark:text-white">{title}</h3>
          </div>
          {description && (
            <p className={clsx('mt-0.5 text-sm text-slate-500 dark:text-slate-400', collapsible && 'ml-6')}>
              {description}
            </p>
          )}
        </div>
        {badge && <div className="flex-shrink-0 ml-4">{badge}</div>}
      </div>
      {collapsible ? (
        <div className={clsx(
          'grid transition-[grid-template-rows] duration-200 ease-out',
          isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'
        )}>
          <div className="overflow-hidden">
            <div className="card-body">{children}</div>
          </div>
        </div>
      ) : (
        <div className="card-body">{children}</div>
      )}
    </div>
  );
}

// ==================== FieldRow ====================

export interface FieldRowProps {
  label: string;
  description?: string;
  children: React.ReactNode;
}

export function FieldRow({ label, description, children }: FieldRowProps) {
  return (
    <div className="flex items-center justify-between py-3 first:pt-0 last:pb-0">
      <div className="flex-1 min-w-0 mr-4">
        <div className="text-sm font-medium text-slate-900 dark:text-white">{label}</div>
        {description && (
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">{description}</div>
        )}
      </div>
      <div className="flex-shrink-0">{children}</div>
    </div>
  );
}

// ==================== InfoBanner ====================

export interface InfoBannerProps {
  children: React.ReactNode;
  variant?: 'info' | 'warning';
}

export function InfoBanner({ children, variant = 'info' }: InfoBannerProps) {
  const Icon = variant === 'warning' ? ExclamationTriangleIcon : InformationCircleIcon;
  return (
    <div className={clsx(
      'flex items-start gap-3 rounded-xl border p-4',
      variant === 'warning'
        ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-800 text-amber-800 dark:text-amber-200'
        : 'bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200'
    )}>
      <Icon className="h-5 w-5 flex-shrink-0 mt-0.5" />
      <div className="text-sm">{children}</div>
    </div>
  );
}

// ==================== Modal ====================

export interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  size?: 'sm' | 'md' | 'lg';
  children: React.ReactNode;
}

const modalSizes = { sm: 'max-w-sm', md: 'max-w-md', lg: 'max-w-lg' };

/**
 * Accessible modal dialog with animated transitions.
 * Uses HeadlessUI Dialog for focus trapping, Escape key handling,
 * click-outside-to-close, and proper ARIA attributes.
 */
export function Modal({ open, onClose, title, size = 'md', children }: ModalProps) {
  return (
    <Transition appear show={open} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-200"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-150"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-slate-900/40 dark:bg-slate-900/60 backdrop-blur-sm" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-200"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-150"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className={clsx(
                'w-full transform rounded-2xl bg-white dark:bg-slate-900 shadow-2xl transition-all',
                'border border-slate-200 dark:border-slate-800',
                modalSizes[size]
              )}>
                <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-800">
                  <Dialog.Title className="text-lg font-semibold text-slate-900 dark:text-white">
                    {title}
                  </Dialog.Title>
                  <button
                    onClick={onClose}
                    className="rounded-lg p-1.5 text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 transition-colors"
                    aria-label="Close"
                  >
                    <XMarkIcon className="h-5 w-5" />
                  </button>
                </div>
                <div className="p-6">{children}</div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  );
}

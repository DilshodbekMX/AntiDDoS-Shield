/**
 * ViewModeSelector -- toggle between EWMA baseline and detection metric views.
 */

import { clsx } from 'clsx';
import { useViewModeStore, type ViewMode } from '../../store';

const MODES: { id: ViewMode; label: string; description: string }[] = [
  { id: 'ewma', label: 'EWMA', description: 'Feature values + baseline overlays' },
  { id: 'detection', label: 'Detection', description: 'Z-score, CUSUM, JSD metrics' },
];

export function ViewModeSelector() {
  const { viewMode, setViewMode } = useViewModeStore();

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-slate-500 mr-1">View:</span>
      {MODES.map((mode) => (
        <button
          key={mode.id}
          onClick={() => setViewMode(mode.id)}
          title={mode.description}
          className={clsx(
            'px-2.5 py-0.5 rounded text-xs font-medium transition-all duration-150',
            'border focus:outline-none',
            viewMode === mode.id
              ? mode.id === 'detection'
                ? 'border-amber-500 bg-amber-500/20 text-amber-300'
                : 'border-brand-500 bg-brand-500/20 text-brand-300'
              : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
          )}
        >
          {mode.label}
        </button>
      ))}
    </div>
  );
}

/**
 * HistoryTimeRangeSelector -- chip buttons for historical time range selection.
 *
 * Presets: 1h, 6h, 24h, 7d. Used by Feature History page.
 */

import { useState } from 'react';
import { clsx } from 'clsx';

const PRESETS = [
  { label: '1h', minutes: 60 },
  { label: '6h', minutes: 360 },
  { label: '24h', minutes: 1440 },
  { label: '7d', minutes: 10080 },
] as const;

interface Props {
  value: number;
  onChange: (minutes: number) => void;
}

export function HistoryTimeRangeSelector({ value, onChange }: Props) {
  const [customValue, setCustomValue] = useState('');
  const [showCustom, setShowCustom] = useState(false);

  const isPreset = PRESETS.some((p) => p.minutes === value);

  const handleCustomSubmit = () => {
    const val = parseInt(customValue, 10);
    if (val && val >= 1 && val <= 20160) {
      onChange(val);
      setShowCustom(false);
      setCustomValue('');
    }
  };

  const fmtLabel = (min: number): string => {
    if (min < 60) return `${min}m`;
    if (min < 1440) return `${min / 60}h`;
    return `${min / 1440}d`;
  };

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-slate-500 mr-1">Range:</span>
      {PRESETS.map((p) => (
        <button
          key={p.minutes}
          onClick={() => { onChange(p.minutes); setShowCustom(false); }}
          className={clsx(
            'px-2 py-0.5 rounded text-xs font-medium transition-all duration-150',
            'border focus:outline-none',
            value === p.minutes
              ? 'border-brand-500 bg-brand-500/20 text-brand-300'
              : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
          )}
        >
          {p.label}
        </button>
      ))}
      {showCustom ? (
        <div className="flex items-center gap-1">
          <input
            type="number"
            min={1}
            max={20160}
            value={customValue}
            onChange={(e) => setCustomValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCustomSubmit()}
            onBlur={() => { if (!customValue) setShowCustom(false); }}
            placeholder="min"
            autoFocus
            className={clsx(
              'w-16 px-1.5 py-0.5 rounded text-xs font-mono',
              'bg-slate-100 dark:bg-slate-800 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white',
              'focus:outline-none focus:border-brand-500'
            )}
          />
          <button
            onClick={handleCustomSubmit}
            className="text-2xs text-brand-400 hover:text-brand-300"
          >
            OK
          </button>
        </div>
      ) : (
        <button
          onClick={() => setShowCustom(true)}
          className={clsx(
            'px-2 py-0.5 rounded text-xs font-medium transition-all duration-150',
            'border focus:outline-none',
            !isPreset
              ? 'border-brand-500 bg-brand-500/20 text-brand-300'
              : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
          )}
        >
          {!isPreset ? fmtLabel(value) : 'Custom'}
        </button>
      )}
    </div>
  );
}

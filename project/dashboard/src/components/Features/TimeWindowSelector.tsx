/**
 * TimeWindowSelector -- preset chips + custom input for chart time window.
 *
 * Controls how many seconds of history are shown on all Feature Monitor charts.
 * Polling is 2s, so 60s = 30 data points on the X axis.
 */

import { useState } from 'react';
import { clsx } from 'clsx';
import { useTimeWindowStore, TIME_WINDOW_PRESETS } from '../../store';

/** Format seconds as a short label */
function fmtLabel(sec: number): string {
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${sec / 60}m`;
  return `${sec / 3600}h`;
}

export function TimeWindowSelector() {
  const { windowSeconds, setWindowSeconds } = useTimeWindowStore();
  const [customValue, setCustomValue] = useState('');
  const [showCustom, setShowCustom] = useState(false);

  const isPreset = (TIME_WINDOW_PRESETS as readonly number[]).includes(windowSeconds);

  const handleCustomSubmit = () => {
    const val = parseInt(customValue, 10);
    if (val && val >= 10 && val <= 600) {
      setWindowSeconds(val);
      setShowCustom(false);
      setCustomValue('');
    }
  };

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-slate-500 mr-1">Window:</span>
      {TIME_WINDOW_PRESETS.map((sec) => (
        <button
          key={sec}
          onClick={() => { setWindowSeconds(sec); setShowCustom(false); }}
          className={clsx(
            'px-2 py-0.5 rounded text-xs font-medium transition-all duration-150',
            'border focus:outline-none',
            windowSeconds === sec
              ? 'border-brand-500 bg-brand-500/20 text-brand-300'
              : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
          )}
        >
          {fmtLabel(sec)}
        </button>
      ))}
      {/* Custom toggle / input */}
      {showCustom ? (
        <div className="flex items-center gap-1">
          <input
            type="number"
            min={10}
            max={600}
            value={customValue}
            onChange={(e) => setCustomValue(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleCustomSubmit()}
            onBlur={() => { if (!customValue) setShowCustom(false); }}
            placeholder="sec"
            autoFocus
            className={clsx(
              'w-14 px-1.5 py-0.5 rounded text-xs font-mono',
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
          {!isPreset ? fmtLabel(windowSeconds) : 'Custom'}
        </button>
      )}
    </div>
  );
}

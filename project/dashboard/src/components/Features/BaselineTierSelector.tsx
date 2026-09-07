/**
 * BaselineTierSelector -- toggle chips for C Layer 2 EWMA baseline tiers.
 *
 * Each tier is a small colored chip that can be clicked to show/hide
 * that baseline line on all Feature Monitor charts.
 */

import { clsx } from 'clsx';
import { useBaselineTierStore, TierId } from '../../store';
import { BASELINE_TIERS } from '../../hooks/useFeatureHistory';

export function BaselineTierSelector() {
  const { enabledTiers, toggleTier, enableAll, disableAll } = useBaselineTierStore();

  const allEnabled = enabledTiers.length === BASELINE_TIERS.length;

  return (
    <div className="flex items-center gap-1.5">
      <span className="text-xs text-slate-500 mr-1">Baselines:</span>
      {BASELINE_TIERS.map((tier) => {
        const tierId = tier.id as TierId;
        const enabled = enabledTiers.includes(tierId);
        return (
          <button
            key={tier.id}
            onClick={() => toggleTier(tierId)}
            className={clsx(
              'px-2 py-0.5 rounded text-xs font-medium transition-all duration-150',
              'border focus:outline-none focus:ring-1 focus:ring-offset-1 focus:ring-offset-white dark:focus:ring-offset-slate-900',
              enabled
                ? 'border-transparent text-slate-900 dark:text-white shadow-sm'
                : 'border-slate-300 dark:border-slate-600 text-slate-500 bg-slate-100 dark:bg-slate-800/50 hover:bg-slate-200 dark:hover:bg-slate-700/50'
            )}
            style={
              enabled
                ? { backgroundColor: tier.color, color: '#000' }
                : undefined
            }
            title={`${enabled ? 'Hide' : 'Show'} ${tier.label} baseline`}
          >
            {tier.label}
          </button>
        );
      })}
      {/* All / None shortcuts */}
      <span className="text-slate-700 mx-0.5">|</span>
      <button
        onClick={allEnabled ? disableAll : enableAll}
        className="text-2xs text-slate-500 hover:text-slate-700 dark:hover:text-slate-300 transition-colors"
      >
        {allEnabled ? 'None' : 'All'}
      </button>
    </div>
  );
}

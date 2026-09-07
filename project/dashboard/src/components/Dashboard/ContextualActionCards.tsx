/**
 * ContextualActionCards -- Data-driven quick action cards
 *
 * Replaces static navigation links with live metric badges
 * that change appearance based on current system state.
 */

import { Link } from 'react-router-dom';
import {
  ComputerDesktopIcon,
  WrenchScrewdriverIcon,
  CpuChipIcon,
  ChartBarSquareIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';

interface ContextualActionCardsProps {
  anomalousIpCount: number;
  totalProtectedIps: number;
  detectionCount: number;
  dropRate: number;
}

interface ActionCard {
  to: string;
  icon: React.ComponentType<React.SVGProps<SVGSVGElement>>;
  title: string;
  subtitle: string;
  accent: 'red' | 'blue' | 'emerald' | 'amber' | 'brand';
  badge?: number | string;
}

const accentStyles = {
  red: {
    iconBg: 'bg-red-500/10 group-hover:bg-red-500/20',
    iconColor: 'text-red-400',
    badgeBg: 'bg-red-500',
  },
  blue: {
    iconBg: 'bg-blue-500/10 group-hover:bg-blue-500/20',
    iconColor: 'text-blue-400',
    badgeBg: 'bg-blue-500',
  },
  emerald: {
    iconBg: 'bg-emerald-500/10 group-hover:bg-emerald-500/20',
    iconColor: 'text-emerald-400',
    badgeBg: 'bg-emerald-500',
  },
  amber: {
    iconBg: 'bg-amber-500/10 group-hover:bg-amber-500/20',
    iconColor: 'text-amber-400',
    badgeBg: 'bg-amber-500',
  },
  brand: {
    iconBg: 'bg-brand-500/10 group-hover:bg-brand-500/20',
    iconColor: 'text-brand-400',
    badgeBg: 'bg-brand-500',
  },
};

export function ContextualActionCards({
  anomalousIpCount,
  totalProtectedIps,
  detectionCount,
  dropRate,
}: ContextualActionCardsProps) {
  const cards: ActionCard[] = [
    {
      to: '/assets',
      icon: ComputerDesktopIcon,
      title: anomalousIpCount > 0
        ? `${anomalousIpCount} IP${anomalousIpCount !== 1 ? 's' : ''} Under Attack`
        : 'Protected Assets',
      subtitle: anomalousIpCount > 0
        ? 'View & Respond'
        : `${totalProtectedIps} assets monitored`,
      accent: anomalousIpCount > 0 ? 'red' : 'blue',
      badge: anomalousIpCount > 0 ? anomalousIpCount : totalProtectedIps || undefined,
    },
    {
      to: '/rules',
      icon: WrenchScrewdriverIcon,
      title: 'Access Rules',
      subtitle: 'Manage IP lists',
      accent: 'brand',
    },
    {
      to: '/system',
      icon: CpuChipIcon,
      title: 'System Health',
      subtitle: dropRate > 5
        ? `Drop rate: ${dropRate.toFixed(1)}% — Check now`
        : 'All systems normal',
      accent: dropRate > 5 ? 'amber' : 'emerald',
    },
    {
      to: '/traffic',
      icon: ChartBarSquareIcon,
      title: 'Traffic Analysis',
      subtitle: detectionCount > 0
        ? `${detectionCount} detections today`
        : 'Deep dive metrics',
      accent: detectionCount > 0 ? 'amber' : 'blue',
      badge: detectionCount > 0 ? detectionCount : undefined,
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
      {cards.map((card) => {
        const style = accentStyles[card.accent];
        return (
          <Link
            key={card.to}
            to={card.to}
            className="card-interactive flex items-center gap-3 p-4 group"
          >
            <div className={clsx('relative flex-shrink-0 p-2 rounded-lg transition-colors', style.iconBg)}>
              <card.icon className={clsx('h-5 w-5', style.iconColor)} />
              {card.badge !== undefined && (
                <span className={clsx(
                  'absolute -top-1.5 -right-1.5 flex h-4 min-w-[16px] items-center justify-center rounded-full px-1 text-2xs font-bold text-slate-900 dark:text-white',
                  style.badgeBg,
                )}>
                  {typeof card.badge === 'number' && card.badge > 99 ? '99+' : card.badge}
                </span>
              )}
            </div>
            <div className="min-w-0">
              <p className="font-medium text-sm text-slate-900 dark:text-white truncate">{card.title}</p>
              <p className="text-xs text-slate-500 dark:text-slate-400 truncate">{card.subtitle}</p>
            </div>
          </Link>
        );
      })}
    </div>
  );
}

export default ContextualActionCards;

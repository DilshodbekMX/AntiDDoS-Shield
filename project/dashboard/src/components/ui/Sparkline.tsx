/**
 * Sparkline - Lightweight inline chart component
 *
 * Mini chart for showing trends in metric cards
 */

import { useMemo } from 'react';

export interface SparklineProps {
  data: number[];
  color?: string;
  height?: number;
  width?: number | string;
  strokeWidth?: number;
  filled?: boolean;
  showDots?: boolean;
  className?: string;
}

export function Sparkline({
  data,
  color = '#6366f1',
  height = 32,
  width = '100%',
  strokeWidth = 2,
  filled = true,
  showDots = false,
  className,
}: SparklineProps) {
  const { path, fillPath, points } = useMemo(() => {
    if (!data || data.length < 2) {
      return { path: '', fillPath: '', points: [] };
    }

    const min = Math.min(...data);
    const max = Math.max(...data);
    const range = max - min || 1;

    // Normalize data to fit in the height
    const padding = 4;
    const chartHeight = height - padding * 2;
    const chartWidth = 100; // Use percentage-based width

    const pointsData = data.map((value, index) => ({
      x: (index / (data.length - 1)) * chartWidth,
      y: padding + chartHeight - ((value - min) / range) * chartHeight,
    }));

    // Straight line segments (clean, professional look)
    let pathD = `M ${pointsData[0].x} ${pointsData[0].y}`;
    for (let i = 1; i < pointsData.length; i++) {
      pathD += ` L ${pointsData[i].x} ${pointsData[i].y}`;
    }

    // Fill path (same as line but closed at bottom)
    const fillPathD = `${pathD} L ${chartWidth} ${height} L 0 ${height} Z`;

    return {
      path: pathD,
      fillPath: fillPathD,
      points: pointsData,
    };
  }, [data, height]);

  if (!data || data.length < 2) {
    return (
      <div
        className={className}
        style={{ height, width }}
      />
    );
  }

  return (
    <svg
      viewBox={`0 0 100 ${height}`}
      preserveAspectRatio="none"
      className={className}
      style={{ height, width }}
    >
      {/* Gradient definition */}
      <defs>
        <linearGradient id={`sparkline-gradient-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>

      {/* Filled area */}
      {filled && (
        <path
          d={fillPath}
          fill={`url(#sparkline-gradient-${color.replace('#', '')})`}
        />
      )}

      {/* Line */}
      <path
        d={path}
        fill="none"
        stroke={color}
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
        vectorEffect="non-scaling-stroke"
      />

      {/* End dot */}
      {showDots && points.length > 0 && (
        <circle
          cx={points[points.length - 1].x}
          cy={points[points.length - 1].y}
          r={3}
          fill={color}
        />
      )}
    </svg>
  );
}

export default Sparkline;

/**
 * GeoMap - Interactive Attack Origin Visualization
 *
 * Features:
 * - World map with attack source markers
 * - Real-time attack animation
 * - Country-based geo-blocking controls
 * - Heat map overlay
 * - Attack trajectory visualization
 */

import { useEffect, useState, useMemo, useCallback } from 'react';
import { MapContainer, TileLayer, CircleMarker, Popup, useMap, Polyline, Circle } from 'react-leaflet';
import { LatLngExpression } from 'leaflet';
import 'leaflet/dist/leaflet.css';
import { clsx } from 'clsx';
import {
  GlobeAltIcon,
  ShieldExclamationIcon,
  NoSymbolIcon,
  CheckCircleIcon,
  ArrowPathIcon,
  FunnelIcon,
  MapIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';

// ============================================================================
// CSS Animation Injection
// ============================================================================

// Inject CSS for animations (runs once on module load)
if (typeof document !== 'undefined') {
  const styleId = 'geomap-animations';
  if (!document.getElementById(styleId)) {
    const style = document.createElement('style');
    style.id = styleId;
    style.textContent = `
      @keyframes pulse-ring {
        0% { transform: scale(0.8); opacity: 0.8; }
        50% { transform: scale(1.5); opacity: 0.4; }
        100% { transform: scale(2); opacity: 0; }
      }
      @keyframes attack-flow {
        0% { stroke-dashoffset: 0; }
        100% { stroke-dashoffset: -30; }
      }
      .leaflet-attack-pulse { animation: pulse-ring 1.5s ease-out infinite; }
      .leaflet-trajectory-animated path { animation: attack-flow 1s linear infinite; }
    `;
    document.head.appendChild(style);
  }
}

// ============================================================================
// Types
// ============================================================================

export interface AttackSource {
  id: string;
  ip: string;
  lat: number;
  lng: number;
  country: string;
  countryCode: string;
  city?: string;
  attackCount: number;
  bandwidth: number;
  attackType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  lastSeen: Date;
  isActive: boolean;
}

export interface CountryStats {
  code: string;
  name: string;
  attackCount: number;
  bandwidth: number;
  topAttackType: string;
  isBlocked: boolean;
}

export interface GeoMapProps {
  attackSources: AttackSource[];
  countryStats?: CountryStats[];
  targetLocation?: { lat: number; lng: number };
  onCountryBlock?: (countryCode: string) => void;
  onCountryUnblock?: (countryCode: string) => void;
  onIPInvestigate?: (ip: string) => void;
  className?: string;
  showTrajectories?: boolean;
  showHeatmap?: boolean;
  /** Total active threats including private IPs not visible on map */
  totalActiveThreats?: number;
}

// ============================================================================
// Constants
// ============================================================================

const SEVERITY_COLORS = {
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
};

const SEVERITY_RADIUS = {
  low: 6,
  medium: 8,
  high: 10,
  critical: 14,
};

// Default protected server location (can be customized)
const DEFAULT_TARGET: LatLngExpression = [40.7128, -74.006]; // New York

// Country coordinates for geo-blocking display (for future use with country-level zoom)
// @ts-ignore intentionally unused -- reserved for future zoom-to-country feature
const _COUNTRY_COORDS: Record<string, [number, number]> = {
  US: [37.0902, -95.7129],
  CN: [35.8617, 104.1954],
  RU: [61.524, 105.3188],
  BR: [-14.235, -51.9253],
  IN: [20.5937, 78.9629],
  DE: [51.1657, 10.4515],
  GB: [55.3781, -3.436],
  FR: [46.2276, 2.2137],
  JP: [36.2048, 138.2529],
  KR: [35.9078, 127.7669],
  AU: [-25.2744, 133.7751],
  CA: [56.1304, -106.3468],
  NL: [52.1326, 5.2913],
  UA: [48.3794, 31.1656],
  IR: [32.4279, 53.688],
  VN: [14.0583, 108.2772],
  ID: [-0.7893, 113.9213],
  PL: [51.9194, 19.1451],
  TH: [15.87, 100.9925],
  PH: [12.8797, 121.774],
};

// ============================================================================
// Sub-components
// ============================================================================

// Map controller for programmatic view changes (for future use)
// @ts-ignore intentionally unused -- reserved for future pan/zoom control feature
function _MapController({ center, zoom }: { center: LatLngExpression; zoom: number }) {
  const map = useMap();
  useEffect(() => {
    map.setView(center, zoom);
  }, [center, zoom, map]);
  return null;
}

function TargetMarker({ target, isUnderAttack }: { target: LatLngExpression; isUnderAttack: boolean }) {
  const [pulseRadius, setPulseRadius] = useState(50000);
  const [pulseOpacity, setPulseOpacity] = useState(0.3);

  // Animate defensive pulse when under attack
  useEffect(() => {
    if (!isUnderAttack) {
      setPulseRadius(50000);
      setPulseOpacity(0.3);
      return;
    }

    let frame: number;
    let startTime: number;
    const duration = 2000; // 2s pulse cycle

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = (elapsed % duration) / duration;

      // Breathing effect
      const scale = 1 + Math.sin(progress * Math.PI * 2) * 0.3;
      setPulseRadius(50000 * scale);
      setPulseOpacity(0.3 + Math.sin(progress * Math.PI * 2) * 0.1);

      frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [isUnderAttack]);

  return (
    <>
      {/* Outer defensive ring */}
      <Circle
        center={target}
        radius={pulseRadius}
        pathOptions={{
          color: isUnderAttack ? '#ef4444' : '#6366f1',
          fillColor: isUnderAttack ? '#ef4444' : '#6366f1',
          fillOpacity: pulseOpacity,
          weight: 1,
        }}
      />
      {/* Main marker */}
      <CircleMarker
        center={target}
        radius={12}
        pathOptions={{
          color: '#6366f1',
          fillColor: '#6366f1',
          fillOpacity: 0.9,
          weight: 3,
        }}
      >
        <Popup>
          <div className="font-semibold text-center">
            <div>Protected Server</div>
            {isUnderAttack && (
              <div className="text-red-600 text-sm mt-1">Under Attack!</div>
            )}
          </div>
        </Popup>
      </CircleMarker>
    </>
  );
}

function PulsingMarker({ source }: { source: AttackSource }) {
  const color = SEVERITY_COLORS[source.severity];
  const baseRadius = SEVERITY_RADIUS[source.severity];
  const [pulseRadius, setPulseRadius] = useState(baseRadius);
  const [pulseOpacity, setPulseOpacity] = useState(0.6);

  // Animate pulse effect for active attacks
  useEffect(() => {
    if (!source.isActive) return;

    let frame: number;
    let startTime: number;
    const duration = 1500; // 1.5s pulse cycle
    const maxScale = 3;

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const elapsed = timestamp - startTime;
      const progress = (elapsed % duration) / duration;

      // Ease out cubic for smooth expansion
      const easeOut = 1 - Math.pow(1 - progress, 3);
      setPulseRadius(baseRadius * (1 + easeOut * (maxScale - 1)));
      setPulseOpacity(0.6 * (1 - easeOut));

      frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [source.isActive, baseRadius]);

  if (!source.isActive) return null;

  return (
    <Circle
      center={[source.lat, source.lng]}
      radius={pulseRadius * 10000} // Convert to meters for Circle
      pathOptions={{
        color,
        fillColor: color,
        fillOpacity: pulseOpacity,
        weight: 0,
      }}
    />
  );
}

function AttackMarker({
  source,
  onInvestigate,
}: {
  source: AttackSource;
  onInvestigate?: (ip: string) => void;
}) {
  const color = SEVERITY_COLORS[source.severity];
  const radius = SEVERITY_RADIUS[source.severity];

  return (
    <>
      {/* Pulsing effect for active attacks */}
      <PulsingMarker source={source} />

      {/* Main marker */}
      <CircleMarker
        center={[source.lat, source.lng]}
        radius={radius}
        pathOptions={{
          color,
          fillColor: color,
          fillOpacity: source.isActive ? 0.8 : 0.4,
          weight: source.isActive ? 3 : 1,
        }}
      >
        <Popup>
        <div className="min-w-[200px]">
          <div className="flex items-center justify-between mb-2">
            <span className="font-bold text-slate-900">{source.ip}</span>
            <span
              className={clsx(
                'px-2 py-0.5 rounded-full text-xs font-medium',
                source.severity === 'critical' && 'bg-red-100 text-red-700',
                source.severity === 'high' && 'bg-orange-100 text-orange-700',
                source.severity === 'medium' && 'bg-yellow-100 text-yellow-700',
                source.severity === 'low' && 'bg-green-100 text-green-700'
              )}
            >
              {source.severity}
            </span>
          </div>
          <div className="space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-500">Location:</span>
              <span className="text-slate-900">
                {source.city ? `${source.city}, ` : ''}
                {source.country}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Attack Type:</span>
              <span className="text-slate-900">{source.attackType}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Attacks:</span>
              <span className="text-slate-900">{source.attackCount.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Bandwidth:</span>
              <span className="text-slate-900">{formatBandwidth(source.bandwidth)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Status:</span>
              <span className={source.isActive ? 'text-red-600' : 'text-slate-500 dark:text-slate-400'}>
                {source.isActive ? 'Active' : 'Inactive'}
              </span>
            </div>
          </div>
          {onInvestigate && (
            <button
              onClick={() => onInvestigate(source.ip)}
              className="mt-3 w-full px-3 py-1.5 bg-brand-600 text-white text-sm rounded hover:bg-brand-700 transition-colors"
            >
              Investigate IP
            </button>
          )}
        </div>
      </Popup>
    </CircleMarker>
    </>
  );
}

function AttackTrajectory({
  source,
  target,
}: {
  source: AttackSource;
  target: LatLngExpression;
}) {
  const positions: LatLngExpression[] = [[source.lat, source.lng], target];
  const color = SEVERITY_COLORS[source.severity];
  const [dashOffset, setDashOffset] = useState(0);

  // Animate dash offset for flowing effect on active attacks
  useEffect(() => {
    if (!source.isActive) return;

    let frame: number;
    let lastTime = 0;
    const speed = 50; // pixels per second

    const animate = (timestamp: number) => {
      if (lastTime) {
        const delta = timestamp - lastTime;
        setDashOffset((prev) => (prev - (delta / 1000) * speed) % 30);
      }
      lastTime = timestamp;
      frame = requestAnimationFrame(animate);
    };

    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [source.isActive]);

  return (
    <>
      {/* Glow effect for active trajectories */}
      {source.isActive && (
        <Polyline
          positions={positions}
          pathOptions={{
            color,
            weight: 4,
            opacity: 0.2,
          }}
        />
      )}
      {/* Main trajectory line */}
      <Polyline
        positions={positions}
        pathOptions={{
          color,
          weight: source.isActive ? 2 : 1,
          opacity: source.isActive ? 0.8 : 0.3,
          dashArray: '8, 12',
          dashOffset: source.isActive ? String(dashOffset) : '0',
        }}
      />
    </>
  );
}

// ============================================================================
// Helpers
// ============================================================================

function formatBandwidth(bytes: number): string {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(2)} Gbps`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(2)} Mbps`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(2)} Kbps`;
  return `${bytes} bps`;
}

// ============================================================================
// Main Component
// ============================================================================

export function GeoMap({
  attackSources,
  countryStats = [],
  targetLocation,
  onCountryBlock,
  onCountryUnblock,
  onIPInvestigate,
  className,
  showTrajectories = true,
  showHeatmap: _showHeatmap = false,
  totalActiveThreats,
}: GeoMapProps) {
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [showActive, setShowActive] = useState(true);
  const [selectedCountry, setSelectedCountry] = useState<CountryStats | null>(null);
  const [mapStyle, setMapStyle] = useState<'dark' | 'light'>('dark');

  const target = targetLocation
    ? ([targetLocation.lat, targetLocation.lng] as LatLngExpression)
    : DEFAULT_TARGET;

  // Filter attack sources
  const filteredSources = useMemo(() => {
    return attackSources.filter((source) => {
      if (severityFilter !== 'all' && source.severity !== severityFilter) return false;
      if (showActive && !source.isActive) return false;
      return true;
    });
  }, [attackSources, severityFilter, showActive]);

  // Aggregate stats
  const stats = useMemo(() => {
    const total = attackSources.length;
    const active = attackSources.filter((s) => s.isActive).length;
    const critical = attackSources.filter((s) => s.severity === 'critical').length;
    const countries = new Set(attackSources.map((s) => s.countryCode)).size;
    const totalBandwidth = attackSources.reduce((sum, s) => sum + s.bandwidth, 0);

    return { total, active, critical, countries, totalBandwidth };
  }, [attackSources]);

  // Top countries by attack count
  const topCountries = useMemo(() => {
    return [...countryStats]
      .sort((a, b) => b.attackCount - a.attackCount)
      .slice(0, 10);
  }, [countryStats]);

  const handleCountryAction = useCallback(
    (country: CountryStats) => {
      if (country.isBlocked) {
        onCountryUnblock?.(country.code);
      } else {
        onCountryBlock?.(country.code);
      }
    },
    [onCountryBlock, onCountryUnblock]
  );

  const tileUrl =
    mapStyle === 'dark'
      ? 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
      : 'https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png';

  return (
    <div className={clsx('flex flex-col', className)}>
      {/* Header Controls */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-4">
          {/* Stats Summary */}
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
              <ShieldExclamationIcon className="h-5 w-5 text-red-500" />
              <div>
                <p className="text-xs text-slate-500 dark:text-slate-400">Active Threats</p>
                <p className="text-lg font-bold text-slate-900 dark:text-white">
                  {totalActiveThreats !== undefined ? totalActiveThreats : stats.active}
                  {totalActiveThreats !== undefined && totalActiveThreats > stats.active && (
                    <span className="text-xs font-normal text-slate-500 ml-1">
                      ({stats.active} on map)
                    </span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <GlobeAltIcon className="h-5 w-5 text-brand-500" />
              <div>
                <p className="text-xs text-slate-500 dark:text-slate-400">Countries</p>
                <p className="text-lg font-bold text-slate-900 dark:text-white">{stats.countries}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <ExclamationTriangleIcon className="h-5 w-5 text-orange-500" />
              <div>
                <p className="text-xs text-slate-500 dark:text-slate-400">Critical</p>
                <p className="text-lg font-bold text-slate-900 dark:text-white">{stats.critical}</p>
              </div>
            </div>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <FunnelIcon className="h-4 w-4 text-slate-500 dark:text-slate-400" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="px-3 py-1.5 text-sm bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded-lg"
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <label className="flex items-center gap-2 text-sm text-slate-600 dark:text-slate-300">
            <input
              type="checkbox"
              checked={showActive}
              onChange={(e) => setShowActive(e.target.checked)}
              className="h-4 w-4 rounded border-slate-300 text-brand-600"
            />
            Active Only
          </label>

          <button
            onClick={() => setMapStyle((s) => (s === 'dark' ? 'light' : 'dark'))}
            className="p-2 text-slate-500 dark:text-slate-300 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-700 rounded-lg transition-colors"
            title={`Switch to ${mapStyle === 'dark' ? 'light' : 'dark'} map`}
          >
            <MapIcon className="h-5 w-5" />
          </button>
        </div>
      </div>

      {/* Map and Sidebar */}
      <div className="flex flex-col lg:flex-row gap-4 flex-1">
        {/* Map Container */}
        <div className="flex-1 rounded-xl overflow-hidden border border-slate-200 dark:border-slate-700">
          <MapContainer
            center={[20, 0]}
            zoom={2}
            style={{ height: '500px', width: '100%' }}
            scrollWheelZoom={true}
          >
            <TileLayer
              attribution='&copy; <a href="https://carto.com/attributions">CARTO</a>'
              url={tileUrl}
            />

            {/* Target marker with pulse when under attack */}
            <TargetMarker target={target} isUnderAttack={stats.active > 0} />

            {/* Attack trajectories */}
            {showTrajectories &&
              filteredSources.map((source) => (
                <AttackTrajectory key={`traj-${source.id}`} source={source} target={target} />
              ))}

            {/* Attack source markers */}
            {filteredSources.map((source) => (
              <AttackMarker
                key={source.id}
                source={source}
                onInvestigate={onIPInvestigate}
              />
            ))}
          </MapContainer>
        </div>

        {/* Sidebar - Top Countries */}
        <div className="w-full lg:w-80 bg-white dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700 overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
            <h3 className="font-semibold text-slate-900 dark:text-white">Top Attack Sources</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400">By country</p>
          </div>

          <div className="divide-y divide-slate-100 dark:divide-slate-700 max-h-[420px] overflow-y-auto">
            {topCountries.map((country) => (
              <div
                key={country.code}
                className={clsx(
                  'px-4 py-3 hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors cursor-pointer',
                  selectedCountry?.code === country.code && 'bg-brand-50 dark:bg-brand-500/10'
                )}
                onClick={() => setSelectedCountry(country)}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className="text-xl">{getCountryFlag(country.code)}</span>
                    <div>
                      <p className="font-medium text-slate-900 dark:text-white">{country.name}</p>
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        {country.attackCount.toLocaleString()} attacks
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    {country.isBlocked ? (
                      <span className="flex items-center gap-1 px-2 py-1 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400 rounded text-xs">
                        <NoSymbolIcon className="h-3 w-3" />
                        Blocked
                      </span>
                    ) : (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleCountryAction(country);
                        }}
                        className="p-1.5 text-slate-500 dark:text-slate-400 hover:text-red-600 hover:bg-red-50 dark:hover:bg-red-500/10 rounded transition-colors"
                        title="Block country"
                      >
                        <NoSymbolIcon className="h-4 w-4" />
                      </button>
                    )}
                  </div>
                </div>

                {/* Progress bar showing relative attack volume */}
                <div className="mt-2 h-1.5 bg-slate-100 dark:bg-slate-600 rounded-full overflow-hidden">
                  <div
                    className={clsx(
                      'h-full rounded-full',
                      country.isBlocked ? 'bg-red-500' : 'bg-brand-500'
                    )}
                    style={{
                      width: `${Math.min(100, (country.attackCount / (topCountries[0]?.attackCount || 1)) * 100)}%`,
                    }}
                  />
                </div>
              </div>
            ))}

            {topCountries.length === 0 && (
              <div className="px-4 py-8 text-center text-slate-500 dark:text-slate-400">
                No attack data available
              </div>
            )}
          </div>

          {/* Selected Country Actions */}
          {selectedCountry && (
            <div className="p-4 border-t border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-700/50">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xl">{getCountryFlag(selectedCountry.code)}</span>
                  <span className="font-semibold text-slate-900 dark:text-white">{selectedCountry.name}</span>
                </div>
                <button
                  onClick={() => setSelectedCountry(null)}
                  className="text-slate-500 dark:text-slate-400 hover:text-slate-600"
                >
                  &times;
                </button>
              </div>

              <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                <div>
                  <p className="text-slate-500 dark:text-slate-400">Attacks</p>
                  <p className="font-semibold text-slate-900 dark:text-white">
                    {selectedCountry.attackCount.toLocaleString()}
                  </p>
                </div>
                <div>
                  <p className="text-slate-500 dark:text-slate-400">Bandwidth</p>
                  <p className="font-semibold text-slate-900 dark:text-white">
                    {formatBandwidth(selectedCountry.bandwidth)}
                  </p>
                </div>
                <div className="col-span-2">
                  <p className="text-slate-500 dark:text-slate-400">Top Attack Type</p>
                  <p className="font-semibold text-slate-900 dark:text-white">
                    {selectedCountry.topAttackType}
                  </p>
                </div>
              </div>

              <button
                onClick={() => handleCountryAction(selectedCountry)}
                className={clsx(
                  'w-full px-4 py-2 rounded-lg text-sm font-medium transition-colors',
                  selectedCountry.isBlocked
                    ? 'bg-emerald-600 hover:bg-emerald-700 text-white'
                    : 'bg-red-600 hover:bg-red-700 text-white'
                )}
              >
                {selectedCountry.isBlocked ? (
                  <span className="flex items-center justify-center gap-2">
                    <CheckCircleIcon className="h-4 w-4" />
                    Unblock Country
                  </span>
                ) : (
                  <span className="flex items-center justify-center gap-2">
                    <NoSymbolIcon className="h-4 w-4" />
                    Block Country
                  </span>
                )}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Legend */}
      <div className="mt-4 flex items-center justify-between px-4 py-3 bg-slate-50 dark:bg-slate-800 rounded-lg">
        <div className="flex items-center gap-6">
          <span className="text-sm text-slate-500 dark:text-slate-400">Severity:</span>
          {Object.entries(SEVERITY_COLORS).map(([level, color]) => (
            <div key={level} className="flex items-center gap-2">
              <div
                className="w-3 h-3 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="text-sm text-slate-600 dark:text-slate-300 capitalize">{level}</span>
            </div>
          ))}
        </div>

        <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
          <ArrowPathIcon className="h-4 w-4" />
          Real-time data • {filteredSources.length} sources shown
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// Helper - Country Flag Emoji
// ============================================================================

function getCountryFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

export default GeoMap;

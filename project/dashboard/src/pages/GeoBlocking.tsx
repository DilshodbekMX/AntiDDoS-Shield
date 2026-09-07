/**
 * Geo-Blocking Page
 *
 * Standalone page for geographic traffic filtering:
 * - Enable/disable geo-blocking with mode selector (blacklist/whitelist)
 * - Country selection with continent grouping and quick filters
 * - Coverage map visualization
 */

import { useState, useEffect } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  GlobeAltIcon,
  MagnifyingGlassIcon,
} from '@heroicons/react/24/outline';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import api from '../services/api';
import { Toggle } from '../components/ui/FormControls';
import { SkeletonCard } from '../components/ui';
import { GeoBlockingMap } from '../components/ui/GeoBlockingMap';

// ==================== Country Data ====================

type Continent = 'Europe' | 'Asia' | 'North America' | 'South America' | 'Africa' | 'Oceania' | 'Middle East';

interface Country {
  code: string;
  name: string;
  continent: Continent;
}

const CONTINENT_ORDER: Continent[] = ['Europe', 'Asia', 'Middle East', 'North America', 'South America', 'Africa', 'Oceania'];

const COUNTRIES: Country[] = [
  // Europe (49)
  { code: 'AL', name: 'Albania', continent: 'Europe' },
  { code: 'AD', name: 'Andorra', continent: 'Europe' },
  { code: 'AT', name: 'Austria', continent: 'Europe' },
  { code: 'BY', name: 'Belarus', continent: 'Europe' },
  { code: 'BE', name: 'Belgium', continent: 'Europe' },
  { code: 'BA', name: 'Bosnia and Herzegovina', continent: 'Europe' },
  { code: 'BG', name: 'Bulgaria', continent: 'Europe' },
  { code: 'HR', name: 'Croatia', continent: 'Europe' },
  { code: 'CY', name: 'Cyprus', continent: 'Europe' },
  { code: 'CZ', name: 'Czechia', continent: 'Europe' },
  { code: 'DK', name: 'Denmark', continent: 'Europe' },
  { code: 'EE', name: 'Estonia', continent: 'Europe' },
  { code: 'FI', name: 'Finland', continent: 'Europe' },
  { code: 'FR', name: 'France', continent: 'Europe' },
  { code: 'GE', name: 'Georgia', continent: 'Europe' },
  { code: 'DE', name: 'Germany', continent: 'Europe' },
  { code: 'GR', name: 'Greece', continent: 'Europe' },
  { code: 'GL', name: 'Greenland', continent: 'Europe' },
  { code: 'VA', name: 'Holy See', continent: 'Europe' },
  { code: 'HU', name: 'Hungary', continent: 'Europe' },
  { code: 'IS', name: 'Iceland', continent: 'Europe' },
  { code: 'XK', name: 'Kosovo', continent: 'Europe' },
  { code: 'IE', name: 'Ireland', continent: 'Europe' },
  { code: 'IT', name: 'Italy', continent: 'Europe' },
  { code: 'LV', name: 'Latvia', continent: 'Europe' },
  { code: 'LI', name: 'Liechtenstein', continent: 'Europe' },
  { code: 'LT', name: 'Lithuania', continent: 'Europe' },
  { code: 'LU', name: 'Luxembourg', continent: 'Europe' },
  { code: 'MT', name: 'Malta', continent: 'Europe' },
  { code: 'MD', name: 'Moldova', continent: 'Europe' },
  { code: 'MC', name: 'Monaco', continent: 'Europe' },
  { code: 'ME', name: 'Montenegro', continent: 'Europe' },
  { code: 'NL', name: 'Netherlands', continent: 'Europe' },
  { code: 'MK', name: 'North Macedonia', continent: 'Europe' },
  { code: 'NO', name: 'Norway', continent: 'Europe' },
  { code: 'PL', name: 'Poland', continent: 'Europe' },
  { code: 'PT', name: 'Portugal', continent: 'Europe' },
  { code: 'RO', name: 'Romania', continent: 'Europe' },
  { code: 'RU', name: 'Russia', continent: 'Europe' },
  { code: 'SM', name: 'San Marino', continent: 'Europe' },
  { code: 'RS', name: 'Serbia', continent: 'Europe' },
  { code: 'SK', name: 'Slovakia', continent: 'Europe' },
  { code: 'SI', name: 'Slovenia', continent: 'Europe' },
  { code: 'ES', name: 'Spain', continent: 'Europe' },
  { code: 'SE', name: 'Sweden', continent: 'Europe' },
  { code: 'CH', name: 'Switzerland', continent: 'Europe' },
  { code: 'TR', name: 'Turkey', continent: 'Europe' },
  { code: 'UA', name: 'Ukraine', continent: 'Europe' },
  { code: 'GB', name: 'United Kingdom', continent: 'Europe' },
  // Asia (33)
  { code: 'AF', name: 'Afghanistan', continent: 'Asia' },
  { code: 'AM', name: 'Armenia', continent: 'Asia' },
  { code: 'AZ', name: 'Azerbaijan', continent: 'Asia' },
  { code: 'BD', name: 'Bangladesh', continent: 'Asia' },
  { code: 'BT', name: 'Bhutan', continent: 'Asia' },
  { code: 'BN', name: 'Brunei', continent: 'Asia' },
  { code: 'KH', name: 'Cambodia', continent: 'Asia' },
  { code: 'CN', name: 'China', continent: 'Asia' },
  { code: 'HK', name: 'Hong Kong', continent: 'Asia' },
  { code: 'IN', name: 'India', continent: 'Asia' },
  { code: 'ID', name: 'Indonesia', continent: 'Asia' },
  { code: 'JP', name: 'Japan', continent: 'Asia' },
  { code: 'KZ', name: 'Kazakhstan', continent: 'Asia' },
  { code: 'KG', name: 'Kyrgyzstan', continent: 'Asia' },
  { code: 'LA', name: 'Laos', continent: 'Asia' },
  { code: 'MY', name: 'Malaysia', continent: 'Asia' },
  { code: 'MV', name: 'Maldives', continent: 'Asia' },
  { code: 'MN', name: 'Mongolia', continent: 'Asia' },
  { code: 'MM', name: 'Myanmar', continent: 'Asia' },
  { code: 'NP', name: 'Nepal', continent: 'Asia' },
  { code: 'KP', name: 'North Korea', continent: 'Asia' },
  { code: 'PK', name: 'Pakistan', continent: 'Asia' },
  { code: 'PH', name: 'Philippines', continent: 'Asia' },
  { code: 'SG', name: 'Singapore', continent: 'Asia' },
  { code: 'KR', name: 'South Korea', continent: 'Asia' },
  { code: 'LK', name: 'Sri Lanka', continent: 'Asia' },
  { code: 'TW', name: 'Taiwan', continent: 'Asia' },
  { code: 'TJ', name: 'Tajikistan', continent: 'Asia' },
  { code: 'TH', name: 'Thailand', continent: 'Asia' },
  { code: 'TL', name: 'Timor-Leste', continent: 'Asia' },
  { code: 'TM', name: 'Turkmenistan', continent: 'Asia' },
  { code: 'UZ', name: 'Uzbekistan', continent: 'Asia' },
  { code: 'VN', name: 'Vietnam', continent: 'Asia' },
  // Middle East (15)
  { code: 'BH', name: 'Bahrain', continent: 'Middle East' },
  { code: 'EG', name: 'Egypt', continent: 'Middle East' },
  { code: 'IR', name: 'Iran', continent: 'Middle East' },
  { code: 'IQ', name: 'Iraq', continent: 'Middle East' },
  { code: 'IL', name: 'Israel', continent: 'Middle East' },
  { code: 'JO', name: 'Jordan', continent: 'Middle East' },
  { code: 'KW', name: 'Kuwait', continent: 'Middle East' },
  { code: 'LB', name: 'Lebanon', continent: 'Middle East' },
  { code: 'OM', name: 'Oman', continent: 'Middle East' },
  { code: 'PS', name: 'Palestine', continent: 'Middle East' },
  { code: 'QA', name: 'Qatar', continent: 'Middle East' },
  { code: 'SA', name: 'Saudi Arabia', continent: 'Middle East' },
  { code: 'SY', name: 'Syria', continent: 'Middle East' },
  { code: 'AE', name: 'UAE', continent: 'Middle East' },
  { code: 'YE', name: 'Yemen', continent: 'Middle East' },
  // North America (24)
  { code: 'AG', name: 'Antigua and Barbuda', continent: 'North America' },
  { code: 'BS', name: 'Bahamas', continent: 'North America' },
  { code: 'BB', name: 'Barbados', continent: 'North America' },
  { code: 'BZ', name: 'Belize', continent: 'North America' },
  { code: 'CA', name: 'Canada', continent: 'North America' },
  { code: 'CR', name: 'Costa Rica', continent: 'North America' },
  { code: 'CU', name: 'Cuba', continent: 'North America' },
  { code: 'DM', name: 'Dominica', continent: 'North America' },
  { code: 'DO', name: 'Dominican Republic', continent: 'North America' },
  { code: 'SV', name: 'El Salvador', continent: 'North America' },
  { code: 'GD', name: 'Grenada', continent: 'North America' },
  { code: 'GT', name: 'Guatemala', continent: 'North America' },
  { code: 'HT', name: 'Haiti', continent: 'North America' },
  { code: 'HN', name: 'Honduras', continent: 'North America' },
  { code: 'JM', name: 'Jamaica', continent: 'North America' },
  { code: 'MX', name: 'Mexico', continent: 'North America' },
  { code: 'NI', name: 'Nicaragua', continent: 'North America' },
  { code: 'PA', name: 'Panama', continent: 'North America' },
  { code: 'PR', name: 'Puerto Rico', continent: 'North America' },
  { code: 'KN', name: 'Saint Kitts and Nevis', continent: 'North America' },
  { code: 'LC', name: 'Saint Lucia', continent: 'North America' },
  { code: 'VC', name: 'Saint Vincent and the Grenadines', continent: 'North America' },
  { code: 'TT', name: 'Trinidad and Tobago', continent: 'North America' },
  { code: 'US', name: 'United States', continent: 'North America' },
  // South America (13)
  { code: 'AR', name: 'Argentina', continent: 'South America' },
  { code: 'BO', name: 'Bolivia', continent: 'South America' },
  { code: 'BR', name: 'Brazil', continent: 'South America' },
  { code: 'CL', name: 'Chile', continent: 'South America' },
  { code: 'CO', name: 'Colombia', continent: 'South America' },
  { code: 'EC', name: 'Ecuador', continent: 'South America' },
  { code: 'FK', name: 'Falkland Islands', continent: 'South America' },
  { code: 'GY', name: 'Guyana', continent: 'South America' },
  { code: 'PY', name: 'Paraguay', continent: 'South America' },
  { code: 'PE', name: 'Peru', continent: 'South America' },
  { code: 'SR', name: 'Suriname', continent: 'South America' },
  { code: 'UY', name: 'Uruguay', continent: 'South America' },
  { code: 'VE', name: 'Venezuela', continent: 'South America' },
  // Africa (54)
  { code: 'DZ', name: 'Algeria', continent: 'Africa' },
  { code: 'AO', name: 'Angola', continent: 'Africa' },
  { code: 'BJ', name: 'Benin', continent: 'Africa' },
  { code: 'BW', name: 'Botswana', continent: 'Africa' },
  { code: 'BF', name: 'Burkina Faso', continent: 'Africa' },
  { code: 'BI', name: 'Burundi', continent: 'Africa' },
  { code: 'CV', name: 'Cabo Verde', continent: 'Africa' },
  { code: 'CM', name: 'Cameroon', continent: 'Africa' },
  { code: 'CF', name: 'Central African Republic', continent: 'Africa' },
  { code: 'TD', name: 'Chad', continent: 'Africa' },
  { code: 'KM', name: 'Comoros', continent: 'Africa' },
  { code: 'CG', name: 'Congo', continent: 'Africa' },
  { code: 'CD', name: 'DR Congo', continent: 'Africa' },
  { code: 'CI', name: "Cote d'Ivoire", continent: 'Africa' },
  { code: 'DJ', name: 'Djibouti', continent: 'Africa' },
  { code: 'GQ', name: 'Equatorial Guinea', continent: 'Africa' },
  { code: 'ER', name: 'Eritrea', continent: 'Africa' },
  { code: 'SZ', name: 'Eswatini', continent: 'Africa' },
  { code: 'ET', name: 'Ethiopia', continent: 'Africa' },
  { code: 'GA', name: 'Gabon', continent: 'Africa' },
  { code: 'GM', name: 'Gambia', continent: 'Africa' },
  { code: 'GH', name: 'Ghana', continent: 'Africa' },
  { code: 'GN', name: 'Guinea', continent: 'Africa' },
  { code: 'GW', name: 'Guinea-Bissau', continent: 'Africa' },
  { code: 'KE', name: 'Kenya', continent: 'Africa' },
  { code: 'LS', name: 'Lesotho', continent: 'Africa' },
  { code: 'LR', name: 'Liberia', continent: 'Africa' },
  { code: 'LY', name: 'Libya', continent: 'Africa' },
  { code: 'MG', name: 'Madagascar', continent: 'Africa' },
  { code: 'MW', name: 'Malawi', continent: 'Africa' },
  { code: 'ML', name: 'Mali', continent: 'Africa' },
  { code: 'MR', name: 'Mauritania', continent: 'Africa' },
  { code: 'MU', name: 'Mauritius', continent: 'Africa' },
  { code: 'MA', name: 'Morocco', continent: 'Africa' },
  { code: 'MZ', name: 'Mozambique', continent: 'Africa' },
  { code: 'NA', name: 'Namibia', continent: 'Africa' },
  { code: 'NE', name: 'Niger', continent: 'Africa' },
  { code: 'NG', name: 'Nigeria', continent: 'Africa' },
  { code: 'RW', name: 'Rwanda', continent: 'Africa' },
  { code: 'ST', name: 'Sao Tome and Principe', continent: 'Africa' },
  { code: 'SN', name: 'Senegal', continent: 'Africa' },
  { code: 'SC', name: 'Seychelles', continent: 'Africa' },
  { code: 'SL', name: 'Sierra Leone', continent: 'Africa' },
  { code: 'SO', name: 'Somalia', continent: 'Africa' },
  { code: 'ZA', name: 'South Africa', continent: 'Africa' },
  { code: 'SS', name: 'South Sudan', continent: 'Africa' },
  { code: 'SD', name: 'Sudan', continent: 'Africa' },
  { code: 'TZ', name: 'Tanzania', continent: 'Africa' },
  { code: 'TG', name: 'Togo', continent: 'Africa' },
  { code: 'TN', name: 'Tunisia', continent: 'Africa' },
  { code: 'UG', name: 'Uganda', continent: 'Africa' },
  { code: 'ZM', name: 'Zambia', continent: 'Africa' },
  { code: 'EH', name: 'Western Sahara', continent: 'Africa' },
  { code: 'ZW', name: 'Zimbabwe', continent: 'Africa' },
  // Oceania (18)
  { code: 'AQ', name: 'Antarctica', continent: 'Oceania' },
  { code: 'AU', name: 'Australia', continent: 'Oceania' },
  { code: 'FJ', name: 'Fiji', continent: 'Oceania' },
  { code: 'KI', name: 'Kiribati', continent: 'Oceania' },
  { code: 'MH', name: 'Marshall Islands', continent: 'Oceania' },
  { code: 'FM', name: 'Micronesia', continent: 'Oceania' },
  { code: 'NR', name: 'Nauru', continent: 'Oceania' },
  { code: 'NC', name: 'New Caledonia', continent: 'Oceania' },
  { code: 'NZ', name: 'New Zealand', continent: 'Oceania' },
  { code: 'PW', name: 'Palau', continent: 'Oceania' },
  { code: 'PG', name: 'Papua New Guinea', continent: 'Oceania' },
  { code: 'WS', name: 'Samoa', continent: 'Oceania' },
  { code: 'SB', name: 'Solomon Islands', continent: 'Oceania' },
  { code: 'TO', name: 'Tonga', continent: 'Oceania' },
  { code: 'TF', name: 'French Southern Territories', continent: 'Oceania' },
  { code: 'TV', name: 'Tuvalu', continent: 'Oceania' },
  { code: 'VU', name: 'Vanuatu', continent: 'Oceania' },
];

const COUNTRIES_BY_CONTINENT = CONTINENT_ORDER.reduce((acc, continent) => {
  acc[continent] = COUNTRIES.filter(c => c.continent === continent);
  return acc;
}, {} as Record<Continent, Country[]>);

// ==================== Page Component ====================

export function GeoBlockingPage() {
  const queryClient = useQueryClient();

  // Local state
  const [selectedCountries, setSelectedCountries] = useState<string[]>([]);
  const [geoMode, setGeoMode] = useState<'blacklist' | 'whitelist'>('blacklist');
  const [geoSearch, setGeoSearch] = useState('');
  const [blockUnknown, setBlockUnknown] = useState(true);
  const [saving, setSaving] = useState(false);

  // Fetch config
  const { data: layer1Config, isLoading } = useQuery({
    queryKey: ['layer1-config'],
    queryFn: () => api.getLayer1Config(),
  });

  const geoEnabled = (layer1Config?.geo_blocking as { enabled: boolean })?.enabled ?? false;

  // Sync geo settings from config
  useEffect(() => {
    if (layer1Config?.geo_blocking) {
      const geo = layer1Config.geo_blocking as { mode: string; blocked_countries: string[]; allowed_countries: string[]; block_unknown?: boolean };
      setGeoMode(geo.mode as 'blacklist' | 'whitelist');
      const countries = geo.mode === 'blacklist' ? geo.blocked_countries : geo.allowed_countries;
      setSelectedCountries(countries || []);
      setBlockUnknown(geo.block_unknown ?? true);
    }
  }, [layer1Config]);

  // Toggle geo enabled
  const toggleGeoEnabled = async (enabled: boolean) => {
    try {
      await api.setGeoBlockingEnabled(enabled);
      toast.success(`Geo-blocking ${enabled ? 'enabled' : 'disabled'}`);
    } catch {
      toast.error('Failed');
    } finally {
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
    }
  };

  // Save geo settings
  const saveGeoSettings = async () => {
    setSaving(true);
    try {
      await api.setGeoBlockingMode(geoMode);
      await api.setGeoBlockUnknown(blockUnknown);
      await api.setGeoCountries(selectedCountries);
      queryClient.invalidateQueries({ queryKey: ['layer1-config'] });
      toast.success('Geo settings saved');
    } catch {
      toast.error('Failed to save settings');
    } finally {
      setSaving(false);
    }
  };

  // Continent toggle helpers
  const toggleContinent = (continent: Continent, select: boolean) => {
    const codes = COUNTRIES_BY_CONTINENT[continent].map(c => c.code);
    if (select) {
      setSelectedCountries(prev => [...new Set([...prev, ...codes])]);
    } else {
      const codeSet = new Set(codes);
      setSelectedCountries(prev => prev.filter(c => !codeSet.has(c)));
    }
  };
  const isContinentFullySelected = (continent: Continent) =>
    COUNTRIES_BY_CONTINENT[continent].every(c => selectedCountries.includes(c.code));
  const isContinentPartiallySelected = (continent: Continent) =>
    COUNTRIES_BY_CONTINENT[continent].some(c => selectedCountries.includes(c.code)) && !isContinentFullySelected(continent);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <SkeletonCard lines={2} />
        <SkeletonCard lines={6} />
        <SkeletonCard lines={3} />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="absolute inset-0 bg-brand-500 blur-lg opacity-30" />
            <GlobeAltIcon className="relative h-8 w-8 text-brand-500" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white">Geo-Blocking</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400 mt-0.5">
              Filter traffic by geographic origin using GeoIP database
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={clsx(
            'badge',
            geoEnabled ? 'badge-success' : 'badge-neutral'
          )}>
            {geoEnabled ? 'Active' : 'Disabled'}
          </span>
          <Toggle
            enabled={geoEnabled}
            onChange={(v) => toggleGeoEnabled(v)}
            label="Toggle geo-blocking"
          />
        </div>
      </div>

      {/* Geo-Blocking Settings Card */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Settings</h3>
          <span className={clsx(
            'badge',
            geoMode === 'blacklist' ? 'badge-danger' : 'badge-success'
          )}>
            {geoMode === 'blacklist' ? 'Blacklist Mode' : 'Whitelist Mode'}
          </span>
        </div>
        <div className="card-body space-y-4">
          <div className="flex items-center gap-6">
            <div className="flex-1">
              <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Mode</label>
              <select
                value={geoMode}
                onChange={(e) => setGeoMode(e.target.value as 'blacklist' | 'whitelist')}
                className="select max-w-md"
              >
                <option value="blacklist">Blacklist - Block selected countries</option>
                <option value="whitelist">Whitelist - Allow only selected countries</option>
              </select>
            </div>
            <div className="text-right">
              <div className="text-3xl font-bold text-slate-900 dark:text-white">{selectedCountries.length}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">of {COUNTRIES.length} selected</div>
            </div>
          </div>
          <div className="flex items-center justify-between pt-3 border-t border-slate-200 dark:border-slate-700">
            <div>
              <div className="text-sm font-medium text-slate-700 dark:text-slate-300">Block Unknown IPs</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">Block IPs that cannot be resolved to any country (e.g. private/RFC1918 addresses)</div>
            </div>
            <Toggle
              enabled={blockUnknown}
              onChange={setBlockUnknown}
              label="Block unknown IPs"
            />
          </div>
          <div className="flex items-center justify-between pt-3 border-t border-slate-200 dark:border-slate-700">
            <div>
              <div className="text-sm font-medium text-slate-700 dark:text-slate-300">Log Blocked Requests</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">Write a log entry for each geo-blocked packet (may generate high log volume during attacks)</div>
            </div>
            <Toggle
              enabled={!!((layer1Config?.geo_blocking as Record<string, unknown>)?.log_blocked ?? false)}
              onChange={async (v) => {
                try {
                  await api.updateLayer1ConfigValue('geo_blocking', 'log_blocked', v);
                  toast.success(v ? 'Logging enabled' : 'Logging disabled');
                } catch { toast.error('Failed to update'); }
                finally { queryClient.invalidateQueries({ queryKey: ['layer1-config'] }); }
              }}
              label="Log blocked requests"
            />
          </div>
        </div>
      </div>

      {/* Countries Selection Card */}
      <div className="card">
        <div className="card-header">
          <h3 className="card-title">Country Selection</h3>
          <div className="flex gap-2">
            <button
              onClick={() => setSelectedCountries(COUNTRIES.map(c => c.code))}
              className="btn btn-sm btn-secondary"
            >
              Select All
            </button>
            <button
              onClick={() => setSelectedCountries([])}
              className="btn btn-sm btn-ghost"
            >
              Clear All
            </button>
          </div>
        </div>
        <div className="card-body space-y-4">
          {/* Continent Quick Filters */}
          <div className="flex flex-wrap gap-2">
            {CONTINENT_ORDER.map(continent => {
              const full = isContinentFullySelected(continent);
              const partial = isContinentPartiallySelected(continent);
              const count = COUNTRIES_BY_CONTINENT[continent].filter(c => selectedCountries.includes(c.code)).length;
              const total = COUNTRIES_BY_CONTINENT[continent].length;
              return (
                <button
                  key={continent}
                  onClick={() => toggleContinent(continent, !full)}
                  className={clsx(
                    'inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm font-medium border transition-all duration-200',
                    full
                      ? (geoMode === 'blacklist'
                        ? 'bg-red-100 border-red-300 text-red-800 dark:bg-red-900/30 dark:border-red-700 dark:text-red-300 shadow-sm'
                        : 'bg-emerald-100 border-emerald-300 text-emerald-800 dark:bg-emerald-900/30 dark:border-emerald-700 dark:text-emerald-300 shadow-sm')
                      : partial
                        ? 'bg-amber-50 border-amber-300 text-amber-800 dark:bg-amber-900/20 dark:border-amber-700 dark:text-amber-300'
                        : 'bg-white border-slate-200 text-slate-700 dark:bg-slate-800 dark:border-slate-600 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-500 hover:shadow-sm'
                  )}
                >
                  {continent}
                  <span className={clsx(
                    'text-xs px-1.5 py-0.5 rounded-full font-semibold',
                    full ? 'bg-white/50 dark:bg-black/20' : 'bg-slate-100 dark:bg-slate-700'
                  )}>{count}/{total}</span>
                </button>
              );
            })}
          </div>

          {/* Search */}
          <div className="relative">
            <MagnifyingGlassIcon className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500 dark:text-slate-400 pointer-events-none" />
            <input
              type="text"
              value={geoSearch}
              onChange={(e) => setGeoSearch(e.target.value)}
              placeholder="Search countries..."
              className="input pl-10"
            />
          </div>

          {/* Countries by Continent */}
          <div className="space-y-4 max-h-[32rem] overflow-y-auto pr-1">
            {CONTINENT_ORDER.map(continent => {
              const countries = COUNTRIES_BY_CONTINENT[continent].filter(c =>
                !geoSearch || c.name.toLowerCase().includes(geoSearch.toLowerCase()) || c.code.toLowerCase().includes(geoSearch.toLowerCase())
              );
              if (countries.length === 0) return null;
              const continentSelected = countries.filter(c => selectedCountries.includes(c.code)).length;
              return (
                <div key={continent}>
                  <div className="flex items-center justify-between mb-2 sticky top-0 bg-white dark:bg-slate-900 py-1.5 z-10 border-b border-slate-100 dark:border-slate-800">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-slate-700 dark:text-slate-300">{continent}</span>
                      <span className={clsx(
                        'badge text-[10px]',
                        continentSelected === countries.length
                          ? (geoMode === 'blacklist' ? 'badge-danger' : 'badge-success')
                          : continentSelected > 0
                            ? 'badge-warning'
                            : 'badge-neutral'
                      )}>
                        {continentSelected}/{countries.length}
                      </span>
                    </div>
                    <button
                      onClick={() => toggleContinent(continent, continentSelected < countries.length)}
                      className="text-xs font-medium text-brand-600 hover:text-brand-700 dark:text-brand-400 dark:hover:text-brand-300 transition-colors"
                    >
                      {continentSelected === countries.length ? 'Deselect' : 'Select'} all
                    </button>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-1.5">
                    {countries.map((country) => (
                      <label key={country.code} className={clsx(
                        'flex items-center gap-2 px-2.5 py-2 rounded-lg cursor-pointer border transition-all duration-150 text-sm',
                        selectedCountries.includes(country.code)
                          ? (geoMode === 'blacklist'
                            ? 'bg-red-50 border-red-200 text-red-900 dark:bg-red-900/15 dark:border-red-800 dark:text-red-200 shadow-sm'
                            : 'bg-emerald-50 border-emerald-200 text-emerald-900 dark:bg-emerald-900/15 dark:border-emerald-800 dark:text-emerald-200 shadow-sm')
                          : 'bg-white dark:bg-slate-800/50 border-slate-200 dark:border-slate-700 text-slate-700 dark:text-slate-300 hover:border-slate-300 dark:hover:border-slate-300 dark:border-slate-600 hover:shadow-sm'
                      )}>
                        <input
                          type="checkbox"
                          checked={selectedCountries.includes(country.code)}
                          onChange={(e) => e.target.checked
                            ? setSelectedCountries([...selectedCountries, country.code])
                            : setSelectedCountries(selectedCountries.filter(c => c !== country.code))
                          }
                          className="rounded border-slate-300 text-brand-600 focus:ring-brand-500 dark:border-slate-600 dark:bg-slate-700"
                        />
                        <span className="truncate">{country.name}</span>
                        <span className="text-xs text-slate-400 dark:text-slate-500 ml-auto flex-shrink-0 font-mono">{country.code}</span>
                      </label>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Save Button */}
          <div className="flex items-center justify-between pt-2 border-t border-slate-200 dark:border-slate-800">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {selectedCountries.length} countries selected
              {geoMode === 'blacklist' ? ' will be blocked' : ' will be allowed'}
            </p>
            <button
              onClick={saveGeoSettings}
              disabled={saving}
              className="btn btn-primary"
            >
              {saving ? 'Saving...' : 'Save Geo Settings'}
            </button>
          </div>
        </div>
      </div>

      {/* Coverage Map Card */}
      <div className={clsx(
        'card overflow-hidden transition-opacity duration-300',
        !geoEnabled && 'opacity-50'
      )}>
        <div className="card-header">
          <h3 className="card-title">Coverage Map</h3>
          {geoEnabled ? (
            <div className="flex items-center gap-4 text-xs text-slate-500 dark:text-slate-400">
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 rounded-sm bg-emerald-500" />
                Allowed
              </span>
              <span className="flex items-center gap-1.5">
                <span className="inline-block w-3 h-3 rounded-sm bg-red-500" />
                Blocked
              </span>
            </div>
          ) : (
            <span className="badge badge-neutral">Disabled</span>
          )}
        </div>
        <GeoBlockingMap
          selectedCountries={selectedCountries}
          allCodes={COUNTRIES.map(c => c.code)}
          mode={geoMode}
          enabled={geoEnabled}
        />
      </div>
    </div>
  );
}

export default GeoBlockingPage;

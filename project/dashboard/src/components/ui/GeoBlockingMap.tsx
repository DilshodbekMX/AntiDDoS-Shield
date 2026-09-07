/**
 * GeoBlockingMap - Read-only world map showing geo-blocking status
 *
 * Displays a choropleth world map where countries are colored based on
 * the current geo-blocking mode and selection:
 * - Whitelist mode: selected = green (allowed), unselected = red (blocked)
 * - Blacklist mode: selected = red (blocked), unselected = green (allowed)
 * - Disabled: all countries grey
 *
 * Non-interactive: pointer-events disabled, no tooltips or clicks.
 * Uses react-simple-maps with Natural Earth 110m topology.
 */

import { memo, useMemo } from 'react';
import {
  ComposableMap,
  Geographies,
  Geography,
} from 'react-simple-maps';

/** Topology feature object passed by react-simple-maps Geographies render prop */
interface GeoFeature {
  /** ISO 3166-1 numeric country code (as string) or undefined for territories */
  id?: string;
  properties: {
    name?: string;
    [key: string]: unknown;
  };
  rsmKey: string;
  svgPath: string;
}

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json';

/**
 * ISO 3166-1 numeric -> alpha-2 mapping for world-atlas topojson IDs.
 * Includes both old (736=Sudan pre-2011) and new (729=Sudan post-2011) codes.
 */
const NUMERIC_TO_ALPHA2: Record<string, string> = {
  '004': 'AF', '008': 'AL', '012': 'DZ', '020': 'AD', '024': 'AO',
  '028': 'AG', '032': 'AR', '051': 'AM', '036': 'AU', '040': 'AT',
  '031': 'AZ', '044': 'BS', '048': 'BH', '050': 'BD', '052': 'BB',
  '112': 'BY', '056': 'BE', '084': 'BZ', '204': 'BJ', '064': 'BT',
  '068': 'BO', '070': 'BA', '072': 'BW', '076': 'BR', '096': 'BN',
  '100': 'BG', '854': 'BF', '108': 'BI', '132': 'CV', '116': 'KH',
  '120': 'CM', '124': 'CA', '140': 'CF', '148': 'TD', '152': 'CL',
  '156': 'CN', '170': 'CO', '174': 'KM', '178': 'CG', '180': 'CD',
  '188': 'CR', '384': 'CI', '191': 'HR', '192': 'CU', '196': 'CY',
  '203': 'CZ', '208': 'DK', '262': 'DJ', '212': 'DM', '214': 'DO',
  '218': 'EC', '818': 'EG', '222': 'SV', '226': 'GQ', '232': 'ER',
  '233': 'EE', '748': 'SZ', '231': 'ET', '242': 'FJ', '246': 'FI',
  '250': 'FR', '266': 'GA', '270': 'GM', '268': 'GE', '276': 'DE',
  '288': 'GH', '300': 'GR', '308': 'GD', '320': 'GT', '324': 'GN',
  '624': 'GW', '328': 'GY', '332': 'HT', '340': 'HN', '344': 'HK',
  '348': 'HU', '352': 'IS', '356': 'IN', '360': 'ID', '364': 'IR',
  '368': 'IQ', '372': 'IE', '376': 'IL', '380': 'IT', '388': 'JM',
  '392': 'JP', '400': 'JO', '398': 'KZ', '404': 'KE', '296': 'KI',
  '408': 'KP', '410': 'KR', '414': 'KW', '417': 'KG', '418': 'LA',
  '428': 'LV', '422': 'LB', '426': 'LS', '430': 'LR', '434': 'LY',
  '438': 'LI', '440': 'LT', '442': 'LU', '450': 'MG', '454': 'MW',
  '458': 'MY', '462': 'MV', '466': 'ML', '470': 'MT', '478': 'MR',
  '480': 'MU', '484': 'MX', '498': 'MD', '496': 'MN', '499': 'ME',
  '504': 'MA', '508': 'MZ', '104': 'MM', '516': 'NA', '524': 'NP',
  '528': 'NL', '554': 'NZ', '558': 'NI', '562': 'NE', '566': 'NG',
  '807': 'MK', '578': 'NO', '512': 'OM', '586': 'PK', '591': 'PA',
  '598': 'PG', '600': 'PY', '604': 'PE', '608': 'PH', '616': 'PL',
  '620': 'PT', '634': 'QA', '642': 'RO', '643': 'RU', '646': 'RW',
  '682': 'SA', '686': 'SN', '688': 'RS', '694': 'SL', '702': 'SG',
  '703': 'SK', '705': 'SI', '090': 'SB', '706': 'SO', '710': 'ZA',
  '728': 'SS', '724': 'ES', '144': 'LK', '736': 'SD', '740': 'SR',
  '752': 'SE', '756': 'CH', '760': 'SY', '158': 'TW', '762': 'TJ',
  '834': 'TZ', '764': 'TH', '626': 'TL', '768': 'TG', '776': 'TO',
  '780': 'TT', '788': 'TN', '792': 'TR', '795': 'TM', '800': 'UG',
  '804': 'UA', '784': 'AE', '826': 'GB', '840': 'US', '858': 'UY',
  '860': 'UZ', '548': 'VU', '862': 'VE', '704': 'VN', '887': 'YE',
  '894': 'ZM', '716': 'ZW', '010': 'AQ',
  '304': 'GL', '732': 'EH', '275': 'PS',
  // Post-2011 Sudan code + territories visible in 110m topojson
  '729': 'SD', '238': 'FK', '260': 'TF', '540': 'NC', '630': 'PR',
};

/**
 * Fallback for null-ID features in the topojson (disputed territories).
 * Maps territory name -> parent country alpha-2 code.
 */
const NAME_TO_ALPHA2: Record<string, string> = {
  'Kosovo': 'XK',
  'Somaliland': 'SO',
  'N. Cyprus': 'CY',
  'Northern Cyprus': 'CY',
};

interface GeoBlockingMapProps {
  selectedCountries: string[];
  allCodes: string[];
  mode: 'blacklist' | 'whitelist';
  enabled: boolean;
}

function GeoBlockingMapInner({ selectedCountries, allCodes, mode, enabled }: GeoBlockingMapProps) {
  const selectedSet = useMemo(() => new Set(selectedCountries), [selectedCountries]);
  const configurableSet = useMemo(() => new Set(allCodes), [allCodes]);

  const getCountryFill = (geo: GeoFeature): string => {
    if (!enabled) return 'var(--geo-disabled)';

    // Resolve alpha-2: try numeric ID first, then name fallback for null-ID territories
    let alpha2 = geo.id ? NUMERIC_TO_ALPHA2[geo.id] : undefined;
    if (!alpha2 && geo.properties?.name) {
      alpha2 = NAME_TO_ALPHA2[geo.properties.name];
    }

    // Territory not in configurable country list -> neutral grey
    if (!alpha2 || !configurableSet.has(alpha2)) {
      return 'var(--geo-neutral)';
    }

    const isSelected = selectedSet.has(alpha2);
    if (mode === 'blacklist') {
      return isSelected ? 'var(--geo-blocked)' : 'var(--geo-allowed)';
    } else {
      return isSelected ? 'var(--geo-allowed)' : 'var(--geo-blocked)';
    }
  };

  return (
    <div
      className="geo-map-container"
      style={{
        '--geo-allowed': '#10b981',
        '--geo-blocked': '#ef4444',
        '--geo-neutral': '#cbd5e1',
        '--geo-disabled': '#94a3b8',
        '--geo-stroke': '#e2e8f0',
      } as React.CSSProperties}
    >
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{
          scale: 120,
          center: [10, 30],
        }}
        width={800}
        height={400}
        style={{ width: '100%', height: 'auto' }}
      >
        <Geographies geography={GEO_URL}>
          {({ geographies }) =>
            (geographies as unknown as GeoFeature[]).map((geo) => (
              <Geography
                key={geo.rsmKey}
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                geography={geo as any}
                fill={getCountryFill(geo)}
                stroke="var(--geo-stroke)"
                strokeWidth={0.5}
                style={{
                  default: { outline: 'none' } as React.SVGProps<SVGPathElement>,
                  hover: { outline: 'none' } as React.SVGProps<SVGPathElement>,
                  pressed: { outline: 'none' } as React.SVGProps<SVGPathElement>,
                }}
              />
            ))
          }
        </Geographies>
      </ComposableMap>
    </div>
  );
}

export const GeoBlockingMap = memo(GeoBlockingMapInner);
export default GeoBlockingMap;

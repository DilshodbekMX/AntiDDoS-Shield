"""Re-parse CIC-IDS-2017 Friday with ALL THREE of its label CSVs.

run_cicids2017_pcap.py used to name one -- the DDoS CSV -- as Friday's sole
label source, leaving PortScan (158,930 flows) and Bot (1,966 flows) unlabelled.
See the comment on FRIDAY_CSVS there for what that cost. This re-parses that one
day and rewrites its cache; Monday is untouched because its labels never
changed, and re-parsing it would burn 10 GB of I/O to reproduce the same file.

    ANTIDDOS_BASE=<dir holding datasets/CIC-IDS-2017> python3 reparse_friday_2017.py

The same run is `python3 run_cicids2017_pcap.py --day friday`.
"""
import os as _os, sys as _sys
_HERE = _os.path.dirname(_os.path.abspath(__file__))
_sys.path.insert(0, _HERE)                        # sibling extraction modules (tree_io, extractors)
_sys.path.insert(0, _os.path.dirname(_HERE))      # ComparisonResults/: config, loaders, registry
_BASE = _os.environ.get('ANTIDDOS_BASE', _os.path.dirname(_os.path.dirname(_HERE)))  # == config.BASE

import os, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from run_cicids2017_pcap import (parse_day, FRIDAY_PCAP, FRIDAY_CSVS,
                                 FRIDAY_FEATURES_JSON)

if __name__ == '__main__':
    t0 = time.time()
    print(f"pcap : {FRIDAY_PCAP}")
    for c in FRIDAY_CSVS:
        print(f"label: {c}  {'OK' if os.path.exists(c) else 'MISSING'}")
    print(f"out  : {FRIDAY_FEATURES_JSON}\n")
    per_ip = parse_day(FRIDAY_PCAP, FRIDAY_CSVS, FRIDAY_FEATURES_JSON)
    print(f"\ndone in {time.time()-t0:.0f}s")

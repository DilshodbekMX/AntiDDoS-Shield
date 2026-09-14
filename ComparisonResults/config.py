import os

# EWMA tiers -- retuned 2026-06 to 0.15/0.05/0.01 (was 0.2/0.1/0.05): slower immediate tier
# de-twitches the baseline on benign bursts. Matches the shipped C default
# (layer2/config/layer2_config.h L2_DEFAULT_ALPHA_*). All headline numbers regenerated at these values.
TIER1_ALPHA = 0.15;  TIER1_MIN_SAMPLES = 10
TIER2_ALPHA = 0.05;  TIER2_MIN_SAMPLES = 20;  TIER2_SLOTS = 24
TIER3_ALPHA = 0.01;  TIER3_MIN_SAMPLES = 40;  TIER3_SLOTS = 168

EPS = 1e-10

# Detection thresholds
THETA_INIT = 4.0; THETA_MIN = 4.0; THETA_MAX = 10.0; THETA_STEP = 0.25
T_MIN_TIERS = 2
SINGLE_TIER_HIGH_Z_MULT = 1.25

# CUSUM
# Production C routes 5 features to EWMA_CUSUM (advanced_detection.c:53-130):
#   packets_per_sec, bytes_per_sec, flows_per_sec, new_srcip_rate, burst_factor.
# On CESNET/LITNET only the 3 volume features are available; new_srcip_rate and
# burst_factor are absent from the data. We use that 3-feature subset directly -- no
# substitution. (Earlier versions of the harness added dst_port_density here to keep
# CUSUM exercised, but that misrepresented production: dst_port_density is
# L2_METHOD_LOG_ZSCORE in C [advanced_detection.c:116], not CUSUM. Removed 2026-06-02
# per the harness-vs-C fidelity check.)
CUSUM_K_MULT = 0.25; CUSUM_H_MULT = 5.0; CUSUM_MIN_SAMPLES = 30
CUSUM_FEATURES = ['packets_per_sec', 'bytes_per_sec', 'flows_per_sec']

# JSD (4-component: tcp/udp/icmp/other -- matches C production)
JSD_THRESHOLD = 0.15
JSD_ALPHA = 0.1            # jsd_baseline_init(0.1, 30) in layer2.c:830
JSD_MIN_SAMPLES = 30       # C readiness gate before JSD can alarm
JSD_FEATURES = ['tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio']

# Log-Z features.
# VESTIGIAL -- the standalone log-Z detector contributes nothing to detection. The
# production C engine has no separate log-Z member; it log-transforms the cardinality
# features INSIDE the three-tier baseline (LOG_TRANSFORM_FEATURES, baselines.c:259-263),
# which ThreeTierBaseline mirrors. LogZDetector is retained only so the run scripts can
# advance its state for warm-up parity (see pipeline.py). Empty so it is provably inert
# and carries no bogus feature names (the previous 'unique_dst_ips' exists in neither the
# C feature enum nor LOG_TRANSFORM_FEATURES).
LOGZ_FEATURES = []

# Adaptive threshold -- must match layer2/adaptive_threshold.h constants so the
# Python harness's AdaptiveThreshold class tracks the same recent-events window
# the production C engine tracks. (Was 100 in this file,
# but L2_ADAPTIVE_WINDOW_SIZE is 60 in adaptive_threshold.h:31.)
ADAPTIVE_WINDOW = 60; ADAPTIVE_MIN_EVENTS = 10
ADAPTIVE_FP_DURATION = 10; ADAPTIVE_TP_DURATION = 30
ADAPTIVE_EVAL_INTERVAL = 300
ADAPTIVE_FP_RATE_TRIGGER = 0.30
ADAPTIVE_TP_RATE_TRIGGER = 0.50

# Baseline poisoning protection (matches C: layer2_config.h:175-179)
POISON_PROTECTION_ENABLED = True
POISON_CHANGE_RATE_THRESHOLD = 2.0    # 200% mean shift in single cycle
POISON_WINDOW_SEC = 300                # rolling 300s window
POISON_COUNT_THRESHOLD = 10            # N large changes before freeze
POISON_KEY_FEATURES = ['packets_per_sec', 'bytes_per_sec', 'syn_per_sec', 'flows_per_sec']
# C engine auto-unfreezes the baselines after a recovery interval -- see
# layer2/layer2.c:660-672. The Python harness used to set frozen=True
# permanently. (This mirrors the C constant; see
# layer2_config.h baseline_poison_recovery_sec default = 900.)
BASELINE_POISON_RECOVERY_SEC = 900     # 15 minutes

# Confidence
TIER_CONF = {3: 0.99, 2: 0.90, 1: 0.75, 0: 0.0}
Z_FACTOR_MULT = 0.1; Z_FACTOR_CAP = 1.5

# Severity thresholds
Z_CRITICAL_3TIER = 12.0; Z_HIGH_3TIER = 9.0; Z_MEDIUM_3TIER = 6.0
Z_HIGH_2TIER = 15.0; Z_MEDIUM_2TIER = 10.0; Z_MEDIUM_1TIER = 15.0

# Data split
TRAIN_NORMAL = 6000; TEST_NORMAL = 6000; TEST_ATTACK = 4000
N_TRIALS = 10; MONTE_CARLO_TRIALS = 100
MIN_IP_ROWS = 1000; TOP_N_IPS = 80

# Per-IP evaluation settings
TRAIN_FRAC   = 0.60   # 60% train
CALIB_FRAC   = 0.15   # 15% calibration (threshold tuning)
# remaining 25% = test
MIN_IP_ROWS_PER_IP = 3000

# Calibration: find theta s.t. FPR on calib set <= this target
CALIB_TARGET_FPR = 0.03
CALIB_THETA_MIN  = 4.0
CALIB_THETA_MAX  = 20.0
CALIB_THETA_STEP = 0.5

# Paths -- derived from this file's location so the package works whether the
# parent folder is named `experiment/` (source tree) or `experiments/` (GitHub
# release tree). Anchor everything off __file__. (This
# replaces the prior hard-coded "experiment/" literal in OUTPUT_JSON and
# introduces RESULTS_DIR / CACHE_DIR for the runners.)
HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.environ.get("ANTIDDOS_BASE", os.path.dirname(HERE))
RESULTS_DIR = os.path.join(HERE, "results")
CACHE_DIR = os.path.join(HERE, "cache")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(CACHE_DIR, exist_ok=True)
TAR_PATH = os.path.join(BASE, "datasets", "cesnet", "ip_addresses_sample.tar.gz")
TIMES_TAR = os.path.join(BASE, "datasets", "cesnet", "times.tar.gz")
OUTPUT_JSON = os.path.join(RESULTS_DIR, "experiment_results.json")

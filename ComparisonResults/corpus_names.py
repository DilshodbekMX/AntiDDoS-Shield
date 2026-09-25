"""One canonical corpus name, and one victim key, for every runner.

Corpus names reached the records by two routes: PANEL.json's hand-written labels and
os.listdir(datasets/extracted). Three corpora therefore carry two spellings each, and
panel_auc_matrix.json and matched_smoothing_matrix.json hold both at once, split by
population. A filter written against one literal silently drops the rows spelled the
other way; runners/run_joint_filter.py is the case that matters, because a miss there
takes the joint-filter survivor count from two to eight.

Resolve every corpus name through canon() and build every clustering key with
victim_key(). canon() raises on an unmapped spelling rather than guessing.
"""

CANONICAL = {
    'CIC-IDS-2017': 'CIC-IDS-2017',
    'CIC-IDS2017': 'CIC-IDS-2017',
    'CIC-IDS-2018': 'CSE-CIC-IDS2018',
    'CIC-IDS2018': 'CSE-CIC-IDS2018',
    'CSE-CIC-IDS2018': 'CSE-CIC-IDS2018',
    'CIC-DDoS2019': 'CIC-DDoS2019',
    'CICDDoS2019': 'CIC-DDoS2019',
    'CIC-IoT-2023': 'CIC-IoT-2023',
    'CIC_IOT_Dataset2023': 'CIC-IoT-2023',
    'LITNET-2020': 'LITNET-2020',
    'CESNET-TimeSeries24': 'CESNET-TimeSeries24',
    # 'dataset' keys in results/rescued/litnet_*.json carry a descriptive suffix.
    'LITNET-2020 (per-destination-IP)': 'LITNET-2020',
    'LITNET-2020 subnet-aggregation (cross-IP) detection \u2014 evaluates L1 protected-subnet '
    'aggregation (subnet-as-host)': 'LITNET-2020',
}

# Corpora whose benign traffic comes from a capture other than the attack capture.
SEPARATE_CAPTURE = frozenset({'CIC-IoT-2023'})

# Corpora whose stream order is an index collision, so no sequential quantity
# (EWMA state, episode runs, benign-after-attack adjacency) is interpretable.
NON_CHRONOLOGICAL = frozenset({'CIC-IoT-2023'})


class UnknownCorpus(KeyError):
    pass


def canon(name):
    """Canonical corpus name. Raises UnknownCorpus on an unmapped spelling."""
    if name is None:
        raise UnknownCorpus('corpus is None')
    key = str(name).strip()
    if key not in CANONICAL:
        raise UnknownCorpus(
            f'unmapped corpus spelling {key!r}; add it to corpus_names.CANONICAL '
            f'rather than matching a literal at the call site')
    return CANONICAL[key]


def is_separate_capture(name):
    return canon(name) in SEPARATE_CAPTURE


def is_chronological(name):
    return canon(name) not in NON_CHRONOLOGICAL


def victim_key(corpus, address):
    """Clustering key. Never key on the address alone: two corpora can share a
    private address, which would merge two victim clusters without a trace."""
    return f'{canon(corpus)}/{address}'


def normalise_victim(value, corpus=None):
    """Canonical victim key from whatever a record happens to carry.

    Deposited records are not consistent: the panel and matched-smoothing matrices key
    victims on a BARE ADDRESS, while newer records key them on canonical corpus plus
    address. Joining the two on the raw string splits one victim into two clusters, which
    lowers the exact signed-rank floor and can make 5% look reachable when it is not.
    Pass every victim through here before grouping, and pass the row's corpus when the
    value has no prefix.
    """
    v = str(value)
    if '/' in v:
        prefix, addr = v.split('/', 1)
        return f'{canon(prefix)}/{addr}'
    if corpus is None:
        raise UnknownCorpus(
            f'victim {v!r} has no corpus prefix and no corpus was supplied; a bare address '
            f'cannot be grouped safely because two corpora may share one')
    return victim_key(corpus, v)


def spelling_census(names):
    """{canonical: {raw spelling: count}} — write this into every output record so the
    normalisation is enforced by the artifact rather than by memory."""
    out = {}
    for n in names:
        out.setdefault(canon(n), {}).setdefault(str(n), 0)
        out[canon(n)][str(n)] += 1
    return out

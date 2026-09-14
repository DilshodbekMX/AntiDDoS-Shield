import random, copy, math
from config import *

def _perturb(row, **kwargs):
    r = dict(row)
    for k, v in kwargs.items():
        if callable(v):
            r[k] = v(row.get(k, 1.0))
        else:
            r[k] = v
    # Recompute dst_port_density -- x1000 to match the C
    # definition (layer2/baselines.h). Without the scale factor, perturbed
    # CESNET attack rows have density values 1000x smaller than the rest of
    # the harness expects after the data_loader fix, biasing z-scores.
    pps = r.get('packets_per_sec', 1.0) + EPS
    r['dst_port_density'] = r.get('unique_dst_ports', 1.0) * 1000.0 / pps
    return r

ATTACK_DEFS = {
    'syn_flood': lambda r: _perturb(r,
        packets_per_sec=r['packets_per_sec']*8,
        bytes_per_sec=r['bytes_per_sec']*4,
        tcp_ratio=0.94, udp_ratio=0.04,
        dir_ratio=0.85,
        flow_duration_avg=r['flow_duration_avg']*0.1,
        unique_dst_ips=r['unique_dst_ips']*6),

    'udp_flood': lambda r: _perturb(r,
        packets_per_sec=r['packets_per_sec']*9,
        bytes_per_sec=r['bytes_per_sec']*7,
        tcp_ratio=0.08, udp_ratio=0.90,
        dir_ratio=0.92),

    'dns_amplification': lambda r: _perturb(r,
        tcp_ratio=0.04, udp_ratio=0.96,
        bytes_per_sec=r['bytes_per_sec']*9,
        packets_per_sec=r['packets_per_sec']*2.5,
        flows_per_sec=r['flows_per_sec']*0.3),

    'ntp_amplification': lambda r: _perturb(r,
        tcp_ratio=0.02, udp_ratio=0.98,
        bytes_per_sec=r['bytes_per_sec']*12,
        packets_per_sec=r['packets_per_sec']*3,
        flows_per_sec=r['flows_per_sec']*0.2),

    'slowloris': lambda r: _perturb(r,
        flows_per_sec=r['flows_per_sec']*4,
        flow_duration_avg=r['flow_duration_avg']*18,
        packets_per_sec=r['packets_per_sec']*1.1,
        bytes_per_sec=r['bytes_per_sec']*1.05,
        dir_ratio=r['dir_ratio']*0.9),

    'fragment_flood': lambda r: _perturb(r,
        packets_per_sec=r['packets_per_sec']*4,
        bytes_per_sec=r['bytes_per_sec']*1.5,
        flows_per_sec=r['flows_per_sec']*0.8,
        dir_ratio=0.88),

    'pulse_attack': lambda r: _perturb(r,
        packets_per_sec=r['packets_per_sec']*22,
        bytes_per_sec=r['bytes_per_sec']*18,
        flows_per_sec=r['flows_per_sec']*12),

    # NOTE: a real carpet-bomb attack is distributed across many destination IPs
    # with each individual destination seeing only a small share. On CESNET, where
    # the harness sees one IP's row stream at a time, this cannot be cross-IP
    # synthesized. What `carpet_bomb` actually models below is a single destination
    # suddenly experiencing extreme port/flow diversity (closer to a "port-scan
    # target" pattern). The real carpet-bomb evaluation lives in section 6.1.5 (LITNET
    # /24 + /16, via run_litnet_zone.py and run_litnet_l1subnet.py). The key name
    # is kept for backwards compatibility with archived result JSONs; per-attack
    # DR on this synthetic perturbation is dropped from paper headlines (section 6.6 note).
    'carpet_bomb': lambda r: _perturb(r,
        unique_dst_ports=r['unique_dst_ports']*80,
        packets_per_sec=r['packets_per_sec']*1.2,
        flows_per_sec=r['flows_per_sec']*40,
        unique_dst_ips=r['unique_dst_ips']*3),
}

def make_slow_ramp(row, rate_per_cycle, n_cycles):
    samples = []
    r = dict(row)
    for i in range(n_cycles):
        factor = (1.0 + rate_per_cycle) ** i
        s = _perturb(r,
            packets_per_sec=r['packets_per_sec']*factor,
            bytes_per_sec=r['bytes_per_sec']*factor,
            flows_per_sec=r['flows_per_sec']*factor)
        samples.append(s)
    return samples

def synthesize(attack_type, test_normal, n_samples=400, seed=42):
    rng = random.Random(seed)
    rows = rng.choices(test_normal, k=n_samples)
    if attack_type == 'slow_ramp_5':
        result = []
        for row in rows[:n_samples//60 + 1]:
            result.extend(make_slow_ramp(row, 0.05, 60))
        return result[:n_samples]
    elif attack_type == 'slow_ramp_20':
        result = []
        for row in rows[:n_samples//25 + 1]:
            result.extend(make_slow_ramp(row, 0.20, 25))
        return result[:n_samples]
    elif attack_type in ATTACK_DEFS:
        fn = ATTACK_DEFS[attack_type]
        return [fn(r) for r in rows]
    else:
        raise ValueError(f"Unknown attack type: {attack_type}")

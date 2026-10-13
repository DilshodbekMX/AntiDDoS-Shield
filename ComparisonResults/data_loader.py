from config import *

FEATURE_MAP = {
    'n_flows':               'flows_per_sec',
    'n_packets':             'packets_per_sec',
    'n_bytes':               'bytes_per_sec',
    'average_n_dest_ports':  'unique_dst_ports',
    'average_n_dest_ip':     'unique_dst_ips',
    'tcp_udp_ratio_packets': 'tcp_ratio',
    'dir_ratio_packets':     'dir_ratio',
    'avg_duration':          'flow_duration_avg',
    'avg_ttl':               'ttl_mean',
}

AVAILABLE_FEATURES = list(FEATURE_MAP.values()) + ['udp_ratio', 'dst_port_density']

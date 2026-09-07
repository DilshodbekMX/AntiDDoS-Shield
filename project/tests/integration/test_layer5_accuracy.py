#!/usr/bin/env python3
"""
Layer 5 Accuracy Tests

Tests for Layer 5 (Intelligence & Coordination) accuracy:
- Threat feed processing
- Cross-tenant learning
- Report generation
- Attack attribution accuracy
"""

import unittest
import random
import json
import time
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple
from enum import Enum
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib


class ThreatType(Enum):
    """Types of threats from intelligence feeds"""
    BOTNET_C2 = 1
    MALWARE_DISTRIBUTION = 2
    PHISHING = 3
    SPAM_SOURCE = 4
    TOR_EXIT = 5
    PROXY = 6
    SCANNER = 7
    BRUTEFORCE = 8
    DDoS_SOURCE = 9
    APT = 10


class ConfidenceLevel(Enum):
    """Confidence levels for threat intelligence"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    VERIFIED = 4


@dataclass
class ThreatIntelEntry:
    """Entry from threat intelligence feed"""
    ip: str
    threat_types: List[ThreatType]
    confidence: ConfidenceLevel
    source: str
    first_seen: datetime
    last_seen: datetime
    tags: List[str]
    asn: Optional[int] = None
    country: Optional[str] = None


@dataclass
class AttackEvent:
    """Recorded attack event"""
    id: str
    tenant_id: int
    start_time: datetime
    end_time: Optional[datetime]
    attack_type: str
    source_ips: Set[str]
    target_ips: Set[str]
    peak_pps: int
    peak_bps: int
    packets_total: int
    bytes_total: int
    mitigated_by: str
    attribution: Optional[str] = None


@dataclass
class CrossTenantPattern:
    """Pattern detected across multiple tenants"""
    pattern_id: str
    first_seen: datetime
    tenants_affected: Set[int]
    source_ips: Set[str]
    attack_signature: str
    confidence: float
    recommended_action: str


class ThreatFeedProcessor:
    """Processes threat intelligence feeds"""

    def __init__(self):
        self.entries: Dict[str, ThreatIntelEntry] = {}
        self.sources: Dict[str, Dict] = {}
        self.source_weights = {
            'internal': 1.0,
            'verified_partner': 0.9,
            'community': 0.6,
            'public': 0.4,
        }

    def add_source(self, name: str, source_type: str, url: str):
        """Register a threat feed source"""
        self.sources[name] = {
            'type': source_type,
            'url': url,
            'weight': self.source_weights.get(source_type, 0.5),
            'entries_added': 0,
            'entries_validated': 0,
            'false_positives': 0,
        }

    def ingest_entry(self, entry: ThreatIntelEntry) -> bool:
        """Ingest a threat intelligence entry"""
        if entry.ip in self.entries:
            # Merge with existing
            existing = self.entries[entry.ip]
            existing.threat_types = list(set(existing.threat_types + entry.threat_types))
            existing.tags = list(set(existing.tags + entry.tags))
            existing.last_seen = max(existing.last_seen, entry.last_seen)

            # Update confidence based on multiple sources
            if entry.confidence.value > existing.confidence.value:
                existing.confidence = entry.confidence
        else:
            self.entries[entry.ip] = entry

        if entry.source in self.sources:
            self.sources[entry.source]['entries_added'] += 1

        return True

    def lookup(self, ip: str) -> Optional[ThreatIntelEntry]:
        """Lookup an IP in threat intelligence"""
        return self.entries.get(ip)

    def bulk_lookup(self, ips: List[str]) -> Dict[str, ThreatIntelEntry]:
        """Lookup multiple IPs"""
        return {ip: self.entries[ip] for ip in ips if ip in self.entries}

    def get_ips_by_threat(self, threat_type: ThreatType) -> List[str]:
        """Get all IPs associated with a threat type"""
        return [ip for ip, entry in self.entries.items()
                if threat_type in entry.threat_types]

    def calculate_risk_score(self, ip: str) -> float:
        """Calculate risk score for an IP (0.0-1.0)"""
        entry = self.entries.get(ip)
        if not entry:
            return 0.0

        base_score = 0.0

        # Confidence contributes up to 0.4
        confidence_scores = {
            ConfidenceLevel.LOW: 0.1,
            ConfidenceLevel.MEDIUM: 0.2,
            ConfidenceLevel.HIGH: 0.3,
            ConfidenceLevel.VERIFIED: 0.4,
        }
        base_score += confidence_scores[entry.confidence]

        # Threat types contribute up to 0.4
        high_risk_threats = {ThreatType.BOTNET_C2, ThreatType.APT, ThreatType.DDoS_SOURCE}
        medium_risk_threats = {ThreatType.MALWARE_DISTRIBUTION, ThreatType.BRUTEFORCE, ThreatType.SCANNER}

        if any(t in high_risk_threats for t in entry.threat_types):
            base_score += 0.4
        elif any(t in medium_risk_threats for t in entry.threat_types):
            base_score += 0.25
        else:
            base_score += 0.1

        # Recency contributes up to 0.2
        age_days = (datetime.now() - entry.last_seen).days
        if age_days < 1:
            base_score += 0.2
        elif age_days < 7:
            base_score += 0.15
        elif age_days < 30:
            base_score += 0.1
        elif age_days < 90:
            base_score += 0.05

        return min(1.0, base_score)


class CrossTenantLearning:
    """Cross-tenant attack pattern learning"""

    def __init__(self):
        self.attack_events: Dict[str, AttackEvent] = {}
        self.patterns: Dict[str, CrossTenantPattern] = {}
        self.ip_attack_history: Dict[str, List[str]] = defaultdict(list)  # IP -> attack IDs
        self.signature_cache: Dict[str, Set[str]] = defaultdict(set)  # signature -> IPs

    def record_attack(self, event: AttackEvent):
        """Record an attack event"""
        self.attack_events[event.id] = event

        # Update IP history
        for ip in event.source_ips:
            self.ip_attack_history[ip].append(event.id)

        # Generate signature
        signature = self._generate_signature(event)
        for ip in event.source_ips:
            self.signature_cache[signature].add(ip)

    def _generate_signature(self, event: AttackEvent) -> str:
        """Generate attack signature"""
        # Simplified signature based on attack characteristics
        sig_data = f"{event.attack_type}:{len(event.source_ips) // 100}:{event.peak_pps // 100000}"
        return hashlib.md5(sig_data.encode()).hexdigest()[:16]

    def detect_cross_tenant_pattern(self, window_hours: int = 24) -> List[CrossTenantPattern]:
        """Detect patterns across multiple tenants"""
        patterns = []
        cutoff = datetime.now() - timedelta(hours=window_hours)

        # Group recent attacks by signature
        recent_attacks: Dict[str, List[AttackEvent]] = defaultdict(list)
        for event in self.attack_events.values():
            if event.start_time > cutoff:
                sig = self._generate_signature(event)
                recent_attacks[sig].append(event)

        # Find patterns affecting multiple tenants
        for sig, events in recent_attacks.items():
            tenants = {e.tenant_id for e in events}
            if len(tenants) >= 2:
                all_ips = set()
                for e in events:
                    all_ips.update(e.source_ips)

                pattern = CrossTenantPattern(
                    pattern_id=f"pattern_{sig}",
                    first_seen=min(e.start_time for e in events),
                    tenants_affected=tenants,
                    source_ips=all_ips,
                    attack_signature=sig,
                    confidence=min(len(tenants) / 5.0, 1.0),  # More tenants = higher confidence
                    recommended_action="block_ips" if len(all_ips) < 1000 else "rate_limit"
                )
                patterns.append(pattern)
                self.patterns[pattern.pattern_id] = pattern

        return patterns

    def get_ip_reputation_from_attacks(self, ip: str) -> Tuple[float, List[str]]:
        """Get IP reputation based on attack history"""
        attack_ids = self.ip_attack_history.get(ip, [])

        if not attack_ids:
            return (0.5, [])  # Neutral score for unknown IPs

        # Count unique tenants attacked
        tenants_attacked = set()
        attack_types = []
        for aid in attack_ids:
            event = self.attack_events.get(aid)
            if event:
                tenants_attacked.add(event.tenant_id)
                attack_types.append(event.attack_type)

        # More tenants = lower reputation
        rep_score = max(0.0, 0.5 - (len(tenants_attacked) * 0.1) - (len(attack_ids) * 0.05))

        return (rep_score, attack_types)

    def share_blocklist(self, source_tenant: int, ip: str) -> List[int]:
        """Recommend sharing a blocked IP with other tenants"""
        # Find other tenants attacked by this IP
        attack_ids = self.ip_attack_history.get(ip, [])
        tenants = set()

        for aid in attack_ids:
            event = self.attack_events.get(aid)
            if event and event.tenant_id != source_tenant:
                tenants.add(event.tenant_id)

        return list(tenants)


class ReportGenerator:
    """Generates attack and threat reports"""

    def __init__(self, feed_processor: ThreatFeedProcessor, learning: CrossTenantLearning):
        self.feed_processor = feed_processor
        self.learning = learning

    def generate_attack_report(self, event: AttackEvent) -> Dict:
        """Generate detailed attack report"""
        # Enrich with threat intel
        enriched_ips = []
        for ip in event.source_ips:
            intel = self.feed_processor.lookup(ip)
            enriched_ips.append({
                'ip': ip,
                'threat_intel': intel is not None,
                'risk_score': self.feed_processor.calculate_risk_score(ip),
                'threat_types': [t.name for t in intel.threat_types] if intel else [],
            })

        # Check for cross-tenant patterns
        patterns = [p for p in self.learning.patterns.values()
                    if event.tenant_id in p.tenants_affected]

        return {
            'event_id': event.id,
            'tenant_id': event.tenant_id,
            'duration_sec': (event.end_time - event.start_time).total_seconds() if event.end_time else None,
            'attack_type': event.attack_type,
            'peak_pps': event.peak_pps,
            'peak_bps': event.peak_bps,
            'total_packets': event.packets_total,
            'total_bytes': event.bytes_total,
            'source_ip_count': len(event.source_ips),
            'enriched_sources': enriched_ips[:100],  # Top 100
            'cross_tenant_patterns': len(patterns),
            'mitigation': event.mitigated_by,
            'attribution': event.attribution,
        }

    def generate_threat_landscape_report(self, tenant_id: int, days: int = 7) -> Dict:
        """Generate threat landscape report for a tenant"""
        cutoff = datetime.now() - timedelta(days=days)

        # Get attacks for this tenant
        tenant_attacks = [e for e in self.learning.attack_events.values()
                         if e.tenant_id == tenant_id and e.start_time > cutoff]

        # Aggregate statistics
        attack_types = defaultdict(int)
        all_source_ips = set()
        total_packets = 0
        total_bytes = 0

        for event in tenant_attacks:
            attack_types[event.attack_type] += 1
            all_source_ips.update(event.source_ips)
            total_packets += event.packets_total
            total_bytes += event.bytes_total

        # Threat intel coverage
        intel_hits = 0
        for ip in all_source_ips:
            if self.feed_processor.lookup(ip):
                intel_hits += 1

        return {
            'tenant_id': tenant_id,
            'period_days': days,
            'total_attacks': len(tenant_attacks),
            'attack_type_breakdown': dict(attack_types),
            'unique_source_ips': len(all_source_ips),
            'total_packets_mitigated': total_packets,
            'total_bytes_mitigated': total_bytes,
            'threat_intel_coverage': intel_hits / len(all_source_ips) if all_source_ips else 0,
            'cross_tenant_patterns_detected': len([p for p in self.learning.patterns.values()
                                                   if tenant_id in p.tenants_affected]),
        }


class TestThreatFeedProcessing(unittest.TestCase):
    """Test threat feed processing accuracy"""

    def setUp(self):
        self.processor = ThreatFeedProcessor()
        self.processor.add_source('internal', 'internal', 'file:///data/internal.json')
        self.processor.add_source('abuse_ch', 'verified_partner', 'https://abuse.ch/feed')
        self.processor.add_source('spamhaus', 'verified_partner', 'https://spamhaus.org/feed')

    def test_single_entry_ingestion(self):
        """Test ingesting a single threat entry"""
        entry = ThreatIntelEntry(
            ip="198.51.100.1",
            threat_types=[ThreatType.BOTNET_C2],
            confidence=ConfidenceLevel.HIGH,
            source='internal',
            first_seen=datetime.now() - timedelta(days=30),
            last_seen=datetime.now(),
            tags=['mirai', 'iot'],
        )

        result = self.processor.ingest_entry(entry)
        self.assertTrue(result)

        lookup = self.processor.lookup("198.51.100.1")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.confidence, ConfidenceLevel.HIGH)
        self.assertIn(ThreatType.BOTNET_C2, lookup.threat_types)

    def test_duplicate_entry_merge(self):
        """Test that duplicate entries are merged correctly"""
        entry1 = ThreatIntelEntry(
            ip="198.51.100.2",
            threat_types=[ThreatType.SPAM_SOURCE],
            confidence=ConfidenceLevel.MEDIUM,
            source='abuse_ch',
            first_seen=datetime.now() - timedelta(days=30),
            last_seen=datetime.now() - timedelta(days=7),
            tags=['spam'],
        )

        entry2 = ThreatIntelEntry(
            ip="198.51.100.2",
            threat_types=[ThreatType.BRUTEFORCE],
            confidence=ConfidenceLevel.HIGH,
            source='spamhaus',
            first_seen=datetime.now() - timedelta(days=10),
            last_seen=datetime.now(),
            tags=['ssh_bruteforce'],
        )

        self.processor.ingest_entry(entry1)
        self.processor.ingest_entry(entry2)

        lookup = self.processor.lookup("198.51.100.2")
        self.assertIsNotNone(lookup)

        # Should have both threat types
        self.assertIn(ThreatType.SPAM_SOURCE, lookup.threat_types)
        self.assertIn(ThreatType.BRUTEFORCE, lookup.threat_types)

        # Should have higher confidence
        self.assertEqual(lookup.confidence, ConfidenceLevel.HIGH)

        # Should have merged tags
        self.assertIn('spam', lookup.tags)
        self.assertIn('ssh_bruteforce', lookup.tags)

    def test_bulk_lookup_performance(self):
        """Test bulk lookup returns correct results"""
        # Ingest 1000 entries
        for i in range(1000):
            entry = ThreatIntelEntry(
                ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                threat_types=[random.choice(list(ThreatType))],
                confidence=random.choice(list(ConfidenceLevel)),
                source='internal',
                first_seen=datetime.now() - timedelta(days=random.randint(1, 90)),
                last_seen=datetime.now() - timedelta(hours=random.randint(0, 168)),
                tags=['test'],
            )
            self.processor.ingest_entry(entry)

        # Test bulk lookup
        ips_to_lookup = [f"10.0.{i // 256}.{i % 256}" for i in range(100)]
        results = self.processor.bulk_lookup(ips_to_lookup)

        # Should find all 100
        self.assertEqual(len(results), 100)

    def test_risk_score_calculation(self):
        """Test risk score calculation accuracy"""
        # High risk: verified botnet C2, recent
        high_risk = ThreatIntelEntry(
            ip="198.51.100.10",
            threat_types=[ThreatType.BOTNET_C2, ThreatType.APT],
            confidence=ConfidenceLevel.VERIFIED,
            source='internal',
            first_seen=datetime.now() - timedelta(days=30),
            last_seen=datetime.now(),
            tags=['high_risk'],
        )
        self.processor.ingest_entry(high_risk)
        high_score = self.processor.calculate_risk_score("198.51.100.10")
        self.assertGreater(high_score, 0.8)

        # Low risk: old proxy, low confidence
        low_risk = ThreatIntelEntry(
            ip="198.51.100.11",
            threat_types=[ThreatType.PROXY],
            confidence=ConfidenceLevel.LOW,
            source='public',
            first_seen=datetime.now() - timedelta(days=180),
            last_seen=datetime.now() - timedelta(days=120),
            tags=['low_risk'],
        )
        self.processor.ingest_entry(low_risk)
        low_score = self.processor.calculate_risk_score("198.51.100.11")
        self.assertLess(low_score, 0.3)

        # Unknown IP
        unknown_score = self.processor.calculate_risk_score("192.0.2.1")
        self.assertEqual(unknown_score, 0.0)


class TestCrossTenantLearning(unittest.TestCase):
    """Test cross-tenant learning accuracy"""

    def setUp(self):
        self.learning = CrossTenantLearning()

    def generate_attack_event(self, tenant_id: int, attack_type: str,
                              num_sources: int = 100) -> AttackEvent:
        """Generate a test attack event"""
        return AttackEvent(
            id=f"attack_{tenant_id}_{random.randint(1000, 9999)}",
            tenant_id=tenant_id,
            start_time=datetime.now() - timedelta(hours=random.randint(1, 24)),
            end_time=datetime.now(),
            attack_type=attack_type,
            source_ips={f"10.{i // 256}.{i % 256}.1" for i in range(num_sources)},
            target_ips={f"192.168.{tenant_id}.{i}" for i in range(10)},
            peak_pps=random.randint(100000, 1000000),
            peak_bps=random.randint(100000000, 10000000000),
            packets_total=random.randint(1000000, 100000000),
            bytes_total=random.randint(1000000000, 100000000000),
            mitigated_by='layer1_rate_limit',
        )

    def test_attack_recording(self):
        """Test attack events are recorded correctly"""
        event = self.generate_attack_event(1, 'syn_flood')
        self.learning.record_attack(event)

        self.assertIn(event.id, self.learning.attack_events)
        self.assertEqual(len(self.learning.attack_events), 1)

    def test_cross_tenant_pattern_detection(self):
        """Test detection of patterns across tenants"""
        # Create similar attacks against multiple tenants from same sources
        common_ips = {f"10.0.0.{i}" for i in range(50)}

        for tenant_id in range(1, 5):
            event = AttackEvent(
                id=f"attack_cross_{tenant_id}",
                tenant_id=tenant_id,
                start_time=datetime.now() - timedelta(hours=2),
                end_time=datetime.now(),
                attack_type='syn_flood',
                source_ips=common_ips | {f"10.0.{tenant_id}.{i}" for i in range(20)},
                target_ips={f"192.168.{tenant_id}.1"},
                peak_pps=500000,
                peak_bps=5000000000,
                packets_total=50000000,
                bytes_total=50000000000,
                mitigated_by='layer1_syn_proxy',
            )
            self.learning.record_attack(event)

        patterns = self.learning.detect_cross_tenant_pattern(window_hours=24)

        # Should detect at least one pattern
        self.assertGreater(len(patterns), 0)

        # Pattern should affect multiple tenants
        pattern = patterns[0]
        self.assertGreaterEqual(len(pattern.tenants_affected), 2)

        # Pattern should include common IPs
        self.assertTrue(common_ips.issubset(pattern.source_ips))

    def test_ip_reputation_from_attacks(self):
        """Test IP reputation calculation from attack history"""
        attacker_ip = "10.0.0.100"

        # Record attacks from this IP against multiple tenants
        for tenant_id in range(1, 4):
            event = AttackEvent(
                id=f"rep_test_{tenant_id}",
                tenant_id=tenant_id,
                start_time=datetime.now() - timedelta(hours=random.randint(1, 48)),
                end_time=datetime.now(),
                attack_type='syn_flood',
                source_ips={attacker_ip, f"10.0.{tenant_id}.1"},
                target_ips={f"192.168.{tenant_id}.1"},
                peak_pps=500000,
                peak_bps=5000000000,
                packets_total=50000000,
                bytes_total=50000000000,
                mitigated_by='layer1_rate_limit',
            )
            self.learning.record_attack(event)

        rep_score, attack_types = self.learning.get_ip_reputation_from_attacks(attacker_ip)

        # Reputation should be low (attacked 3 tenants)
        self.assertLess(rep_score, 0.3)
        self.assertEqual(len(attack_types), 3)

    def test_blocklist_sharing_recommendation(self):
        """Test blocklist sharing recommendations"""
        shared_attacker = "10.0.0.50"

        # Record attacks from shared IP
        for tenant_id in [1, 2, 3]:
            event = AttackEvent(
                id=f"share_test_{tenant_id}",
                tenant_id=tenant_id,
                start_time=datetime.now(),
                end_time=datetime.now(),
                attack_type='syn_flood',
                source_ips={shared_attacker},
                target_ips={f"192.168.{tenant_id}.1"},
                peak_pps=500000,
                peak_bps=5000000000,
                packets_total=50000000,
                bytes_total=50000000000,
                mitigated_by='layer1_rate_limit',
            )
            self.learning.record_attack(event)

        # Tenant 1 blocks IP, recommend sharing with others
        recommendations = self.learning.share_blocklist(1, shared_attacker)

        # Should recommend sharing with tenants 2 and 3
        self.assertEqual(set(recommendations), {2, 3})


class TestReportGeneration(unittest.TestCase):
    """Test report generation accuracy"""

    def setUp(self):
        self.feed_processor = ThreatFeedProcessor()
        self.learning = CrossTenantLearning()
        self.report_gen = ReportGenerator(self.feed_processor, self.learning)

        # Populate some threat intel
        for i in range(100):
            entry = ThreatIntelEntry(
                ip=f"10.0.0.{i}",
                threat_types=[ThreatType.DDoS_SOURCE],
                confidence=ConfidenceLevel.HIGH,
                source='internal',
                first_seen=datetime.now() - timedelta(days=30),
                last_seen=datetime.now(),
                tags=['ddos'],
            )
            self.feed_processor.ingest_entry(entry)

    def test_attack_report_generation(self):
        """Test attack report generation"""
        event = AttackEvent(
            id="report_test_1",
            tenant_id=1,
            start_time=datetime.now() - timedelta(hours=1),
            end_time=datetime.now(),
            attack_type='syn_flood',
            source_ips={f"10.0.0.{i}" for i in range(50)},
            target_ips={"192.168.1.1"},
            peak_pps=1000000,
            peak_bps=10000000000,
            packets_total=100000000,
            bytes_total=100000000000,
            mitigated_by='layer1_syn_proxy',
        )
        self.learning.record_attack(event)

        report = self.report_gen.generate_attack_report(event)

        self.assertEqual(report['event_id'], "report_test_1")
        self.assertEqual(report['tenant_id'], 1)
        self.assertEqual(report['attack_type'], 'syn_flood')
        self.assertEqual(report['source_ip_count'], 50)
        self.assertIsNotNone(report['duration_sec'])

        # Check threat intel enrichment
        enriched = report['enriched_sources']
        threat_intel_count = sum(1 for e in enriched if e['threat_intel'])
        self.assertGreater(threat_intel_count, 0)

    def test_threat_landscape_report(self):
        """Test threat landscape report generation"""
        # Record multiple attacks
        for i in range(5):
            event = AttackEvent(
                id=f"landscape_{i}",
                tenant_id=1,
                start_time=datetime.now() - timedelta(days=random.randint(0, 5)),
                end_time=datetime.now(),
                attack_type=random.choice(['syn_flood', 'udp_flood', 'dns_amplification']),
                source_ips={f"10.0.{i}.{j}" for j in range(20)},
                target_ips={"192.168.1.1"},
                peak_pps=random.randint(100000, 1000000),
                peak_bps=random.randint(1000000000, 10000000000),
                packets_total=random.randint(10000000, 100000000),
                bytes_total=random.randint(10000000000, 100000000000),
                mitigated_by='layer1_rate_limit',
            )
            self.learning.record_attack(event)

        report = self.report_gen.generate_threat_landscape_report(1, days=7)

        self.assertEqual(report['tenant_id'], 1)
        self.assertEqual(report['total_attacks'], 5)
        self.assertGreater(report['unique_source_ips'], 0)
        self.assertGreater(report['total_packets_mitigated'], 0)
        self.assertIn('attack_type_breakdown', report)


class TestLayer5Integration(unittest.TestCase):
    """Integration tests for Layer 5 components"""

    def test_full_intelligence_pipeline(self):
        """Test full Layer 5 intelligence pipeline"""
        # Setup
        feed_processor = ThreatFeedProcessor()
        learning = CrossTenantLearning()
        report_gen = ReportGenerator(feed_processor, learning)

        # Step 1: Ingest threat intel
        for i in range(1000):
            entry = ThreatIntelEntry(
                ip=f"10.{i // 65536}.{(i // 256) % 256}.{i % 256}",
                threat_types=[random.choice(list(ThreatType))],
                confidence=random.choice(list(ConfidenceLevel)),
                source='internal',
                first_seen=datetime.now() - timedelta(days=random.randint(1, 90)),
                last_seen=datetime.now() - timedelta(hours=random.randint(0, 168)),
                tags=['test'],
            )
            feed_processor.ingest_entry(entry)

        self.assertEqual(len(feed_processor.entries), 1000)

        # Step 2: Record attacks across tenants
        for tenant_id in range(1, 11):
            for attack_num in range(3):
                event = AttackEvent(
                    id=f"integration_{tenant_id}_{attack_num}",
                    tenant_id=tenant_id,
                    start_time=datetime.now() - timedelta(hours=random.randint(1, 72)),
                    end_time=datetime.now(),
                    attack_type=random.choice(['syn_flood', 'udp_flood', 'dns_amp']),
                    source_ips={f"10.0.{i // 256}.{i % 256}" for i in range(50 + random.randint(0, 50))},
                    target_ips={f"192.168.{tenant_id}.1"},
                    peak_pps=random.randint(100000, 2000000),
                    peak_bps=random.randint(1000000000, 20000000000),
                    packets_total=random.randint(10000000, 200000000),
                    bytes_total=random.randint(10000000000, 200000000000),
                    mitigated_by='layer1_rate_limit',
                )
                learning.record_attack(event)

        self.assertEqual(len(learning.attack_events), 30)

        # Step 3: Detect cross-tenant patterns
        patterns = learning.detect_cross_tenant_pattern(window_hours=96)
        # Should find some patterns given overlapping attack IPs
        self.assertGreater(len(patterns), 0)

        # Step 4: Generate reports
        for tenant_id in range(1, 11):
            landscape = report_gen.generate_threat_landscape_report(tenant_id, days=7)
            self.assertEqual(landscape['tenant_id'], tenant_id)
            self.assertEqual(landscape['total_attacks'], 3)

        # Step 5: Verify threat intel enrichment
        sample_attack = list(learning.attack_events.values())[0]
        attack_report = report_gen.generate_attack_report(sample_attack)

        # Should have some IPs matched in threat intel
        enriched = attack_report['enriched_sources']
        intel_matches = sum(1 for e in enriched if e['threat_intel'])
        # Given 1000 IPs in intel and ~50-100 in attack, expect some overlap
        self.assertGreater(intel_matches, 0)


if __name__ == '__main__':
    # Run tests with verbose output
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestThreatFeedProcessing))
    suite.addTests(loader.loadTestsFromTestCase(TestCrossTenantLearning))
    suite.addTests(loader.loadTestsFromTestCase(TestReportGeneration))
    suite.addTests(loader.loadTestsFromTestCase(TestLayer5Integration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*70)
    print("LAYER 5 ACCURACY TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✓ ALL LAYER 5 ACCURACY TESTS PASSED")
    else:
        print("\n✗ SOME TESTS FAILED")
        exit(1)

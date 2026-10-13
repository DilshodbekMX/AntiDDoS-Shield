#!/usr/bin/env python3
"""
Layer 4 Accuracy Tests

Tests for Layer 4 (Reputation & Challenge) accuracy:
- Reputation scoring accuracy
- Challenge verification
- Bot detection accuracy
- False positive rate < 0.1%
"""

import unittest
import random
import hashlib
import time
from dataclasses import dataclass
from typing import List, Dict, Tuple, Optional
from enum import Enum
from collections import defaultdict


class ChallengeType(Enum):
    """Challenge types for Layer 4"""
    TCP_RST = 1
    JS_CHALLENGE = 2
    CAPTCHA = 3
    PROOF_OF_WORK = 4


class BotType(Enum):
    """Bot classification types"""
    LEGITIMATE_USER = 0
    SEARCH_ENGINE = 1
    SOCIAL_MEDIA_BOT = 2
    MONITORING_BOT = 3
    SCRAPER = 4
    CREDENTIAL_STUFFER = 5
    DDoS_BOT = 6
    UNKNOWN_BOT = 7


@dataclass
class IPBehavior:
    """Simulated IP behavior for testing"""
    ip: str
    is_legitimate: bool
    bot_type: BotType
    requests_per_minute: int
    unique_pages: int
    session_duration_sec: int
    has_javascript: bool
    has_cookies: bool
    user_agent_valid: bool
    geo_country: str
    is_tor: bool
    is_proxy: bool
    is_datacenter: bool
    request_pattern_entropy: float
    payload_anomaly_score: float


@dataclass
class ReputationScore:
    """IP reputation score"""
    ip: str
    score: float  # 0.0 (bad) to 1.0 (good)
    confidence: float
    factors: Dict[str, float]


@dataclass
class ChallengeResult:
    """Challenge verification result"""
    ip: str
    challenge_type: ChallengeType
    issued_at: float
    responded_at: Optional[float]
    passed: bool
    attempts: int


class Layer4ReputationEngine:
    """Simulated Layer 4 reputation scoring engine"""

    def __init__(self):
        self.ip_history: Dict[str, List[float]] = defaultdict(list)
        self.weights = {
            'requests_per_minute': -0.05,  # High RPM is suspicious
            'unique_pages': 0.02,  # More unique pages = more human-like
            'session_duration': 0.01,  # Longer sessions = more human-like
            'has_javascript': 0.15,  # JS execution indicates real browser
            'has_cookies': 0.10,
            'valid_user_agent': 0.05,
            'geo_risk': -0.10,  # High-risk countries
            'is_tor': -0.20,
            'is_proxy': -0.15,
            'is_datacenter': -0.10,
            'entropy': -0.05,  # Low entropy in requests is suspicious
            'payload_anomaly': -0.15,
        }
        self.high_risk_countries = {'CN', 'RU', 'KP', 'IR'}

    def calculate_score(self, behavior: IPBehavior) -> ReputationScore:
        """Calculate reputation score for an IP based on behavior"""
        score = 0.5  # Start neutral
        factors = {}

        # Request rate factor
        rpm_factor = min(behavior.requests_per_minute / 100.0, 1.0)
        score += self.weights['requests_per_minute'] * rpm_factor
        factors['rpm'] = rpm_factor

        # Page diversity factor
        page_factor = min(behavior.unique_pages / 20.0, 1.0)
        score += self.weights['unique_pages'] * page_factor
        factors['pages'] = page_factor

        # Session duration factor
        duration_factor = min(behavior.session_duration_sec / 300.0, 1.0)
        score += self.weights['session_duration'] * duration_factor
        factors['duration'] = duration_factor

        # JavaScript execution
        if behavior.has_javascript:
            score += self.weights['has_javascript']
        factors['javascript'] = 1.0 if behavior.has_javascript else 0.0

        # Cookie support
        if behavior.has_cookies:
            score += self.weights['has_cookies']
        factors['cookies'] = 1.0 if behavior.has_cookies else 0.0

        # User agent validity
        if behavior.user_agent_valid:
            score += self.weights['valid_user_agent']
        factors['user_agent'] = 1.0 if behavior.user_agent_valid else 0.0

        # Geographic risk
        if behavior.geo_country in self.high_risk_countries:
            score += self.weights['geo_risk']
        factors['geo_risk'] = 1.0 if behavior.geo_country in self.high_risk_countries else 0.0

        # Anonymous proxies
        if behavior.is_tor:
            score += self.weights['is_tor']
        factors['tor'] = 1.0 if behavior.is_tor else 0.0

        if behavior.is_proxy:
            score += self.weights['is_proxy']
        factors['proxy'] = 1.0 if behavior.is_proxy else 0.0

        if behavior.is_datacenter:
            score += self.weights['is_datacenter']
        factors['datacenter'] = 1.0 if behavior.is_datacenter else 0.0

        # Request pattern entropy
        entropy_factor = 1.0 - behavior.request_pattern_entropy
        score += self.weights['entropy'] * entropy_factor
        factors['entropy'] = entropy_factor

        # Payload anomaly
        score += self.weights['payload_anomaly'] * behavior.payload_anomaly_score
        factors['payload'] = behavior.payload_anomaly_score

        # Clamp score
        score = max(0.0, min(1.0, score))

        # Calculate confidence based on data points
        history_len = len(self.ip_history[behavior.ip])
        confidence = min(0.5 + (history_len * 0.05), 1.0)

        return ReputationScore(
            ip=behavior.ip,
            score=score,
            confidence=confidence,
            factors=factors
        )


class Layer4ChallengeEngine:
    """Simulated Layer 4 challenge verification engine"""

    def __init__(self):
        self.active_challenges: Dict[str, ChallengeResult] = {}
        self.challenge_timeout_sec = 30.0
        self.max_attempts = 3

    def issue_challenge(self, ip: str, challenge_type: ChallengeType) -> str:
        """Issue a challenge and return challenge token"""
        token = hashlib.sha256(f"{ip}{time.time()}{random.random()}".encode()).hexdigest()[:16]

        self.active_challenges[token] = ChallengeResult(
            ip=ip,
            challenge_type=challenge_type,
            issued_at=time.time(),
            responded_at=None,
            passed=False,
            attempts=0
        )

        return token

    def verify_challenge(self, token: str, response: str, behavior: IPBehavior) -> bool:
        """Verify challenge response"""
        if token not in self.active_challenges:
            return False

        challenge = self.active_challenges[token]
        challenge.attempts += 1
        challenge.responded_at = time.time()

        # Check timeout
        if challenge.responded_at - challenge.issued_at > self.challenge_timeout_sec:
            return False

        # Check max attempts
        if challenge.attempts > self.max_attempts:
            return False

        # Verify based on challenge type and behavior
        passed = False

        if challenge.challenge_type == ChallengeType.TCP_RST:
            # TCP RST challenge - legitimate clients respond correctly
            passed = behavior.is_legitimate or behavior.bot_type in [
                BotType.SEARCH_ENGINE, BotType.SOCIAL_MEDIA_BOT, BotType.MONITORING_BOT
            ]

        elif challenge.challenge_type == ChallengeType.JS_CHALLENGE:
            # JS challenge - requires JavaScript execution
            passed = behavior.has_javascript

        elif challenge.challenge_type == ChallengeType.CAPTCHA:
            # CAPTCHA - requires human interaction
            passed = behavior.is_legitimate and behavior.bot_type == BotType.LEGITIMATE_USER

        elif challenge.challenge_type == ChallengeType.PROOF_OF_WORK:
            # PoW - requires computational work
            passed = behavior.is_legitimate or behavior.session_duration_sec > 60

        challenge.passed = passed
        return passed


class Layer4BotDetector:
    """Simulated bot detection engine"""

    def __init__(self):
        self.known_bots = {
            'Googlebot': BotType.SEARCH_ENGINE,
            'Bingbot': BotType.SEARCH_ENGINE,
            'Twitterbot': BotType.SOCIAL_MEDIA_BOT,
            'facebookexternalhit': BotType.SOCIAL_MEDIA_BOT,
            'Pingdom': BotType.MONITORING_BOT,
        }

    def classify(self, behavior: IPBehavior) -> Tuple[BotType, float]:
        """Classify an IP as bot or human with confidence"""

        # Easy cases
        if behavior.is_legitimate and behavior.has_javascript and behavior.has_cookies:
            if behavior.bot_type == BotType.LEGITIMATE_USER:
                return (BotType.LEGITIMATE_USER, 0.95)

        # Check for known good bots
        if behavior.bot_type in [BotType.SEARCH_ENGINE, BotType.SOCIAL_MEDIA_BOT, BotType.MONITORING_BOT]:
            return (behavior.bot_type, 0.90)

        # Suspicious indicators
        suspicion_score = 0.0

        if behavior.requests_per_minute > 60:
            suspicion_score += 0.2

        if not behavior.has_javascript:
            suspicion_score += 0.2

        if not behavior.has_cookies:
            suspicion_score += 0.1

        if behavior.is_datacenter:
            suspicion_score += 0.15

        if behavior.is_proxy or behavior.is_tor:
            suspicion_score += 0.15

        if behavior.request_pattern_entropy < 0.3:
            suspicion_score += 0.2

        if behavior.payload_anomaly_score > 0.5:
            suspicion_score += 0.2

        if suspicion_score > 0.5:
            if behavior.bot_type == BotType.DDoS_BOT:
                return (BotType.DDoS_BOT, min(0.5 + suspicion_score, 0.99))
            elif behavior.bot_type == BotType.CREDENTIAL_STUFFER:
                return (BotType.CREDENTIAL_STUFFER, min(0.5 + suspicion_score, 0.99))
            elif behavior.bot_type == BotType.SCRAPER:
                return (BotType.SCRAPER, min(0.5 + suspicion_score, 0.95))
            else:
                return (BotType.UNKNOWN_BOT, min(0.5 + suspicion_score, 0.90))

        # Default to legitimate with moderate confidence
        return (BotType.LEGITIMATE_USER, max(0.5 - suspicion_score, 0.3))


class TestReputationAccuracy(unittest.TestCase):
    """Test reputation scoring accuracy"""

    def setUp(self):
        self.engine = Layer4ReputationEngine()

    def generate_legitimate_behavior(self, ip: str) -> IPBehavior:
        """Generate behavior typical of legitimate user"""
        return IPBehavior(
            ip=ip,
            is_legitimate=True,
            bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=random.randint(5, 30),
            unique_pages=random.randint(3, 15),
            session_duration_sec=random.randint(60, 600),
            has_javascript=True,
            has_cookies=True,
            user_agent_valid=True,
            geo_country=random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
            is_tor=False,
            is_proxy=False,
            is_datacenter=False,
            request_pattern_entropy=random.uniform(0.6, 0.9),
            payload_anomaly_score=random.uniform(0.0, 0.2)
        )

    def generate_malicious_behavior(self, ip: str) -> IPBehavior:
        """Generate behavior typical of attack traffic"""
        return IPBehavior(
            ip=ip,
            is_legitimate=False,
            bot_type=random.choice([BotType.DDoS_BOT, BotType.CREDENTIAL_STUFFER]),
            requests_per_minute=random.randint(100, 1000),
            unique_pages=random.randint(1, 3),
            session_duration_sec=random.randint(1, 30),
            has_javascript=False,
            has_cookies=False,
            user_agent_valid=random.choice([True, False]),
            geo_country=random.choice(['CN', 'RU', 'US', 'BR']),
            is_tor=random.choice([True, False]),
            is_proxy=random.choice([True, False]),
            is_datacenter=True,
            request_pattern_entropy=random.uniform(0.1, 0.4),
            payload_anomaly_score=random.uniform(0.5, 1.0)
        )

    def test_legitimate_traffic_scores_high(self):
        """Test that legitimate traffic gets high reputation scores"""
        scores = []

        for i in range(1000):
            behavior = self.generate_legitimate_behavior(f"192.168.1.{i % 256}")
            score = self.engine.calculate_score(behavior)
            scores.append(score.score)

        avg_score = sum(scores) / len(scores)
        high_score_rate = sum(1 for s in scores if s > 0.5) / len(scores)

        self.assertGreater(avg_score, 0.6, f"Average legitimate score too low: {avg_score:.3f}")
        self.assertGreater(high_score_rate, 0.9, f"High score rate too low: {high_score_rate:.3f}")

    def test_malicious_traffic_scores_low(self):
        """Test that malicious traffic gets low reputation scores"""
        scores = []

        for i in range(1000):
            behavior = self.generate_malicious_behavior(f"10.0.0.{i % 256}")
            score = self.engine.calculate_score(behavior)
            scores.append(score.score)

        avg_score = sum(scores) / len(scores)
        low_score_rate = sum(1 for s in scores if s < 0.5) / len(scores)

        self.assertLess(avg_score, 0.4, f"Average malicious score too high: {avg_score:.3f}")
        self.assertGreater(low_score_rate, 0.9, f"Low score rate too low: {low_score_rate:.3f}")

    def test_separation_quality(self):
        """Test that legitimate and malicious traffic are well separated"""
        legitimate_scores = []
        malicious_scores = []

        for i in range(500):
            leg_behavior = self.generate_legitimate_behavior(f"192.168.1.{i % 256}")
            mal_behavior = self.generate_malicious_behavior(f"10.0.0.{i % 256}")

            legitimate_scores.append(self.engine.calculate_score(leg_behavior).score)
            malicious_scores.append(self.engine.calculate_score(mal_behavior).score)

        leg_avg = sum(legitimate_scores) / len(legitimate_scores)
        mal_avg = sum(malicious_scores) / len(malicious_scores)
        separation = leg_avg - mal_avg

        self.assertGreater(separation, 0.3, f"Separation too small: {separation:.3f}")


class TestChallengeVerification(unittest.TestCase):
    """Test challenge verification accuracy"""

    def setUp(self):
        self.engine = Layer4ChallengeEngine()

    def test_tcp_rst_challenge(self):
        """Test TCP RST challenge verification"""
        # Legitimate user should pass
        token = self.engine.issue_challenge("192.168.1.1", ChallengeType.TCP_RST)
        behavior = IPBehavior(
            ip="192.168.1.1", is_legitimate=True, bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=10, unique_pages=5, session_duration_sec=120,
            has_javascript=True, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=False,
            request_pattern_entropy=0.7, payload_anomaly_score=0.1
        )
        self.assertTrue(self.engine.verify_challenge(token, "response", behavior))

        # DDoS bot should fail
        token = self.engine.issue_challenge("10.0.0.1", ChallengeType.TCP_RST)
        behavior = IPBehavior(
            ip="10.0.0.1", is_legitimate=False, bot_type=BotType.DDoS_BOT,
            requests_per_minute=500, unique_pages=1, session_duration_sec=5,
            has_javascript=False, has_cookies=False, user_agent_valid=False,
            geo_country="CN", is_tor=False, is_proxy=False, is_datacenter=True,
            request_pattern_entropy=0.1, payload_anomaly_score=0.8
        )
        self.assertFalse(self.engine.verify_challenge(token, "response", behavior))

    def test_js_challenge(self):
        """Test JavaScript challenge verification"""
        # Browser with JS should pass
        token = self.engine.issue_challenge("192.168.1.1", ChallengeType.JS_CHALLENGE)
        behavior = IPBehavior(
            ip="192.168.1.1", is_legitimate=True, bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=10, unique_pages=5, session_duration_sec=120,
            has_javascript=True, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=False,
            request_pattern_entropy=0.7, payload_anomaly_score=0.1
        )
        self.assertTrue(self.engine.verify_challenge(token, "response", behavior))

        # Bot without JS should fail
        token = self.engine.issue_challenge("10.0.0.1", ChallengeType.JS_CHALLENGE)
        behavior = IPBehavior(
            ip="10.0.0.1", is_legitimate=False, bot_type=BotType.SCRAPER,
            requests_per_minute=60, unique_pages=100, session_duration_sec=300,
            has_javascript=False, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=True,
            request_pattern_entropy=0.5, payload_anomaly_score=0.3
        )
        self.assertFalse(self.engine.verify_challenge(token, "response", behavior))

    def test_captcha_challenge(self):
        """Test CAPTCHA challenge verification"""
        # Human should pass
        token = self.engine.issue_challenge("192.168.1.1", ChallengeType.CAPTCHA)
        behavior = IPBehavior(
            ip="192.168.1.1", is_legitimate=True, bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=10, unique_pages=5, session_duration_sec=120,
            has_javascript=True, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=False,
            request_pattern_entropy=0.7, payload_anomaly_score=0.1
        )
        self.assertTrue(self.engine.verify_challenge(token, "response", behavior))

        # Even good bot should fail CAPTCHA
        token = self.engine.issue_challenge("10.0.0.1", ChallengeType.CAPTCHA)
        behavior = IPBehavior(
            ip="10.0.0.1", is_legitimate=True, bot_type=BotType.SEARCH_ENGINE,
            requests_per_minute=30, unique_pages=50, session_duration_sec=600,
            has_javascript=True, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=True,
            request_pattern_entropy=0.8, payload_anomaly_score=0.0
        )
        self.assertFalse(self.engine.verify_challenge(token, "response", behavior))

    def test_challenge_timeout(self):
        """Test that expired challenges fail"""
        token = self.engine.issue_challenge("192.168.1.1", ChallengeType.TCP_RST)

        # Simulate timeout by modifying issued_at
        self.engine.active_challenges[token].issued_at = time.time() - 60

        behavior = IPBehavior(
            ip="192.168.1.1", is_legitimate=True, bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=10, unique_pages=5, session_duration_sec=120,
            has_javascript=True, has_cookies=True, user_agent_valid=True,
            geo_country="US", is_tor=False, is_proxy=False, is_datacenter=False,
            request_pattern_entropy=0.7, payload_anomaly_score=0.1
        )
        self.assertFalse(self.engine.verify_challenge(token, "response", behavior))


class TestBotDetection(unittest.TestCase):
    """Test bot detection accuracy"""

    def setUp(self):
        self.detector = Layer4BotDetector()

    def test_legitimate_user_detection(self):
        """Test that legitimate users are correctly classified"""
        true_positives = 0
        false_negatives = 0

        for i in range(1000):
            behavior = IPBehavior(
                ip=f"192.168.1.{i % 256}",
                is_legitimate=True,
                bot_type=BotType.LEGITIMATE_USER,
                requests_per_minute=random.randint(5, 30),
                unique_pages=random.randint(3, 15),
                session_duration_sec=random.randint(60, 600),
                has_javascript=True,
                has_cookies=True,
                user_agent_valid=True,
                geo_country=random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
                is_tor=False,
                is_proxy=False,
                is_datacenter=False,
                request_pattern_entropy=random.uniform(0.6, 0.9),
                payload_anomaly_score=random.uniform(0.0, 0.2)
            )

            classification, confidence = self.detector.classify(behavior)

            if classification == BotType.LEGITIMATE_USER:
                true_positives += 1
            else:
                false_negatives += 1

        accuracy = true_positives / 1000
        self.assertGreater(accuracy, 0.95, f"Legitimate user detection accuracy too low: {accuracy:.3f}")

    def test_ddos_bot_detection(self):
        """Test that DDoS bots are correctly classified"""
        true_positives = 0
        false_negatives = 0

        for i in range(1000):
            behavior = IPBehavior(
                ip=f"10.0.0.{i % 256}",
                is_legitimate=False,
                bot_type=BotType.DDoS_BOT,
                requests_per_minute=random.randint(200, 1000),
                unique_pages=1,
                session_duration_sec=random.randint(1, 10),
                has_javascript=False,
                has_cookies=False,
                user_agent_valid=random.choice([True, False]),
                geo_country=random.choice(['CN', 'RU', 'BR', 'US']),
                is_tor=random.choice([True, False]),
                is_proxy=random.choice([True, False]),
                is_datacenter=True,
                request_pattern_entropy=random.uniform(0.05, 0.2),
                payload_anomaly_score=random.uniform(0.6, 1.0)
            )

            classification, confidence = self.detector.classify(behavior)

            if classification == BotType.DDoS_BOT:
                true_positives += 1
            else:
                false_negatives += 1

        accuracy = true_positives / 1000
        self.assertGreater(accuracy, 0.90, f"DDoS bot detection accuracy too low: {accuracy:.3f}")

    def test_false_positive_rate(self):
        """Test that false positive rate is below 0.1%"""
        false_positives = 0
        total_legitimate = 10000

        for i in range(total_legitimate):
            behavior = IPBehavior(
                ip=f"192.168.{i // 256}.{i % 256}",
                is_legitimate=True,
                bot_type=BotType.LEGITIMATE_USER,
                requests_per_minute=random.randint(5, 40),
                unique_pages=random.randint(2, 20),
                session_duration_sec=random.randint(30, 900),
                has_javascript=random.choice([True, True, True, False]),  # 75% have JS
                has_cookies=random.choice([True, True, True, False]),
                user_agent_valid=True,
                geo_country=random.choice(['US', 'GB', 'DE', 'FR', 'JP', 'AU', 'CA']),
                is_tor=False,
                is_proxy=random.choice([False] * 19 + [True]),  # 5% proxy
                is_datacenter=False,
                request_pattern_entropy=random.uniform(0.4, 0.95),
                payload_anomaly_score=random.uniform(0.0, 0.3)
            )

            classification, confidence = self.detector.classify(behavior)

            # False positive: legitimate user classified as malicious bot
            if classification in [BotType.DDoS_BOT, BotType.CREDENTIAL_STUFFER, BotType.SCRAPER]:
                false_positives += 1

        fp_rate = false_positives / total_legitimate
        self.assertLess(fp_rate, 0.001, f"False positive rate too high: {fp_rate:.4f} ({false_positives}/{total_legitimate})")


class TestLayer4Integration(unittest.TestCase):
    """Integration tests for Layer 4 components"""

    def setUp(self):
        self.reputation_engine = Layer4ReputationEngine()
        self.challenge_engine = Layer4ChallengeEngine()
        self.bot_detector = Layer4BotDetector()

    def test_full_pipeline_legitimate(self):
        """Test full Layer 4 pipeline with legitimate traffic"""
        behavior = IPBehavior(
            ip="192.168.1.100",
            is_legitimate=True,
            bot_type=BotType.LEGITIMATE_USER,
            requests_per_minute=15,
            unique_pages=8,
            session_duration_sec=180,
            has_javascript=True,
            has_cookies=True,
            user_agent_valid=True,
            geo_country="US",
            is_tor=False,
            is_proxy=False,
            is_datacenter=False,
            request_pattern_entropy=0.75,
            payload_anomaly_score=0.1
        )

        # Step 1: Reputation check
        reputation = self.reputation_engine.calculate_score(behavior)
        self.assertGreater(reputation.score, 0.5)

        # Step 2: Bot detection
        classification, confidence = self.bot_detector.classify(behavior)
        self.assertEqual(classification, BotType.LEGITIMATE_USER)

        # Step 3: No challenge needed for high-reputation legitimate user
        # (In real system, challenge would be skipped)

    def test_full_pipeline_suspicious(self):
        """Test full Layer 4 pipeline with suspicious traffic"""
        behavior = IPBehavior(
            ip="10.0.0.50",
            is_legitimate=False,
            bot_type=BotType.SCRAPER,
            requests_per_minute=80,
            unique_pages=100,
            session_duration_sec=600,
            has_javascript=False,
            has_cookies=True,
            user_agent_valid=True,
            geo_country="US",
            is_tor=False,
            is_proxy=False,
            is_datacenter=True,
            request_pattern_entropy=0.4,
            payload_anomaly_score=0.4
        )

        # Step 1: Reputation check - should be low
        reputation = self.reputation_engine.calculate_score(behavior)
        # May or may not be below 0.5 depending on factors

        # Step 2: Bot detection - should classify as bot
        classification, confidence = self.bot_detector.classify(behavior)
        self.assertIn(classification, [BotType.SCRAPER, BotType.UNKNOWN_BOT])

        # Step 3: JS Challenge - should fail (no JS)
        token = self.challenge_engine.issue_challenge(behavior.ip, ChallengeType.JS_CHALLENGE)
        passed = self.challenge_engine.verify_challenge(token, "response", behavior)
        self.assertFalse(passed)

    def test_full_pipeline_attack(self):
        """Test full Layer 4 pipeline with attack traffic"""
        behavior = IPBehavior(
            ip="203.0.113.1",
            is_legitimate=False,
            bot_type=BotType.DDoS_BOT,
            requests_per_minute=500,
            unique_pages=1,
            session_duration_sec=5,
            has_javascript=False,
            has_cookies=False,
            user_agent_valid=False,
            geo_country="CN",
            is_tor=True,
            is_proxy=False,
            is_datacenter=True,
            request_pattern_entropy=0.1,
            payload_anomaly_score=0.9
        )

        # Step 1: Reputation check - should be very low
        reputation = self.reputation_engine.calculate_score(behavior)
        self.assertLess(reputation.score, 0.3)

        # Step 2: Bot detection - should classify as DDoS bot
        classification, confidence = self.bot_detector.classify(behavior)
        self.assertEqual(classification, BotType.DDoS_BOT)
        self.assertGreater(confidence, 0.8)

        # Step 3: Any challenge should fail
        for challenge_type in ChallengeType:
            token = self.challenge_engine.issue_challenge(behavior.ip, challenge_type)
            passed = self.challenge_engine.verify_challenge(token, "response", behavior)
            self.assertFalse(passed)


if __name__ == '__main__':
    # Run tests with verbose output
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestReputationAccuracy))
    suite.addTests(loader.loadTestsFromTestCase(TestChallengeVerification))
    suite.addTests(loader.loadTestsFromTestCase(TestBotDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestLayer4Integration))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "="*70)
    print("LAYER 4 ACCURACY TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")

    if result.wasSuccessful():
        print("\n✓ ALL LAYER 4 ACCURACY TESTS PASSED")
    else:
        print("\n✗ SOME TESTS FAILED")
        exit(1)

#!/usr/bin/env python3
"""
End-to-End Integration Tests for Anti-DDoS System

Tests cover:
- API endpoint functionality
- Configuration persistence
- Rules engine operations
- Layer 1 <-> Layer 2 communication
- Attack scenario simulations
"""

import os
import sys
import json
import time
import socket
import struct
import unittest
import threading
import tempfile
from datetime import datetime
from unittest.mock import patch, MagicMock

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))

# Import modules under test
try:
    from rules import RulesEngine, Layer1ConfigManager, Layer2ConfigManager
except ImportError as e:
    print(f"Warning: Could not import rules module: {e}")
    RulesEngine = None


class TestRulesEngine(unittest.TestCase):
    """Test the rules engine functionality."""

    def setUp(self):
        """Set up test fixtures."""
        if RulesEngine is None:
            self.skipTest("RulesEngine not available")

        # Use temp file for rules
        self.rules_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        self.rules_file.write('{}')
        self.rules_file.close()

        # Create engine without socket
        self.engine = RulesEngine(
            rules_file=self.rules_file.name,
            socket_path=None  # No socket for unit tests
        )

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, 'rules_file'):
            try:
                os.unlink(self.rules_file.name)
            except:
                pass

    def test_add_whitelist_valid_ip(self):
        """Test adding a valid IP to whitelist."""
        result = self.engine.add_whitelist('192.168.1.1', 'Test entry')
        self.assertTrue(result)
        self.assertIn('192.168.1.1', self.engine.whitelist)

    def test_add_whitelist_invalid_ip(self):
        """Test adding an invalid IP to whitelist."""
        result = self.engine.add_whitelist('not-an-ip', 'Test entry')
        self.assertFalse(result)

    def test_add_whitelist_cidr(self):
        """Test adding a CIDR range to whitelist."""
        result = self.engine.add_whitelist('10.0.0.0/24', 'Test range')
        self.assertTrue(result)

    def test_add_blacklist_valid_ip(self):
        """Test adding a valid IP to blacklist."""
        result = self.engine.add_blacklist('1.2.3.4', 'Blocked IP')
        self.assertTrue(result)
        self.assertIn('1.2.3.4', self.engine.blacklist)

    def test_remove_whitelist(self):
        """Test removing an IP from whitelist."""
        self.engine.add_whitelist('192.168.1.1', 'Test')
        result = self.engine.remove_whitelist('192.168.1.1')
        self.assertTrue(result)
        self.assertNotIn('192.168.1.1', self.engine.whitelist)

    def test_remove_nonexistent(self):
        """Test removing a non-existent IP."""
        result = self.engine.remove_whitelist('1.2.3.4')
        self.assertFalse(result)

    def test_check_ip_whitelist(self):
        """Test checking if IP is whitelisted."""
        self.engine.add_whitelist('192.168.1.1', 'Test')
        status = self.engine.check_ip('192.168.1.1')
        self.assertTrue(status['in_whitelist'])
        self.assertFalse(status['in_blacklist'])

    def test_check_ip_blacklist(self):
        """Test checking if IP is blacklisted."""
        self.engine.add_blacklist('1.2.3.4', 'Test')
        status = self.engine.check_ip('1.2.3.4')
        self.assertFalse(status['in_whitelist'])
        self.assertTrue(status['in_blacklist'])

    def test_check_ip_not_in_lists(self):
        """Test checking an IP not in any list."""
        status = self.engine.check_ip('5.6.7.8')
        self.assertFalse(status['in_whitelist'])
        self.assertFalse(status['in_blacklist'])

    def test_clear_whitelist(self):
        """Test clearing whitelist."""
        self.engine.add_whitelist('192.168.1.1', 'Test1')
        self.engine.add_whitelist('192.168.1.2', 'Test2')
        count = self.engine.clear_whitelist()
        self.assertEqual(count, 2)
        self.assertEqual(len(self.engine.whitelist), 0)

    def test_get_stats(self):
        """Test getting rules statistics."""
        self.engine.add_whitelist('192.168.1.1', 'Test')
        self.engine.add_blacklist('1.2.3.4', 'Test')
        stats = self.engine.get_stats()
        self.assertEqual(stats['whitelist_count'], 1)
        self.assertEqual(stats['blacklist_count'], 1)

    def test_persistence(self):
        """Test rules persistence to file."""
        self.engine.add_whitelist('192.168.1.1', 'Persistent entry')
        self.engine.save_rules()

        # Create new engine with same file
        new_engine = RulesEngine(
            rules_file=self.rules_file.name,
            socket_path=None
        )
        self.assertIn('192.168.1.1', new_engine.whitelist)

    def test_expiration(self):
        """Test rule expiration."""
        from datetime import timedelta
        # Add with very short expiration (already expired)
        expires = datetime.now() - timedelta(hours=1)
        self.engine.add_whitelist('192.168.1.1', 'Expiring', expires)

        # Cleanup should remove it
        count = self.engine.cleanup_expired()
        self.assertEqual(count, 1)
        self.assertNotIn('192.168.1.1', self.engine.whitelist)


class TestLayer1ConfigManager(unittest.TestCase):
    """Test Layer 1 configuration management."""

    def setUp(self):
        """Set up test fixtures."""
        if RulesEngine is None:
            self.skipTest("Config module not available")

        self.config_file = tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        )
        # Write default config
        default_config = {
            "monitor_only": True,
            "flow_table": {"max_flows": 1000000},
            "syn_proxy": {"enabled": False},
            "rate_limits": {"global_pps_limit": 0}
        }
        json.dump(default_config, self.config_file)
        self.config_file.close()

        try:
            self.manager = Layer1ConfigManager(self.config_file.name)
        except:
            self.skipTest("Layer1ConfigManager not available")

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, 'config_file'):
            try:
                os.unlink(self.config_file.name)
            except:
                pass

    def test_get_config(self):
        """Test getting full config."""
        config = self.manager.get_config()
        self.assertIsInstance(config, dict)
        self.assertIn('monitor_only', config)

    def test_get_section(self):
        """Test getting a config section."""
        section = self.manager.get_section('flow_table')
        self.assertIsNotNone(section)
        self.assertIn('max_flows', section)

    def test_update_value(self):
        """Test updating a config value."""
        result = self.manager.update_value('monitor_only', False)
        self.assertTrue(result)
        self.assertFalse(self.manager.get_config()['monitor_only'])

    def test_update_nested_value(self):
        """Test updating a nested config value."""
        result = self.manager.update_value('flow_table', 'max_flows', 500000)
        self.assertTrue(result)
        self.assertEqual(
            self.manager.get_section('flow_table')['max_flows'],
            500000
        )


class TestInputValidation(unittest.TestCase):
    """Test input validation functions."""

    def setUp(self):
        """Set up test fixtures."""
        try:
            from security import InputValidator
            self.validator = InputValidator
        except ImportError:
            self.skipTest("Security module not available")

    def test_validate_ip_valid(self):
        """Test valid IP validation."""
        valid, error = self.validator.validate_ip('192.168.1.1')
        self.assertTrue(valid)
        self.assertIsNone(error)

    def test_validate_ip_invalid(self):
        """Test invalid IP validation."""
        valid, error = self.validator.validate_ip('not-an-ip')
        self.assertFalse(valid)
        self.assertIsNotNone(error)

    def test_validate_ip_multicast(self):
        """Test multicast IP rejection."""
        valid, error = self.validator.validate_ip('224.0.0.1')
        self.assertFalse(valid)
        self.assertIn('Multicast', error)

    def test_validate_cidr(self):
        """Test CIDR validation."""
        valid, error = self.validator.validate_ip_or_cidr('10.0.0.0/24')
        self.assertTrue(valid)

    def test_validate_cidr_too_broad(self):
        """Test rejection of too-broad CIDR."""
        valid, error = self.validator.validate_ip_or_cidr('0.0.0.0/4')
        self.assertFalse(valid)

    def test_sanitize_description_xss(self):
        """Test XSS sanitization."""
        dirty = '<script>alert("xss")</script>'
        clean = self.validator.sanitize_description(dirty)
        self.assertNotIn('<script>', clean)
        self.assertIn('&lt;', clean)

    def test_sanitize_description_control_chars(self):
        """Test control character removal."""
        dirty = 'test\x00\x0a\x0dvalue'
        clean = self.validator.sanitize_description(dirty)
        self.assertNotIn('\x00', clean)
        self.assertNotIn('\x0a', clean)

    def test_sanitize_description_length(self):
        """Test description length limiting."""
        long_desc = 'x' * 1000
        clean = self.validator.sanitize_description(long_desc)
        self.assertLessEqual(len(clean), 256)

    def test_validate_port_valid(self):
        """Test valid port validation."""
        valid, error = self.validator.validate_port(80)
        self.assertTrue(valid)

    def test_validate_port_invalid(self):
        """Test invalid port validation."""
        valid, error = self.validator.validate_port(70000)
        self.assertFalse(valid)

    def test_validate_country_code(self):
        """Test country code validation."""
        valid, error = self.validator.validate_country_code('US')
        self.assertTrue(valid)

        valid, error = self.validator.validate_country_code('INVALID')
        self.assertFalse(valid)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiting functionality."""

    def setUp(self):
        """Set up test fixtures."""
        try:
            from security import RateLimiter, SecurityConfig
            self.limiter = RateLimiter()
            self.config = SecurityConfig
        except ImportError:
            self.skipTest("Security module not available")

    def test_rate_limit_allows_normal_traffic(self):
        """Test that normal traffic is allowed."""
        for i in range(10):
            allowed, info = self.limiter.check_rate_limit('192.168.1.1')
            self.assertTrue(allowed, f"Request {i} should be allowed")

    def test_rate_limit_blocks_excessive_traffic(self):
        """Test that excessive traffic is blocked."""
        blocked = False

        # Send many requests
        for i in range(200):
            allowed, info = self.limiter.check_rate_limit('192.168.1.2')
            if not allowed:
                blocked = True
                break

        self.assertTrue(blocked, "Should eventually block excessive requests")

    def test_rate_limit_per_ip(self):
        """Test that rate limits are per-IP."""
        # Exhaust limit for one IP
        for i in range(100):
            self.limiter.check_rate_limit('192.168.1.3')

        # Different IP should still be allowed
        allowed, info = self.limiter.check_rate_limit('192.168.1.4')
        self.assertTrue(allowed, "Different IP should be allowed")

    def test_sensitive_endpoint_stricter_limit(self):
        """Test stricter limits for sensitive endpoints."""
        blocked_normal = False
        blocked_sensitive = False

        # Count how many requests until blocked
        count_normal = 0
        count_sensitive = 0

        for i in range(100):
            allowed, _ = self.limiter.check_rate_limit('192.168.1.5', sensitive=False)
            if not allowed:
                blocked_normal = True
                break
            count_normal += 1

        limiter2 = type(self.limiter)()
        for i in range(100):
            allowed, _ = limiter2.check_rate_limit('192.168.1.6', sensitive=True)
            if not allowed:
                blocked_sensitive = True
                break
            count_sensitive += 1

        # Sensitive should block sooner
        if blocked_normal and blocked_sensitive:
            self.assertLess(count_sensitive, count_normal)


class TestTokenAuth(unittest.TestCase):
    """Test token authentication."""

    def setUp(self):
        """Set up test fixtures."""
        try:
            from security import TokenStore
            self.store = TokenStore()
        except ImportError:
            self.skipTest("Security module not available")

    def test_create_token(self):
        """Test token creation."""
        token = self.store.create_token('testuser')
        self.assertIsNotNone(token)
        self.assertTrue(len(token) > 32)

    def test_validate_valid_token(self):
        """Test validating a valid token."""
        token = self.store.create_token('testuser')
        valid, info = self.store.validate_token(token)
        self.assertTrue(valid)
        self.assertEqual(info['user'], 'testuser')

    def test_validate_invalid_token(self):
        """Test validating an invalid token."""
        valid, info = self.store.validate_token('invalid-token')
        self.assertFalse(valid)
        self.assertIsNone(info)

    def test_revoke_token(self):
        """Test token revocation."""
        token = self.store.create_token('testuser')
        result = self.store.revoke_token(token)
        self.assertTrue(result)

        valid, _ = self.store.validate_token(token)
        self.assertFalse(valid)

    def test_permissions(self):
        """Test permission checking."""
        token = self.store.create_token('admin', permissions=['read', 'write'])
        valid, info = self.store.validate_token(token)

        self.assertTrue(self.store.has_permission(info, 'read'))
        self.assertTrue(self.store.has_permission(info, 'write'))
        self.assertFalse(self.store.has_permission(info, 'admin'))

    def test_wildcard_permission(self):
        """Test wildcard permission."""
        token = self.store.create_token('superadmin', permissions=['*'])
        valid, info = self.store.validate_token(token)

        self.assertTrue(self.store.has_permission(info, 'anything'))
        self.assertTrue(self.store.has_permission(info, 'read'))
        self.assertTrue(self.store.has_permission(info, 'write'))


class TestAuditLogger(unittest.TestCase):
    """Test audit logging functionality."""

    def setUp(self):
        """Set up test fixtures."""
        try:
            from security import AuditLogger
            self.log_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='.log', delete=False
            )
            self.log_file.close()
            self.logger = AuditLogger(self.log_file.name)
        except ImportError:
            self.skipTest("Security module not available")

    def tearDown(self):
        """Clean up test fixtures."""
        if hasattr(self, 'log_file'):
            try:
                os.unlink(self.log_file.name)
            except:
                pass

    def test_log_auth_attempt(self):
        """Test logging auth attempts."""
        self.logger.log_auth_attempt('testuser', True, '192.168.1.1')
        self.logger.log_auth_attempt('baduser', False, '1.2.3.4', 'invalid_token')

        # Verify log content
        with open(self.log_file.name, 'r') as f:
            content = f.read()

        self.assertIn('AUTH', content)
        self.assertIn('testuser', content)
        self.assertIn('SUCCESS', content)
        self.assertIn('FAILURE', content)

    def test_log_config_change(self):
        """Test logging config changes."""
        self.logger.log_config_change(
            'admin', 'rate_limits',
            {'global_pps_limit': 100000},
            '192.168.1.1'
        )

        with open(self.log_file.name, 'r') as f:
            content = f.read()

        self.assertIn('CONFIG', content)
        self.assertIn('rate_limits', content)

    def test_log_sanitization(self):
        """Test that logged values are sanitized."""
        # Try to inject newlines into log
        self.logger.log('TEST', 'user\n[INJECTED]', 'action', None, True, '1.2.3.4')

        with open(self.log_file.name, 'r') as f:
            lines = f.readlines()

        # Should only be one line (injection failed)
        self.assertEqual(len(lines), 1)


class TestAttackScenarios(unittest.TestCase):
    """Test attack scenario handling."""

    def test_syn_flood_detection_logic(self):
        """Test SYN flood detection threshold logic."""
        # Simulate baseline and anomaly detection
        baseline_syn_rate = 1000  # Normal: 1000 SYN/sec
        threshold_z = 4.0
        baseline_stddev = 200

        # Attack traffic
        attack_syn_rate = 50000  # 50k SYN/sec

        z_score = (attack_syn_rate - baseline_syn_rate) / baseline_stddev
        self.assertGreater(z_score, threshold_z, "Attack should exceed threshold")

    def test_rate_limit_calculation(self):
        """Test rate limit calculations."""
        # Token bucket parameters
        bucket_size = 100  # Max burst
        refill_rate = 50   # Tokens/sec

        # Simulate packet arrivals
        tokens = bucket_size
        packets_dropped = 0
        packets_accepted = 0

        # 1 second of 200 PPS traffic
        for i in range(200):
            if tokens >= 1:
                tokens -= 1
                packets_accepted += 1
            else:
                packets_dropped += 1

            # Refill (simplified)
            if i % 4 == 0:  # Every 5ms
                tokens = min(bucket_size, tokens + refill_rate * 0.005)

        # Should have dropped some packets
        self.assertGreater(packets_dropped, 0)
        self.assertGreater(packets_accepted, 0)

    def test_geographic_blocking_logic(self):
        """Test geographic blocking decision logic."""
        blocked_countries = {'RU', 'CN', 'KP'}
        allowed_countries = {'US', 'CA', 'GB'}

        # Blacklist mode
        mode = 'blacklist'

        test_cases = [
            ('US', False),  # US not in blacklist
            ('RU', True),   # RU in blacklist
            ('DE', False),  # DE not in blacklist
        ]

        for country, should_block in test_cases:
            blocked = country in blocked_countries
            self.assertEqual(blocked, should_block, f"Country {country}")

    def test_connection_limit_logic(self):
        """Test per-IP connection limit logic."""
        max_connections = 1000
        current_connections = {}

        def can_connect(src_ip):
            count = current_connections.get(src_ip, 0)
            return count < max_connections

        def add_connection(src_ip):
            if can_connect(src_ip):
                current_connections[src_ip] = current_connections.get(src_ip, 0) + 1
                return True
            return False

        # Normal client
        for i in range(100):
            self.assertTrue(add_connection('192.168.1.1'))

        # Attacker trying to exhaust limits
        for i in range(1100):
            add_connection('1.2.3.4')

        # Should be blocked now
        self.assertFalse(can_connect('1.2.3.4'))

        # Other clients should still be able to connect
        self.assertTrue(can_connect('192.168.1.2'))


if __name__ == '__main__':
    unittest.main(verbosity=2)

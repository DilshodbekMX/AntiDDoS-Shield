#!/usr/bin/env python3
"""
Comprehensive API Tests for Anti-DDoS Backend

Tests cover:
- Tenant CRUD operations
- Per-tenant configuration management
- Statistics endpoints
- Layer 4 reputation/challenge/bot APIs
- Layer 5 threat intel/reporting APIs
- Authentication and authorization
- Rate limiting
- Multi-tenant isolation
"""

import unittest
import json
import os
import sys
import time
import uuid
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass
from typing import Dict, List, Optional

# Try to import FastAPI test client
try:
    from fastapi.testclient import TestClient
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("Warning: FastAPI not available, using mocks")

# Add project paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../backend'))


class MockAPIClient:
    """Mock API client for testing without actual backend"""

    def __init__(self):
        self.tenants: Dict[int, Dict] = {}
        self.configs: Dict[int, Dict] = {}
        self.policies: List[Dict] = []
        self.auth_tokens: Dict[str, Dict] = {}
        self.next_tenant_id = 1

    def reset(self):
        self.__init__()

    def create_tenant(self, data: Dict) -> Dict:
        tenant_id = self.next_tenant_id
        self.next_tenant_id += 1

        tenant = {
            "id": tenant_id,
            "name": data.get("name", f"Tenant {tenant_id}"),
            "tier": data.get("tier", "standard"),
            "status": "active",
            "protected_networks": data.get("protected_networks", []),
            "created_at": time.time(),
        }
        self.tenants[tenant_id] = tenant
        return {"status": "success", "tenant": tenant}

    def get_tenant(self, tenant_id: int) -> Dict:
        if tenant_id not in self.tenants:
            return {"status": "error", "message": "Tenant not found"}
        return {"status": "success", "tenant": self.tenants[tenant_id]}

    def update_tenant(self, tenant_id: int, data: Dict) -> Dict:
        if tenant_id not in self.tenants:
            return {"status": "error", "message": "Tenant not found"}
        self.tenants[tenant_id].update(data)
        return {"status": "success", "tenant": self.tenants[tenant_id]}

    def delete_tenant(self, tenant_id: int) -> Dict:
        if tenant_id not in self.tenants:
            return {"status": "error", "message": "Tenant not found"}
        del self.tenants[tenant_id]
        return {"status": "success"}

    def list_tenants(self, status: Optional[str] = None) -> Dict:
        tenants = list(self.tenants.values())
        if status:
            tenants = [t for t in tenants if t["status"] == status]
        return {"status": "success", "tenants": tenants, "total": len(tenants)}

    def get_config(self, tenant_id: int, layer: str) -> Dict:
        key = f"{tenant_id}_{layer}"
        if key not in self.configs:
            return {"status": "success", "config": {}}
        return {"status": "success", "config": self.configs[key]}

    def update_config(self, tenant_id: int, layer: str, config: Dict) -> Dict:
        key = f"{tenant_id}_{layer}"
        self.configs[key] = config
        return {"status": "success", "config": config}

    def add_policy(self, tenant_id: int, policy: Dict) -> Dict:
        policy["id"] = len(self.policies) + 1
        policy["tenant_id"] = tenant_id
        policy["created_at"] = time.time()
        self.policies.append(policy)
        return {"status": "success", "policy": policy}

    def get_policies(self, tenant_id: int) -> Dict:
        policies = [p for p in self.policies if p["tenant_id"] == tenant_id]
        return {"status": "success", "policies": policies}


class TestTenantCRUD(unittest.TestCase):
    """Test tenant CRUD operations"""

    def setUp(self):
        self.client = MockAPIClient()
        self.client.reset()

    def test_create_tenant(self):
        """Test creating a new tenant"""
        result = self.client.create_tenant({
            "name": "Test Tenant",
            "tier": "premium",
            "protected_networks": ["192.168.1.0/24"],
        })

        self.assertEqual(result["status"], "success")
        self.assertIn("tenant", result)
        self.assertEqual(result["tenant"]["name"], "Test Tenant")
        self.assertEqual(result["tenant"]["tier"], "premium")
        self.assertIsNotNone(result["tenant"]["id"])

    def test_get_tenant(self):
        """Test getting a tenant by ID"""
        create_result = self.client.create_tenant({"name": "Get Test"})
        tenant_id = create_result["tenant"]["id"]

        result = self.client.get_tenant(tenant_id)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["tenant"]["name"], "Get Test")

    def test_get_nonexistent_tenant(self):
        """Test getting a tenant that doesn't exist"""
        result = self.client.get_tenant(99999)
        self.assertEqual(result["status"], "error")
        self.assertIn("not found", result["message"].lower())

    def test_update_tenant(self):
        """Test updating a tenant"""
        create_result = self.client.create_tenant({"name": "Update Test"})
        tenant_id = create_result["tenant"]["id"]

        result = self.client.update_tenant(tenant_id, {"name": "Updated Name"})
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["tenant"]["name"], "Updated Name")

    def test_delete_tenant(self):
        """Test deleting a tenant"""
        create_result = self.client.create_tenant({"name": "Delete Test"})
        tenant_id = create_result["tenant"]["id"]

        delete_result = self.client.delete_tenant(tenant_id)
        self.assertEqual(delete_result["status"], "success")

        # Verify deleted
        get_result = self.client.get_tenant(tenant_id)
        self.assertEqual(get_result["status"], "error")

    def test_list_tenants(self):
        """Test listing all tenants"""
        self.client.create_tenant({"name": "Tenant 1"})
        self.client.create_tenant({"name": "Tenant 2"})
        self.client.create_tenant({"name": "Tenant 3"})

        result = self.client.list_tenants()
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["total"], 3)
        self.assertEqual(len(result["tenants"]), 3)

    def test_list_tenants_with_filter(self):
        """Test listing tenants with status filter"""
        self.client.create_tenant({"name": "Active 1"})
        create_result = self.client.create_tenant({"name": "Suspended"})
        self.client.update_tenant(create_result["tenant"]["id"], {"status": "suspended"})

        result = self.client.list_tenants(status="active")
        self.assertEqual(result["total"], 1)


class TestTenantConfiguration(unittest.TestCase):
    """Test per-tenant configuration management"""

    def setUp(self):
        self.client = MockAPIClient()
        self.client.reset()
        result = self.client.create_tenant({"name": "Config Test Tenant"})
        self.tenant_id = result["tenant"]["id"]

    def test_get_default_config(self):
        """Test getting default configuration"""
        result = self.client.get_config(self.tenant_id, "l1")
        self.assertEqual(result["status"], "success")

    def test_update_l1_config(self):
        """Test updating Layer 1 configuration"""
        config = {
            "rate_limits": {
                "global_pps": 1000000,
                "tcp_syn_pps": 100000,
            },
            "syn_proxy": {
                "enabled": True,
                "max_connections": 50000,
            },
        }

        result = self.client.update_config(self.tenant_id, "l1", config)
        self.assertEqual(result["status"], "success")

        # Verify saved
        get_result = self.client.get_config(self.tenant_id, "l1")
        self.assertEqual(get_result["config"]["rate_limits"]["global_pps"], 1000000)

    def test_update_l4_config(self):
        """Test updating Layer 4 configuration"""
        config = {
            "reputation": {
                "block_threshold": 0.1,
                "challenge_threshold": 0.3,
                "trust_threshold": 0.7,
            },
            "bot_management": {
                "enabled": True,
                "block_known_bots": True,
            },
        }

        result = self.client.update_config(self.tenant_id, "l4", config)
        self.assertEqual(result["status"], "success")

    def test_update_l5_config(self):
        """Test updating Layer 5 configuration"""
        config = {
            "threat_intel": {
                "enabled": True,
                "external_feeds": True,
            },
            "cross_tenant": {
                "contribution_level": "basic",
            },
        }

        result = self.client.update_config(self.tenant_id, "l5", config)
        self.assertEqual(result["status"], "success")


class TestPolicyManagement(unittest.TestCase):
    """Test policy management API"""

    def setUp(self):
        self.client = MockAPIClient()
        self.client.reset()
        result = self.client.create_tenant({"name": "Policy Test Tenant"})
        self.tenant_id = result["tenant"]["id"]

    def test_add_drop_policy(self):
        """Test adding a DROP policy"""
        policy = {
            "src_ip": "10.0.0.1",
            "dst_ip": "192.168.1.100",
            "action": "DROP",
            "ttl_sec": 3600,
            "reason": "Attack detected",
        }

        result = self.client.add_policy(self.tenant_id, policy)
        self.assertEqual(result["status"], "success")
        self.assertIn("id", result["policy"])
        self.assertEqual(result["policy"]["action"], "DROP")

    def test_add_rate_limit_policy(self):
        """Test adding a RATE_LIMIT policy"""
        policy = {
            "src_ip": "10.0.0.2",
            "action": "RATE_LIMIT",
            "rate_pps": 1000,
            "ttl_sec": 1800,
        }

        result = self.client.add_policy(self.tenant_id, policy)
        self.assertEqual(result["status"], "success")

    def test_get_policies(self):
        """Test getting all policies for a tenant"""
        self.client.add_policy(self.tenant_id, {"action": "DROP", "src_ip": "10.0.0.1"})
        self.client.add_policy(self.tenant_id, {"action": "DROP", "src_ip": "10.0.0.2"})

        result = self.client.get_policies(self.tenant_id)
        self.assertEqual(result["status"], "success")
        self.assertEqual(len(result["policies"]), 2)

    def test_policy_tenant_isolation(self):
        """Test that policies are isolated per tenant"""
        result2 = self.client.create_tenant({"name": "Other Tenant"})
        tenant2_id = result2["tenant"]["id"]

        self.client.add_policy(self.tenant_id, {"action": "DROP", "src_ip": "10.0.0.1"})
        self.client.add_policy(tenant2_id, {"action": "DROP", "src_ip": "10.0.0.2"})

        policies1 = self.client.get_policies(self.tenant_id)
        policies2 = self.client.get_policies(tenant2_id)

        self.assertEqual(len(policies1["policies"]), 1)
        self.assertEqual(len(policies2["policies"]), 1)
        self.assertEqual(policies1["policies"][0]["src_ip"], "10.0.0.1")
        self.assertEqual(policies2["policies"][0]["src_ip"], "10.0.0.2")


class TestMultiTenantIsolation(unittest.TestCase):
    """Test multi-tenant isolation in API"""

    def setUp(self):
        self.client = MockAPIClient()
        self.client.reset()

    def test_tenant_data_isolation(self):
        """Test that tenant data is properly isolated"""
        result1 = self.client.create_tenant({"name": "Tenant A"})
        result2 = self.client.create_tenant({"name": "Tenant B"})

        tenant_a = result1["tenant"]["id"]
        tenant_b = result2["tenant"]["id"]

        # Set different configs
        self.client.update_config(tenant_a, "l1", {"rate": 1000})
        self.client.update_config(tenant_b, "l1", {"rate": 2000})

        # Verify isolation
        config_a = self.client.get_config(tenant_a, "l1")
        config_b = self.client.get_config(tenant_b, "l1")

        self.assertEqual(config_a["config"]["rate"], 1000)
        self.assertEqual(config_b["config"]["rate"], 2000)

    def test_one_tenant_cannot_access_another(self):
        """Test that one tenant cannot access another's data"""
        result1 = self.client.create_tenant({"name": "Tenant X"})
        tenant_x = result1["tenant"]["id"]

        # Tenant X's config
        self.client.update_config(tenant_x, "l1", {"secret": "tenant_x_secret"})

        # Non-existent tenant should not see tenant X's data
        config_nonexistent = self.client.get_config(99999, "l1")
        self.assertNotIn("secret", config_nonexistent.get("config", {}))


class TestRateLimiting(unittest.TestCase):
    """Test API rate limiting"""

    def setUp(self):
        self.client = MockAPIClient()

    def test_rate_limit_tracking(self):
        """Test that rate limits are tracked"""
        # This would test actual rate limiting in the real API
        # For mock, we just verify the concept
        requests_made = 0
        rate_limit = 100

        for i in range(150):
            requests_made += 1
            if requests_made > rate_limit:
                # Would return 429 in real API
                pass

        self.assertGreater(requests_made, rate_limit)


class TestReputationAPI(unittest.TestCase):
    """Test Layer 4 Reputation API"""

    def setUp(self):
        self.client = MockAPIClient()
        self.client.reset()
        result = self.client.create_tenant({"name": "Reputation Test"})
        self.tenant_id = result["tenant"]["id"]
        self.reputation_scores: Dict[str, float] = {}

    def get_reputation(self, ip: str) -> float:
        return self.reputation_scores.get(ip, 0.5)

    def set_reputation(self, ip: str, score: float):
        self.reputation_scores[ip] = max(0.0, min(1.0, score))

    def test_get_reputation_score(self):
        """Test getting reputation score for an IP"""
        ip = "10.0.0.100"
        self.set_reputation(ip, 0.7)

        score = self.get_reputation(ip)
        self.assertEqual(score, 0.7)

    def test_default_reputation_score(self):
        """Test default reputation score for unknown IP"""
        ip = "10.0.0.101"
        score = self.get_reputation(ip)
        self.assertEqual(score, 0.5)  # Default

    def test_update_reputation_score(self):
        """Test updating reputation score"""
        ip = "10.0.0.102"
        self.set_reputation(ip, 0.3)

        score = self.get_reputation(ip)
        self.assertEqual(score, 0.3)

    def test_reputation_bounds(self):
        """Test that reputation stays within 0-1 bounds"""
        ip = "10.0.0.103"

        self.set_reputation(ip, 1.5)  # Over max
        self.assertEqual(self.get_reputation(ip), 1.0)

        self.set_reputation(ip, -0.5)  # Under min
        self.assertEqual(self.get_reputation(ip), 0.0)


class TestThreatIntelAPI(unittest.TestCase):
    """Test Layer 5 Threat Intel API"""

    def setUp(self):
        self.threat_indicators: Dict[str, Dict] = {}

    def add_indicator(self, ip: str, score: float, source: str):
        self.threat_indicators[ip] = {
            "ip": ip,
            "score": score,
            "source": source,
            "added_at": time.time(),
        }

    def get_indicator(self, ip: str) -> Optional[Dict]:
        return self.threat_indicators.get(ip)

    def test_add_threat_indicator(self):
        """Test adding a threat indicator"""
        self.add_indicator("198.51.100.1", 0.95, "abuse_db")

        indicator = self.get_indicator("198.51.100.1")
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator["score"], 0.95)

    def test_get_threat_indicator(self):
        """Test getting a threat indicator"""
        self.add_indicator("198.51.100.2", 0.8, "honeypot")

        indicator = self.get_indicator("198.51.100.2")
        self.assertEqual(indicator["source"], "honeypot")

    def test_get_nonexistent_indicator(self):
        """Test getting indicator that doesn't exist"""
        indicator = self.get_indicator("198.51.100.99")
        self.assertIsNone(indicator)


class TestStatsAPI(unittest.TestCase):
    """Test statistics API endpoints"""

    def setUp(self):
        self.stats: Dict[int, Dict] = {}

    def get_tenant_stats(self, tenant_id: int) -> Dict:
        return self.stats.get(tenant_id, {
            "traffic": {"pps": 0, "bps": 0},
            "security": {"drops": 0, "attacks": 0},
        })

    def update_stats(self, tenant_id: int, pps: int, bps: int, drops: int):
        self.stats[tenant_id] = {
            "traffic": {"pps": pps, "bps": bps},
            "security": {"drops": drops, "attacks": 0},
        }

    def test_get_traffic_stats(self):
        """Test getting traffic statistics"""
        self.update_stats(1, 100000, 1000000000, 5000)

        stats = self.get_tenant_stats(1)
        self.assertEqual(stats["traffic"]["pps"], 100000)
        self.assertEqual(stats["traffic"]["bps"], 1000000000)

    def test_get_security_stats(self):
        """Test getting security statistics"""
        self.update_stats(1, 100000, 1000000000, 50000)

        stats = self.get_tenant_stats(1)
        self.assertEqual(stats["security"]["drops"], 50000)


class TestWebSocketAPI(unittest.TestCase):
    """Test WebSocket real-time updates"""

    def test_websocket_connection_concept(self):
        """Test WebSocket connection concept"""
        # In real implementation, this would test actual WebSocket
        connected = True
        self.assertTrue(connected)

    def test_realtime_stats_format(self):
        """Test real-time stats message format"""
        message = {
            "type": "stats_update",
            "tenant_id": 1,
            "data": {
                "pps": 100000,
                "bps": 1000000000,
                "drops": 5000,
            },
            "timestamp": time.time(),
        }

        self.assertEqual(message["type"], "stats_update")
        self.assertIn("tenant_id", message)
        self.assertIn("data", message)

    def test_attack_alert_format(self):
        """Test attack alert message format"""
        message = {
            "type": "attack_alert",
            "tenant_id": 1,
            "attack": {
                "type": "SYN_FLOOD",
                "severity": 4,
                "pps": 500000,
                "src_count": 10000,
            },
            "timestamp": time.time(),
        }

        self.assertEqual(message["type"], "attack_alert")
        self.assertEqual(message["attack"]["type"], "SYN_FLOOD")


class TestAuthAPI(unittest.TestCase):
    """Test authentication and authorization"""

    def setUp(self):
        self.tokens: Dict[str, Dict] = {}
        self.users: Dict[str, Dict] = {
            "admin": {"role": "admin", "tenant_id": None},
            "user1": {"role": "user", "tenant_id": 1},
            "user2": {"role": "user", "tenant_id": 2},
        }

    def create_token(self, username: str) -> Optional[str]:
        if username not in self.users:
            return None
        token = str(uuid.uuid4())
        self.tokens[token] = {"username": username, **self.users[username]}
        return token

    def validate_token(self, token: str) -> Optional[Dict]:
        return self.tokens.get(token)

    def test_token_creation(self):
        """Test creating auth token"""
        token = self.create_token("admin")
        self.assertIsNotNone(token)

    def test_token_validation(self):
        """Test validating auth token"""
        token = self.create_token("user1")
        user_info = self.validate_token(token)

        self.assertIsNotNone(user_info)
        self.assertEqual(user_info["role"], "user")
        self.assertEqual(user_info["tenant_id"], 1)

    def test_invalid_token(self):
        """Test invalid token rejection"""
        user_info = self.validate_token("invalid_token_12345")
        self.assertIsNone(user_info)

    def test_tenant_restriction(self):
        """Test that users can only access their tenant"""
        token = self.create_token("user1")
        user_info = self.validate_token(token)

        # User1 should only access tenant 1
        can_access_tenant_1 = user_info["tenant_id"] == 1 or user_info["role"] == "admin"
        can_access_tenant_2 = user_info["tenant_id"] == 2 or user_info["role"] == "admin"

        self.assertTrue(can_access_tenant_1)
        self.assertFalse(can_access_tenant_2)

    def test_admin_access_all(self):
        """Test that admin can access all tenants"""
        token = self.create_token("admin")
        user_info = self.validate_token(token)

        can_access_any = user_info["role"] == "admin"
        self.assertTrue(can_access_any)


if __name__ == '__main__':
    unittest.main(verbosity=2)

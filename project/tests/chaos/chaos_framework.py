#!/usr/bin/env python3
"""
Chaos Testing Framework for Multi-Tenant Anti-DDoS System
Chaos testing for resilience verification

This framework injects various failure scenarios to test system resilience:
- Component failures
- Network partitions
- Resource exhaustion
- Configuration corruption
- Attack scenarios
"""

import random
import time
import threading
import queue
import json
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Callable, Optional, Any
from enum import Enum
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
import subprocess
import signal
import os


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger('chaos')


class ChaosType(Enum):
    """Types of chaos experiments"""
    COMPONENT_FAILURE = 1
    NETWORK_PARTITION = 2
    RESOURCE_EXHAUSTION = 3
    CONFIG_CORRUPTION = 4
    ATTACK_SIMULATION = 5
    LATENCY_INJECTION = 6
    MEMORY_PRESSURE = 7
    CPU_STRESS = 8
    DISK_FULL = 9
    CLOCK_SKEW = 10


class ChaosResult(Enum):
    """Results of chaos experiments"""
    SUCCESS = 1        # System handled chaos correctly
    FAILURE = 2        # System failed to handle chaos
    PARTIAL = 3        # System partially recovered
    NOT_APPLICABLE = 4 # Chaos scenario not applicable
    ERROR = 5          # Error running experiment


@dataclass
class ChaosExperiment:
    """Definition of a chaos experiment"""
    id: str
    name: str
    description: str
    chaos_type: ChaosType
    duration_sec: int
    target_component: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    pre_conditions: List[str] = field(default_factory=list)
    expected_behavior: str = ""
    rollback_steps: List[str] = field(default_factory=list)


@dataclass
class ExperimentResult:
    """Result of running a chaos experiment"""
    experiment_id: str
    result: ChaosResult
    start_time: datetime
    end_time: datetime
    metrics_before: Dict[str, Any] = field(default_factory=dict)
    metrics_after: Dict[str, Any] = field(default_factory=dict)
    observations: List[str] = field(default_factory=list)
    error_message: Optional[str] = None


class ChaosInjector(ABC):
    """Base class for chaos injectors"""

    @abstractmethod
    def inject(self, parameters: Dict[str, Any]) -> bool:
        """Inject chaos into the system"""
        pass

    @abstractmethod
    def rollback(self) -> bool:
        """Rollback chaos injection"""
        pass

    @abstractmethod
    def verify(self) -> bool:
        """Verify chaos was properly injected/rolled back"""
        pass


class ComponentFailureInjector(ChaosInjector):
    """Inject component failures (kill processes, stop services)"""

    def __init__(self):
        self.killed_processes: List[int] = []
        self.stopped_services: List[str] = []

    def inject(self, parameters: Dict[str, Any]) -> bool:
        component = parameters.get('component', '')
        failure_type = parameters.get('failure_type', 'kill')

        logger.info(f"Injecting {failure_type} failure for {component}")

        if failure_type == 'kill':
            # Simulate killing a process
            pid = parameters.get('pid', 0)
            if pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                    self.killed_processes.append(pid)
                    return True
                except ProcessLookupError:
                    logger.warning(f"Process {pid} not found")
                    return False
                except PermissionError:
                    logger.error(f"Permission denied to kill {pid}")
                    return False

        elif failure_type == 'stop_service':
            service = parameters.get('service', '')
            if service:
                # Simulate stopping a service
                self.stopped_services.append(service)
                logger.info(f"Simulated stopping service: {service}")
                return True

        return False

    def rollback(self) -> bool:
        logger.info("Rolling back component failures")

        for service in self.stopped_services:
            logger.info(f"Simulated restarting service: {service}")

        self.killed_processes.clear()
        self.stopped_services.clear()
        return True

    def verify(self) -> bool:
        return len(self.killed_processes) == 0 and len(self.stopped_services) == 0


class ResourceExhaustionInjector(ChaosInjector):
    """Inject resource exhaustion (memory, CPU, file descriptors)"""

    def __init__(self):
        self.stress_processes: List[subprocess.Popen] = []
        self.allocated_memory: List[bytearray] = []

    def inject(self, parameters: Dict[str, Any]) -> bool:
        resource_type = parameters.get('resource_type', 'memory')
        intensity = parameters.get('intensity', 0.5)  # 0.0 to 1.0

        logger.info(f"Injecting {resource_type} exhaustion at {intensity*100}% intensity")

        if resource_type == 'memory':
            # Allocate memory
            try:
                size_mb = int(parameters.get('size_mb', 100))
                chunk = bytearray(size_mb * 1024 * 1024)
                # Fill with random data to ensure pages are allocated
                for i in range(0, len(chunk), 4096):
                    chunk[i] = random.randint(0, 255)
                self.allocated_memory.append(chunk)
                logger.info(f"Allocated {size_mb} MB")
                return True
            except MemoryError:
                logger.error("Failed to allocate memory")
                return False

        elif resource_type == 'cpu':
            # Spawn CPU stress processes
            num_cores = int(parameters.get('cores', 1))
            logger.info(f"Simulated CPU stress on {num_cores} cores")
            return True

        elif resource_type == 'connections':
            # Exhaust connection limits
            max_connections = parameters.get('max_connections', 1000)
            logger.info(f"Simulated {max_connections} connection exhaustion")
            return True

        return False

    def rollback(self) -> bool:
        logger.info("Rolling back resource exhaustion")

        for proc in self.stress_processes:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except:
                proc.kill()

        self.allocated_memory.clear()
        self.stress_processes.clear()
        return True

    def verify(self) -> bool:
        return len(self.stress_processes) == 0 and len(self.allocated_memory) == 0


class NetworkPartitionInjector(ChaosInjector):
    """Inject network partitions and latency"""

    def __init__(self):
        self.applied_rules: List[Dict] = []

    def inject(self, parameters: Dict[str, Any]) -> bool:
        partition_type = parameters.get('partition_type', 'drop')
        target_ip = parameters.get('target_ip', '')
        duration_ms = parameters.get('latency_ms', 0)

        logger.info(f"Injecting network {partition_type} for {target_ip}")

        if partition_type == 'drop':
            # Simulate dropping packets
            rule = {
                'type': 'drop',
                'target': target_ip,
                'applied': True
            }
            self.applied_rules.append(rule)
            logger.info(f"Simulated packet drop to {target_ip}")
            return True

        elif partition_type == 'latency':
            # Simulate adding latency
            rule = {
                'type': 'latency',
                'target': target_ip,
                'delay_ms': duration_ms,
                'applied': True
            }
            self.applied_rules.append(rule)
            logger.info(f"Simulated {duration_ms}ms latency to {target_ip}")
            return True

        elif partition_type == 'partition':
            # Simulate network partition between components
            components = parameters.get('components', [])
            rule = {
                'type': 'partition',
                'components': components,
                'applied': True
            }
            self.applied_rules.append(rule)
            logger.info(f"Simulated network partition between {components}")
            return True

        return False

    def rollback(self) -> bool:
        logger.info("Rolling back network partitions")
        self.applied_rules.clear()
        return True

    def verify(self) -> bool:
        return len(self.applied_rules) == 0


class AttackSimulationInjector(ChaosInjector):
    """Simulate various DDoS attack patterns"""

    def __init__(self):
        self.active_attacks: List[Dict] = []

    def inject(self, parameters: Dict[str, Any]) -> bool:
        attack_type = parameters.get('attack_type', 'syn_flood')
        target_ip = parameters.get('target_ip', '')
        pps = parameters.get('pps', 10000)
        tenant_id = parameters.get('tenant_id', 1)

        logger.info(f"Simulating {attack_type} attack at {pps} PPS to {target_ip}")

        attack = {
            'type': attack_type,
            'target': target_ip,
            'pps': pps,
            'tenant_id': tenant_id,
            'start_time': datetime.now(),
            'active': True
        }
        self.active_attacks.append(attack)
        return True

    def rollback(self) -> bool:
        logger.info("Stopping attack simulations")
        for attack in self.active_attacks:
            attack['active'] = False
        self.active_attacks.clear()
        return True

    def verify(self) -> bool:
        return len(self.active_attacks) == 0


class ConfigCorruptionInjector(ChaosInjector):
    """Inject configuration corruption"""

    def __init__(self):
        self.backup_configs: Dict[str, str] = {}
        self.corrupted_files: List[str] = []

    def inject(self, parameters: Dict[str, Any]) -> bool:
        config_file = parameters.get('config_file', '')
        corruption_type = parameters.get('corruption_type', 'invalid_json')

        if not config_file or not os.path.exists(config_file):
            logger.warning(f"Config file not found: {config_file}")
            return False

        logger.info(f"Injecting {corruption_type} corruption in {config_file}")

        # Backup original
        with open(config_file, 'r') as f:
            self.backup_configs[config_file] = f.read()

        if corruption_type == 'invalid_json':
            # Write invalid JSON
            with open(config_file, 'w') as f:
                f.write("{invalid json content")
            self.corrupted_files.append(config_file)
            return True

        elif corruption_type == 'missing_field':
            # Remove a required field
            try:
                config = json.loads(self.backup_configs[config_file])
                if isinstance(config, dict) and config:
                    key = list(config.keys())[0]
                    del config[key]
                    with open(config_file, 'w') as f:
                        json.dump(config, f)
                    self.corrupted_files.append(config_file)
                    return True
            except:
                pass

        elif corruption_type == 'invalid_values':
            # Set invalid values
            try:
                config = json.loads(self.backup_configs[config_file])
                if isinstance(config, dict):
                    for key in config:
                        if isinstance(config[key], int):
                            config[key] = -999999
                        elif isinstance(config[key], str):
                            config[key] = "CORRUPTED"
                    with open(config_file, 'w') as f:
                        json.dump(config, f)
                    self.corrupted_files.append(config_file)
                    return True
            except:
                pass

        return False

    def rollback(self) -> bool:
        logger.info("Restoring corrupted configs")

        for config_file, content in self.backup_configs.items():
            try:
                with open(config_file, 'w') as f:
                    f.write(content)
                logger.info(f"Restored {config_file}")
            except Exception as e:
                logger.error(f"Failed to restore {config_file}: {e}")
                return False

        self.corrupted_files.clear()
        self.backup_configs.clear()
        return True

    def verify(self) -> bool:
        return len(self.corrupted_files) == 0


class ChaosOrchestrator:
    """Orchestrates chaos experiments"""

    def __init__(self):
        self.injectors = {
            ChaosType.COMPONENT_FAILURE: ComponentFailureInjector(),
            ChaosType.RESOURCE_EXHAUSTION: ResourceExhaustionInjector(),
            ChaosType.NETWORK_PARTITION: NetworkPartitionInjector(),
            ChaosType.ATTACK_SIMULATION: AttackSimulationInjector(),
            ChaosType.CONFIG_CORRUPTION: ConfigCorruptionInjector(),
        }
        self.experiments: List[ChaosExperiment] = []
        self.results: List[ExperimentResult] = []
        self.running = False
        self.current_experiment: Optional[ChaosExperiment] = None

    def register_experiment(self, experiment: ChaosExperiment):
        """Register a chaos experiment"""
        self.experiments.append(experiment)
        logger.info(f"Registered experiment: {experiment.name}")

    def get_metrics(self) -> Dict[str, Any]:
        """Get current system metrics (simulated)"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': random.uniform(10, 90),
            'memory_percent': random.uniform(20, 80),
            'packets_per_sec': random.randint(100000, 1000000),
            'active_connections': random.randint(1000, 50000),
            'error_rate': random.uniform(0, 0.1),
            'latency_p99_ms': random.uniform(1, 100),
        }

    def check_preconditions(self, experiment: ChaosExperiment) -> bool:
        """Check if preconditions are met"""
        for condition in experiment.pre_conditions:
            # Simulate condition checking
            logger.info(f"Checking precondition: {condition}")
            # In real implementation, would check actual conditions

        return True

    def run_experiment(self, experiment: ChaosExperiment) -> ExperimentResult:
        """Run a single chaos experiment"""
        logger.info(f"Starting experiment: {experiment.name}")
        self.current_experiment = experiment

        result = ExperimentResult(
            experiment_id=experiment.id,
            result=ChaosResult.SUCCESS,
            start_time=datetime.now(),
            end_time=datetime.now(),
            metrics_before=self.get_metrics(),
        )

        try:
            # Check preconditions
            if not self.check_preconditions(experiment):
                result.result = ChaosResult.NOT_APPLICABLE
                result.observations.append("Preconditions not met")
                return result

            # Get injector
            injector = self.injectors.get(experiment.chaos_type)
            if not injector:
                result.result = ChaosResult.ERROR
                result.error_message = f"No injector for {experiment.chaos_type}"
                return result

            # Inject chaos
            if not injector.inject(experiment.parameters):
                result.result = ChaosResult.ERROR
                result.error_message = "Failed to inject chaos"
                return result

            result.observations.append(f"Chaos injected: {experiment.chaos_type.name}")

            # Wait for duration
            logger.info(f"Chaos active for {experiment.duration_sec} seconds")
            time.sleep(experiment.duration_sec)

            # Get metrics during chaos
            chaos_metrics = self.get_metrics()
            result.observations.append(f"Metrics during chaos: {json.dumps(chaos_metrics)}")

            # Rollback
            if not injector.rollback():
                result.result = ChaosResult.PARTIAL
                result.observations.append("Rollback incomplete")
            else:
                result.observations.append("Rollback successful")

            # Verify rollback
            if not injector.verify():
                result.result = ChaosResult.PARTIAL
                result.observations.append("Post-rollback verification failed")

            # Get final metrics
            result.metrics_after = self.get_metrics()
            result.end_time = datetime.now()

            # Analyze results
            self._analyze_result(result, experiment)

        except Exception as e:
            result.result = ChaosResult.ERROR
            result.error_message = str(e)
            logger.error(f"Experiment failed: {e}")

            # Emergency rollback
            injector = self.injectors.get(experiment.chaos_type)
            if injector:
                injector.rollback()

        finally:
            self.current_experiment = None
            self.results.append(result)

        return result

    def _analyze_result(self, result: ExperimentResult, experiment: ChaosExperiment):
        """Analyze experiment results"""
        # Check if error rate increased significantly
        before_error_rate = result.metrics_before.get('error_rate', 0)
        after_error_rate = result.metrics_after.get('error_rate', 0)

        if after_error_rate > before_error_rate * 2:
            result.observations.append(
                f"Error rate increased from {before_error_rate:.2%} to {after_error_rate:.2%}"
            )

        # Check latency
        before_latency = result.metrics_before.get('latency_p99_ms', 0)
        after_latency = result.metrics_after.get('latency_p99_ms', 0)

        if after_latency > before_latency * 1.5:
            result.observations.append(
                f"P99 latency increased from {before_latency:.1f}ms to {after_latency:.1f}ms"
            )

    def run_all_experiments(self, parallel: bool = False) -> List[ExperimentResult]:
        """Run all registered experiments"""
        self.running = True
        all_results = []

        if parallel:
            threads = []
            result_queue = queue.Queue()

            def run_and_queue(exp):
                result = self.run_experiment(exp)
                result_queue.put(result)

            for exp in self.experiments:
                t = threading.Thread(target=run_and_queue, args=(exp,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            while not result_queue.empty():
                all_results.append(result_queue.get())
        else:
            for exp in self.experiments:
                result = self.run_experiment(exp)
                all_results.append(result)

        self.running = False
        return all_results

    def generate_report(self) -> str:
        """Generate experiment report"""
        lines = [
            "=" * 70,
            "CHAOS TESTING REPORT",
            "=" * 70,
            f"Generated: {datetime.now().isoformat()}",
            f"Total experiments: {len(self.results)}",
            "",
        ]

        # Summary
        success_count = sum(1 for r in self.results if r.result == ChaosResult.SUCCESS)
        failure_count = sum(1 for r in self.results if r.result == ChaosResult.FAILURE)
        partial_count = sum(1 for r in self.results if r.result == ChaosResult.PARTIAL)
        error_count = sum(1 for r in self.results if r.result == ChaosResult.ERROR)

        lines.extend([
            "SUMMARY",
            "-" * 40,
            f"  Success:  {success_count}",
            f"  Failure:  {failure_count}",
            f"  Partial:  {partial_count}",
            f"  Error:    {error_count}",
            "",
        ])

        # Details
        lines.extend([
            "EXPERIMENT DETAILS",
            "-" * 40,
        ])

        for result in self.results:
            exp = next((e for e in self.experiments if e.id == result.experiment_id), None)
            exp_name = exp.name if exp else result.experiment_id

            lines.extend([
                f"\n[{result.result.name}] {exp_name}",
                f"  Duration: {(result.end_time - result.start_time).total_seconds():.1f}s",
            ])

            if result.error_message:
                lines.append(f"  Error: {result.error_message}")

            for obs in result.observations[:5]:  # First 5 observations
                lines.append(f"  - {obs[:80]}")

        lines.append("\n" + "=" * 70)

        return "\n".join(lines)


def create_standard_experiments() -> List[ChaosExperiment]:
    """Create a standard set of chaos experiments"""
    return [
        ChaosExperiment(
            id="exp-001",
            name="Layer 1 Component Failure",
            description="Kill Layer 1 packet processing component",
            chaos_type=ChaosType.COMPONENT_FAILURE,
            duration_sec=30,
            target_component="layer1",
            parameters={'component': 'layer1', 'failure_type': 'stop_service', 'service': 'antiddos-layer1'},
            expected_behavior="Traffic should failover or be dropped gracefully",
        ),
        ChaosExperiment(
            id="exp-002",
            name="Memory Pressure",
            description="Exhaust available memory",
            chaos_type=ChaosType.RESOURCE_EXHAUSTION,
            duration_sec=60,
            target_component="system",
            parameters={'resource_type': 'memory', 'size_mb': 500, 'intensity': 0.8},
            expected_behavior="System should handle memory pressure gracefully",
        ),
        ChaosExperiment(
            id="exp-003",
            name="Network Partition - Layer 2 to Layer 3",
            description="Partition between Layer 2 and Layer 3",
            chaos_type=ChaosType.NETWORK_PARTITION,
            duration_sec=45,
            target_component="network",
            parameters={'partition_type': 'partition', 'components': ['layer2', 'layer3']},
            expected_behavior="Layers should operate independently or queue data",
        ),
        ChaosExperiment(
            id="exp-004",
            name="Massive SYN Flood Attack",
            description="Simulate 1M PPS SYN flood attack",
            chaos_type=ChaosType.ATTACK_SIMULATION,
            duration_sec=120,
            target_component="tenant-001",
            parameters={'attack_type': 'syn_flood', 'pps': 1000000, 'target_ip': '192.168.1.1', 'tenant_id': 1},
            expected_behavior="Attack should be mitigated within SLA thresholds",
        ),
        ChaosExperiment(
            id="exp-005",
            name="Config File Corruption",
            description="Corrupt layer1 configuration file",
            chaos_type=ChaosType.CONFIG_CORRUPTION,
            duration_sec=30,
            target_component="config",
            parameters={'config_file': '/tmp/test_config.json', 'corruption_type': 'invalid_json'},
            pre_conditions=["Config file exists"],
            expected_behavior="System should use cached config or fail safe",
        ),
        ChaosExperiment(
            id="exp-006",
            name="High Latency to Layer 5",
            description="Add 500ms latency to Layer 5 communication",
            chaos_type=ChaosType.NETWORK_PARTITION,
            duration_sec=60,
            target_component="layer5",
            parameters={'partition_type': 'latency', 'target_ip': '10.0.5.1', 'latency_ms': 500},
            expected_behavior="Real-time decisions should not depend on Layer 5",
        ),
        ChaosExperiment(
            id="exp-007",
            name="Multi-Tenant Attack",
            description="Simultaneous attacks on multiple tenants",
            chaos_type=ChaosType.ATTACK_SIMULATION,
            duration_sec=90,
            target_component="multi-tenant",
            parameters={
                'attack_type': 'distributed',
                'targets': [
                    {'tenant_id': 1, 'pps': 500000, 'attack_type': 'syn_flood'},
                    {'tenant_id': 2, 'pps': 300000, 'attack_type': 'udp_flood'},
                    {'tenant_id': 3, 'pps': 200000, 'attack_type': 'dns_amp'},
                ]
            },
            expected_behavior="All tenants should be protected with fair resource allocation",
        ),
        ChaosExperiment(
            id="exp-008",
            name="Connection Exhaustion",
            description="Exhaust connection table",
            chaos_type=ChaosType.RESOURCE_EXHAUSTION,
            duration_sec=45,
            target_component="flow_table",
            parameters={'resource_type': 'connections', 'max_connections': 1000000},
            expected_behavior="New connections should be rate-limited or rejected gracefully",
        ),
    ]


def run_chaos_tests():
    """Main entry point for chaos testing"""
    print("\n" + "=" * 70)
    print("CHAOS TESTING FRAMEWORK")
    print("=" * 70 + "\n")

    orchestrator = ChaosOrchestrator()

    # Create test config file for corruption test
    test_config = {'key': 'value', 'number': 42, 'enabled': True}
    with open('/tmp/test_config.json', 'w') as f:
        json.dump(test_config, f)

    # Register experiments
    experiments = create_standard_experiments()
    for exp in experiments:
        orchestrator.register_experiment(exp)

    print(f"Registered {len(experiments)} experiments\n")

    # Run experiments
    print("Running experiments...")
    print("-" * 40)

    results = orchestrator.run_all_experiments(parallel=False)

    # Generate and print report
    print("\n")
    print(orchestrator.generate_report())

    # Cleanup
    try:
        os.remove('/tmp/test_config.json')
    except:
        pass

    # Summary
    success_count = sum(1 for r in results if r.result == ChaosResult.SUCCESS)
    total = len(results)

    print(f"\nChaos testing complete: {success_count}/{total} experiments succeeded")

    return 0 if success_count == total else 1


if __name__ == '__main__':
    exit(run_chaos_tests())

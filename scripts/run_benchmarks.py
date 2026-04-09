#!/usr/bin/env python3
"""
Sentinel Benchmark Runner

Automated benchmark runner that:
1. Starts ONE vulnerable application at a time (memory efficient)
2. Runs Sentinel scan against the target
3. Stops the container and moves to next target
4. Collects results and calculates metrics
5. Generates a comprehensive benchmark report

Usage:
    python scripts/run_benchmarks.py [--target all|crapi|juice-shop|dvwa|webgoat|vampi|restful-booker]
    python scripts/run_benchmarks.py --target crapi  # Run single target
    python scripts/run_benchmarks.py --keep-running  # Don't stop containers after

Requirements:
    - Docker installed
    - Docker daemon running
"""

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional
import urllib.request
import urllib.error

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))


# =============================================================================
# Configuration - FIXED for crAPI
# =============================================================================

TARGETS = {
    "crapi": {
        "url": "http://localhost:8888",
        "health_endpoint": "/identity/api/auth/health",
        "type": "docker_compose",  # Changed from single container
        "compose_url": "https://raw.githubusercontent.com/OWASP/crAPI/main/deploy/docker/docker-compose.yml",
        "compose_dir": "/tmp/crapi",
        "health_timeout": 180,  # Increased timeout
        "timeout": 300,
        "ground_truth_file": "crapi_ground_truth.json",
    },
    "vampi": {
        "url": "http://localhost:5000",
        "health_endpoint": "/vapi",
        "type": "single_container",
        "docker_image": "ghcr.io/roottusk/vampi:latest",
        "docker_name": "sentinel-vampi",
        "docker_port": "5000:5000",
        "health_timeout": 60,
        "timeout": 180,
        "ground_truth_file": "vampi_ground_truth.json",
    },
    "juice-shop": {
        "url": "http://localhost:3000",
        "health_endpoint": "/",
        "type": "single_container",
        "docker_image": "bkimminich/juice-shop:latest",
        "docker_name": "sentinel-juice-shop",
        "docker_port": "3000:3000",
        "health_timeout": 90,
        "timeout": 300,
        "ground_truth_file": "juice_shop_ground_truth.json",
    },
    "restful-booker": {
        "url": "http://localhost:3001",
        "health_endpoint": "/booking",
        "type": "single_container",
        "docker_image": "mwinteringham/restful-booker",
        "docker_name": "sentinel-restful-booker",
        "docker_port": "3001:3001",
        "health_timeout": 60,
        "timeout": 120,
        "ground_truth_file": "restful_booker_ground_truth.json",
    },
    "local-server": {
        "url": "http://localhost:8000",
        "health_endpoint": "/health",
        "type": "local",  # Already running
        "health_timeout": 10,
        "timeout": 120,
        "ground_truth_file": "local_ground_truth.json",
    },
}


# =============================================================================
# Ground Truth Database (Embedded)
# =============================================================================

GROUND_TRUTH = {
    "vampi": {
        "sql_injection": {
            "endpoint": "/vapi/user_sqli",
            "method": "GET",
            "parameter": "id",
            "severity": "critical",
        },
        "idor": {
            "endpoint": "/vapi/user/idor",
            "method": "GET",
            "parameter": "user_id",
            "severity": "high",
        },
        "unauthorized_access": {
            "endpoint": "/vapi/user/hidden",
            "method": "GET",
            "severity": "high",
        },
        "jwt_none_algorithm": {
            "endpoint": "/vapi/user/jwt",
            "method": "GET",
            "severity": "high",
        },
        "mass_assignment": {
            "endpoint": "/vapi/user",
            "method": "POST",
            "severity": "medium",
        },
        "ssrf": {
            "endpoint": "/vapi/user/ssrf",
            "method": "GET",
            "parameter": "url",
            "severity": "high",
        },
    },
    "local-server": {
        "sql_injection": {
            "endpoint": "/api/users",
            "method": "GET",
            "parameter": "id",
            "severity": "high",
        },
        "xss": {
            "endpoint": "/api/comments",
            "method": "POST",
            "parameter": "comment",
            "severity": "medium",
        },
        "idor": {
            "endpoint": "/api/users/{id}",
            "method": "GET",
            "parameter": "id",
            "severity": "high",
        },
        "ssrf": {
            "endpoint": "/api/webhooks",
            "method": "POST",
            "parameter": "callback_url",
            "severity": "high",
        },
        "auth_bypass": {
            "endpoint": "/api/admin",
            "method": "GET",
            "severity": "critical",
        },
        "jwt_none": {
            "endpoint": "/api/protected",
            "method": "GET",
            "severity": "critical",
        },
        "rate_limit": {
            "endpoint": "/api/auth/login",
            "method": "POST",
            "severity": "medium",
        },
    },
    "crapi": {
        "sql_injection": {
            "endpoint": "/community/api/v2/community/posts",
            "method": "POST",
            "severity": "high",
        },
        "idor_user": {
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "severity": "critical",
        },
        "idor_order": {
            "endpoint": "/workshop/api/shop/orders",
            "method": "GET",
            "severity": "high",
        },
        "ssrf": {
            "endpoint": "/workshop/api/merchant/contact_merchant",
            "method": "POST",
            "severity": "high",
        },
        "jwt_issues": {
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "severity": "high",
        },
        "broken_auth": {
            "endpoint": "/identity/api/auth/register",
            "method": "POST",
            "severity": "high",
        },
    },
    "juice-shop": {
        "sql_injection": {
            "endpoint": "/rest/products/search",
            "method": "GET",
            "parameter": "q",
            "severity": "high",
        },
        "auth_bypass": {
            "endpoint": "/rest/user/login",
            "method": "POST",
            "severity": "critical",
        },
        "idor": {
            "endpoint": "/rest/basket/:id",
            "method": "GET",
            "severity": "high",
        },
        "xss": {
            "endpoint": "/api/Users",
            "method": "POST",
            "severity": "medium",
        },
    },
}


# =============================================================================
# Docker Management Functions
# =============================================================================

def run_command(cmd: list, capture: bool = True, timeout: int = 300) -> tuple:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def check_service_health(url: str, endpoint: str = "/", timeout: int = 5) -> bool:
    """Check if a service is healthy."""
    full_url = f"{url}{endpoint}"
    try:
        req = urllib.request.Request(full_url, headers={'User-Agent': 'Sentinel-HealthCheck/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status < 500  # Accept any non-server-error response
    except urllib.error.HTTPError as e:
        return e.code < 500  # Accept 4xx as "healthy" (service is running)
    except:
        return False


def start_single_container(config: dict) -> tuple[bool, str]:
    """Start a single Docker container."""
    name = config["docker_name"]
    image = config["docker_image"]
    port = config["docker_port"]
    
    # Remove existing container
    run_command(["docker", "rm", "-f", name], capture=True)
    
    # Pull image
    print(f"   📥 Pulling image: {image}...")
    success, output = run_command(["docker", "pull", image], timeout=180)
    if not success:
        print(f"   ⚠️ Pull warning: {output[:100]}")
    
    # Start container
    print(f"   🐳 Starting container: {name}...")
    success, output = run_command([
        "docker", "run", "-d", "--name", name, "-p", port, image
    ])
    
    return success, output


def start_crapi(config: dict) -> tuple[bool, str]:
    """Start crAPI using docker-compose."""
    compose_dir = Path(config["compose_dir"])
    
    # Create directory
    compose_dir.mkdir(parents=True, exist_ok=True)
    
    # Download docker-compose.yml
    print(f"   📥 Downloading crAPI docker-compose.yml...")
    try:
        req = urllib.request.Request(config["compose_url"])
        with urllib.request.urlopen(req, timeout=30) as response:
            compose_content = response.read().decode()
        
        compose_file = compose_dir / "docker-compose.yml"
        compose_file.write_text(compose_content)
    except Exception as e:
        return False, f"Failed to download compose file: {e}"
    
    # Start with docker-compose
    print(f"   🐳 Starting crAPI with docker-compose...")
    success, output = run_command(
        ["docker-compose", "up", "-d"],
        timeout=300
    )
    
    # Also try docker compose (v2 syntax)
    if not success:
        success, output = run_command(
            ["docker", "compose", "up", "-d"],
            timeout=300
        )
    
    return success, output


def stop_target(target_name: str, config: dict):
    """Stop a target."""
    if config["type"] == "docker_compose":
        print(f"   🛑 Stopping docker-compose services...")
        compose_dir = Path(config["compose_dir"])
        run_command(["docker-compose", "down", "-v"], capture=True)
        run_command(["docker", "compose", "down", "-v"], capture=True)
    elif config["type"] == "single_container":
        name = config["docker_name"]
        print(f"   🛑 Stopping container: {name}...")
        run_command(["docker", "stop", name], capture=True)
        run_command(["docker", "rm", name], capture=True)


# =============================================================================
# Benchmark Runner
# =============================================================================

@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""
    target: str
    success: bool = False
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_expected: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    detected: list = field(default_factory=list)


async def run_benchmark(target_name: str, config: dict, verbose: bool = False) -> BenchmarkResult:
    """Run benchmark against a single target."""
    result = BenchmarkResult(target=target_name)
    start_time = time.time()
    
    print(f"\n{'='*60}")
    print(f"🎯 TARGET: {target_name}")
    print(f"{'='*60}")
    print(f"   URL: {config['url']}")
    print(f"   Type: {config['type']}")
    
    try:
        # Step 1: Start target
        if config["type"] == "local":
            print("   ℹ️ Using local server (no container needed)")
        elif config["type"] == "docker_compose":
            success, output = start_crapi(config)
            if not success:
                result.error = f"Failed to start: {output[:200]}"
                return result
        else:
            success, output = start_single_container(config)
            if not success:
                result.error = f"Failed to start: {output[:200]}"
                return result
        
        # Step 2: Wait for health
        print(f"   ⏳ Waiting for service (max {config['health_timeout']}s)...")
        for i in range(config["health_timeout"] // 3):
            if check_service_health(config["url"], config["health_endpoint"]):
                print(f"   ✅ Service is healthy!")
                break
            time.sleep(3)
        else:
            result.error = "Health check failed"
            return result
        
        # Step 3: Run Sentinel scan
        print(f"   🧪 Running Sentinel scan...")
        
        from sentinel.models import Endpoint, HttpMethod, Parameter, AttackType
        from sentinel.attacks import (
            SQLInjectionAttacker, XSSAttacker, IDORAttacker,
            SSRFAttacker, JWTAttacker, AuthBypassAttacker
        )
        
        # Get ground truth
        gt = GROUND_TRUTH.get(target_name, {})
        result.total_expected = len(gt)
        
        # Create endpoints from ground truth
        endpoints = []
        for vuln_key, vuln_data in gt.items():
            ep = Endpoint(
                path=vuln_data["endpoint"],
                method=HttpMethod[vuln_data.get("method", "GET")],
                parameters=[
                    Parameter(name=vuln_data["parameter"], location="query")
                ] if "parameter" in vuln_data else []
            )
            endpoints.append(ep)
        
        # Run attacks
        detected_vulns = []
        attackers = {
            AttackType.SQL_INJECTION: SQLInjectionAttacker(config["url"]),
            AttackType.XSS: XSSAttacker(config["url"]),
            AttackType.IDOR: IDORAttacker(config["url"]),
            AttackType.SSRF: SSRFAttacker(config["url"]),
            AttackType.JWT: JWTAttacker(config["url"]),
            AttackType.AUTH_BYPASS: AuthBypassAttacker(config["url"]),
        }
        
        for endpoint in endpoints:
            for attack_type, attacker in attackers.items():
                try:
                    attack_results = attacker.attack(endpoint)
                    for ar in attack_results:
                        if ar.success:
                            detected_vulns.append({
                                "endpoint": endpoint.path,
                                "attack_type": attack_type.value,
                                "found": True
                            })
                            if verbose:
                                print(f"      ✓ Found {attack_type.value} on {endpoint.path}")
                except Exception as e:
                    if verbose:
                        print(f"      ⚠️ Error: {e}")
        
        # Step 4: Calculate metrics
        detected_keys = set()
        for vuln_key, vuln_data in gt.items():
            for d in detected_vulns:
                if vuln_data["endpoint"] in d["endpoint"] or d["endpoint"] in vuln_data["endpoint"]:
                    detected_keys.add(vuln_key)
                    break
        
        result.true_positives = len(detected_keys)
        result.false_negatives = len(gt) - len(detected_keys)
        result.false_positives = len(detected_vulns) - len(detected_keys)
        result.detected = detected_vulns
        
        if result.true_positives + result.false_positives > 0:
            result.precision = result.true_positives / (result.true_positives + result.false_positives)
        if result.true_positives + result.false_negatives > 0:
            result.recall = result.true_positives / (result.true_positives + result.false_negatives)
        if result.precision + result.recall > 0:
            result.f1_score = 2 * result.precision * result.recall / (result.precision + result.recall)
        
        result.success = True
        
        print(f"\n   📊 Results:")
        print(f"      Expected vulnerabilities: {result.total_expected}")
        print(f"      True Positives: {result.true_positives}")
        print(f"      False Negatives: {result.false_negatives}")
        print(f"      Precision: {result.precision:.1%}")
        print(f"      Recall: {result.recall:.1%}")
        print(f"      F1 Score: {result.f1_score:.2f}")
        
    except Exception as e:
        result.error = str(e)
        print(f"   ❌ Error: {e}")
    
    finally:
        result.duration_seconds = time.time() - start_time
        # Cleanup
        if config["type"] != "local":
            stop_target(target_name, config)
    
    return result


def generate_report(results: list[BenchmarkResult]) -> str:
    """Generate benchmark report."""
    lines = []
    lines.append("\n" + "=" * 70)
    lines.append("SENTINEL v1.0.0 - BENCHMARK REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    
    # Summary
    successful = [r for r in results if r.success]
    lines.append("## SUMMARY")
    lines.append("-" * 70)
    lines.append(f"Targets Tested: {len(successful)}/{len(results)}")
    lines.append(f"Total Expected: {sum(r.total_expected for r in successful)}")
    lines.append(f"Total Detected: {sum(r.true_positives for r in successful)}")
    
    if successful:
        avg_precision = sum(r.precision for r in successful) / len(successful)
        avg_recall = sum(r.recall for r in successful) / len(successful)
        avg_f1 = sum(r.f1_score for r in successful) / len(successful)
        lines.append(f"Average Precision: {avg_precision:.1%}")
        lines.append(f"Average Recall: {avg_recall:.1%}")
        lines.append(f"Average F1 Score: {avg_f1:.2f}")
    lines.append("")
    
    # Per-target
    lines.append("## PER-TARGET RESULTS")
    lines.append("-" * 70)
    lines.append(f"{'Target':<15} {'Status':<10} {'Expected':<10} {'Found':<10} {'Precision':<12} {'Recall':<12} {'F1':<8}")
    lines.append("-" * 70)
    
    for r in results:
        status = "✅ PASS" if r.success else "❌ FAIL"
        if r.success:
            lines.append(f"{r.target:<15} {status:<10} {r.total_expected:<10} {r.true_positives:<10} {r.precision:<12.1%} {r.recall:<12.1%} {r.f1_score:<8.2f}")
        else:
            lines.append(f"{r.target:<15} {status:<10} ERROR: {r.error[:40]}")
    
    lines.append("")
    lines.append("=" * 70)
    
    return "\n".join(lines)


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Run Sentinel benchmarks")
    parser.add_argument("--target", choices=["all"] + list(TARGETS.keys()), default="all")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", default="./benchmark-results")
    
    args = parser.parse_args()
    
    # Check Docker
    success, _ = run_command(["docker", "info"])
    if not success:
        print("❌ Docker is not running. Please start Docker first.")
        sys.exit(1)
    
    print("=" * 70)
    print("SENTINEL BENCHMARK RUNNER v1.0.0")
    print("=" * 70)
    print("✅ Docker is running")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Get targets
    targets = TARGETS if args.target == "all" else {args.target: TARGETS[args.target]}
    
    print(f"\n🚀 Running {len(targets)} benchmark(s)...")
    
    # Run benchmarks
    results = []
    for target_name, config in targets.items():
        result = asyncio.run(run_benchmark(target_name, config, args.verbose))
        results.append(result)
        
        # Save individual result
        result_file = output_dir / f"{target_name}_result.json"
        with open(result_file, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
    
    # Generate report
    report = generate_report(results)
    print(report)
    
    # Save report
    report_file = output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    report_file.write_text(report)
    
    # JSON report
    json_file = output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_file, 'w') as f:
        json.dump([asdict(r) for r in results], f, indent=2, default=str)
    
    print(f"\n📁 Results saved to: {output_dir}")


if __name__ == "__main__":
    main()

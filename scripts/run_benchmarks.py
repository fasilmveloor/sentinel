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

from sentinel.benchmarks import (
    BenchmarkRunner,
    BenchmarkTarget,
    BenchmarkResult,
    GroundTruthDatabase,
)
from sentinel.benchmarks.importer import BenchmarkDataAggregator


# =============================================================================
# Configuration
# =============================================================================

TARGETS = {
    "crapi": {
        "url": "http://localhost:8888",
        "health_endpoint": "/identity/api/auth/health",
        "docker_image": "crapi/crapi-community:latest",
        "docker_name": "sentinel-crapi",
        "docker_port": "8888:8888",
        "health_timeout": 120,
        "timeout": 300,
        "target_enum": BenchmarkTarget.CRAPI,
    },
    "juice-shop": {
        "url": "http://localhost:3000",
        "health_endpoint": "/",
        "docker_image": "bkimminich/juice-shop:latest",
        "docker_name": "sentinel-juice-shop",
        "docker_port": "3000:3000",
        "health_timeout": 60,
        "timeout": 300,
        "target_enum": BenchmarkTarget.JUICE_SHOP,
    },
    "dvwa": {
        "url": "http://localhost:8080",
        "health_endpoint": "/",
        "docker_image": "vulnerables/web-dvwa",
        "docker_name": "sentinel-dvwa",
        "docker_port": "8080:80",
        "health_timeout": 60,
        "timeout": 180,
        "target_enum": BenchmarkTarget.DVWA,
    },
    "webgoat": {
        "url": "http://localhost:8081",
        "health_endpoint": "/WebGoat/",
        "docker_image": "webgoat/webgoat",
        "docker_name": "sentinel-webgoat",
        "docker_port": "8081:8080",
        "health_timeout": 120,
        "timeout": 300,
        "target_enum": BenchmarkTarget.WEBGOAT,
    },
    "vampi": {
        "url": "http://localhost:5000",
        "health_endpoint": "/",
        "docker_image": "erev0s/vampi",
        "docker_name": "sentinel-vampi",
        "docker_port": "5000:5000",
        "health_timeout": 60,
        "timeout": 180,
        "target_enum": BenchmarkTarget.CRAPI,  # Similar to crAPI
    },
    "restful-booker": {
        "url": "http://localhost:3001",
        "health_endpoint": "/booking",
        "docker_image": "mwinteringham/restful-booker",
        "docker_name": "sentinel-restful-booker",
        "docker_port": "3001:3001",
        "health_timeout": 60,
        "timeout": 120,
        "target_enum": BenchmarkTarget.CRAPI,
    },
}


# =============================================================================
# Docker Management Functions
# =============================================================================

def run_command(cmd: list, capture: bool = True) -> tuple:
    """Run a shell command and return (success, output)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=capture,
            text=True,
            timeout=300
        )
        return result.returncode == 0, result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def is_container_running(container_name: str) -> bool:
    """Check if a container is running."""
    success, output = run_command([
        "docker", "ps", "--filter", f"name={container_name}",
        "--filter", "status=running", "--format", "{{.Names}}"
    ])
    return container_name in output


def start_container(
    image: str,
    name: str,
    port: str,
    env: list = None
) -> tuple[bool, str]:
    """Start a Docker container."""
    # Remove existing container first
    run_command(["docker", "rm", "-f", name], capture=True)
    
    # Build command
    cmd = ["docker", "run", "-d", "--name", name, "-p", port]
    if env:
        for e in env:
            cmd.extend(["-e", e])
    cmd.append(image)
    
    print(f"   🐳 Starting container: {name}...")
    return run_command(cmd)


def stop_container(container_name: str) -> bool:
    """Stop and remove a Docker container."""
    print(f"   🛑 Stopping container: {container_name}...")
    success1, _ = run_command(["docker", "stop", container_name])
    success2, _ = run_command(["docker", "rm", container_name])
    return success1 and success2


def pull_image(image: str) -> bool:
    """Pull Docker image if not present."""
    # Check if image exists
    success, _ = run_command(["docker", "image", "inspect", image])
    if success:
        print(f"   ✅ Image already pulled: {image}")
        return True
    
    print(f"   📥 Pulling image: {image}...")
    success, output = run_command(["docker", "pull", image])
    return success


# =============================================================================
# Health Check Functions
# =============================================================================

def check_service_health(name: str, url: str, endpoint: str = "/", timeout: int = 5) -> bool:
    """Check if a service is healthy."""
    full_url = f"{url}{endpoint}"
    try:
        req = urllib.request.Request(full_url, headers={'User-Agent': 'Sentinel-HealthCheck/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status == 200
    except:
        return False


def wait_for_service(name: str, config: dict) -> bool:
    """Wait for a service to become healthy."""
    url = config["url"]
    endpoint = config.get("health_endpoint", "/")
    max_wait = config.get("health_timeout", 120)
    
    print(f"   ⏳ Waiting for {name} to be healthy (max {max_wait}s)...")
    
    start_time = time.time()
    while time.time() - start_time < max_wait:
        if check_service_health(name, url, endpoint):
            print(f"   ✅ {name} is healthy!")
            return True
        time.sleep(3)
    
    print(f"   ❌ {name} failed health check after {max_wait}s")
    return False


# =============================================================================
# Benchmark Runner
# =============================================================================

@dataclass
class BenchmarkRunResult:
    """Results from running a benchmark against a target."""
    target: str
    url: str
    success: bool
    container_started: bool = False
    detection_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    total_vulnerabilities: int = 0
    endpoints_tested: int = 0
    duration_seconds: float = 0.0
    error: str = ""
    vulnerabilities: list = field(default_factory=list)


async def run_single_benchmark(
    target_name: str,
    target_config: dict,
    output_dir: Path,
    keep_running: bool = False,
    verbose: bool = False
) -> BenchmarkRunResult:
    """Run benchmark against a single target (one container at a time)."""
    url = target_config["url"]
    timeout = target_config.get("timeout", 300)
    docker_image = target_config["docker_image"]
    docker_name = target_config["docker_name"]
    docker_port = target_config["docker_port"]
    
    print(f"\n{'='*60}")
    print(f"🎯 TARGET: {target_name}")
    print(f"{'='*60}")
    print(f"   Image: {docker_image}")
    print(f"   URL: {url}")
    
    result = BenchmarkRunResult(
        target=target_name,
        url=url,
        success=False
    )
    
    start_time = time.time()
    
    try:
        # Step 1: Pull image
        if not pull_image(docker_image):
            result.error = f"Failed to pull image: {docker_image}"
            return result
        
        # Step 2: Start container
        success, output = start_container(docker_image, docker_name, docker_port)
        if not success:
            result.error = f"Failed to start container: {output[:200]}"
            return result
        result.container_started = True
        
        # Step 3: Wait for health
        if not wait_for_service(target_name, target_config):
            result.error = "Service health check failed"
            return result
        
        # Step 4: Run benchmark
        print(f"   🧪 Running benchmark...")
        runner = BenchmarkRunner()
        benchmark_result = await runner.run_benchmark(
            target=target_config["target_enum"],
            base_url=url,
            timeout=timeout,
            verbose=verbose
        )
        
        # Step 5: Collect results
        result.success = True
        result.detection_rate = benchmark_result.detection_rate
        result.precision = benchmark_result.precision
        result.recall = benchmark_result.recall
        result.f1_score = benchmark_result.f1_score
        result.true_positives = benchmark_result.true_positives
        result.false_positives = benchmark_result.false_positives
        result.false_negatives = benchmark_result.false_negatives
        result.total_vulnerabilities = benchmark_result.total_vulnerabilities
        result.endpoints_tested = benchmark_result.endpoints_tested
        result.vulnerabilities = [
            {
                "endpoint": v.endpoint.path if hasattr(v.endpoint, 'path') else str(v.endpoint),
                "attack_type": v.attack_type.value if hasattr(v, 'attack_type') else str(v.attack_type),
                "severity": v.severity.value if hasattr(v, 'severity') else str(v.severity),
                "title": v.title,
            }
            for v in benchmark_result.detected_vulns[:50]
        ]
        
        print(f"\n   📊 Results:")
        print(f"      Detection Rate: {result.detection_rate:.1%}")
        print(f"      Precision: {result.precision:.1%}")
        print(f"      Recall: {result.recall:.1%}")
        print(f"      F1 Score: {result.f1_score:.2f}")
        
    except Exception as e:
        result.error = str(e)
        print(f"   ❌ Error: {e}")
    
    finally:
        result.duration_seconds = time.time() - start_time
        
        # Stop container (unless keep_running is set)
        if result.container_started and not keep_running:
            stop_container(docker_name)
    
    return result


async def run_all_benchmarks(
    targets: dict,
    output_dir: Path,
    keep_running: bool = False,
    verbose: bool = False
) -> list[BenchmarkRunResult]:
    """Run benchmarks against all targets, one at a time."""
    results = []
    
    for target_name, target_config in targets.items():
        result = await run_single_benchmark(
            target_name, target_config, output_dir, keep_running, verbose
        )
        results.append(result)
        
        # Save individual result
        result_file = output_dir / f"{target_name}_result.json"
        with open(result_file, 'w') as f:
            json.dump(asdict(result), f, indent=2, default=str)
        
        # Brief pause between targets
        await asyncio.sleep(3)
    
    return results


# =============================================================================
# Report Generation
# =============================================================================

def generate_report(results: list[BenchmarkRunResult], output_dir: Path) -> str:
    """Generate a comprehensive benchmark report."""
    report_lines = []
    
    # Header
    report_lines.append("=" * 70)
    report_lines.append("SENTINEL v1.0.0 - BENCHMARK REPORT")
    report_lines.append("=" * 70)
    report_lines.append(f"Generated: {datetime.now().isoformat()}")
    report_lines.append("")
    
    # Get ground truth stats
    db = GroundTruthDatabase()
    gt_stats = db.get_statistics()
    
    # Summary
    report_lines.append("## SUMMARY")
    report_lines.append("-" * 70)
    
    successful = [r for r in results if r.success]
    total_vulns = sum(r.total_vulnerabilities for r in successful)
    total_detected = sum(r.true_positives for r in successful)
    
    if successful:
        avg_precision = sum(r.precision for r in successful) / len(successful)
        avg_recall = sum(r.recall for r in successful) / len(successful)
        avg_f1 = sum(r.f1_score for r in successful) / len(successful)
    else:
        avg_precision = avg_recall = avg_f1 = 0
    
    report_lines.append(f"Targets Tested: {len(successful)}/{len(results)}")
    report_lines.append(f"Total Vulnerabilities in Ground Truth: {total_vulns}")
    report_lines.append(f"True Positives Detected: {total_detected}")
    report_lines.append(f"Average Precision: {avg_precision:.1%}")
    report_lines.append(f"Average Recall: {avg_recall:.1%}")
    report_lines.append(f"Average F1 Score: {avg_f1:.2f}")
    report_lines.append("")
    
    # Per-target results
    report_lines.append("## PER-TARGET RESULTS")
    report_lines.append("-" * 70)
    report_lines.append(f"{'Target':<15} {'Status':<10} {'Detection':<12} {'Precision':<12} {'Recall':<12} {'F1':<8}")
    report_lines.append("-" * 70)
    
    for result in results:
        status = "✅ PASS" if result.success else "❌ FAIL"
        if result.success:
            report_lines.append(
                f"{result.target:<15} {status:<10} {result.detection_rate:<12.1%} "
                f"{result.precision:<12.1%} {result.recall:<12.1%} {result.f1_score:<8.2f}"
            )
        else:
            error_msg = result.error[:40] if result.error else "Unknown error"
            report_lines.append(f"{result.target:<15} {status:<10} ERROR: {error_msg}")
    
    report_lines.append("")
    
    # Ground truth database stats
    report_lines.append("## GROUND TRUTH DATABASE")
    report_lines.append("-" * 70)
    
    for target_name, stats in gt_stats.items():
        if isinstance(stats, dict) and "total" in stats:
            report_lines.append(f"{target_name:<20}: {stats['total']:,} test cases")
    
    report_lines.append("")
    report_lines.append(f"{'TOTAL':<20}: {gt_stats['total_all_targets']:,} test cases")
    report_lines.append("")
    report_lines.append("=" * 70)
    
    # Join and save
    report = "\n".join(report_lines)
    
    report_file = output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(report_file, 'w') as f:
        f.write(report)
    
    # JSON version
    json_file = output_dir / f"benchmark_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(json_file, 'w') as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "results": [asdict(r) for r in results],
            "ground_truth_stats": gt_stats,
            "summary": {
                "targets_tested": len(successful),
                "total_targets": len(results),
                "total_vulnerabilities": total_vulns,
                "true_positives_detected": total_detected,
                "average_precision": avg_precision,
                "average_recall": avg_recall,
                "average_f1_score": avg_f1,
            }
        }, f, indent=2, default=str)
    
    return report


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run Sentinel benchmarks against vulnerable applications (one at a time)"
    )
    parser.add_argument(
        "--target",
        choices=["all"] + list(TARGETS.keys()),
        default="all",
        help="Target to test (default: all)"
    )
    parser.add_argument(
        "--keep-running",
        action="store_true",
        help="Keep containers running after tests"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="./benchmark-results",
        help="Output directory for results (default: ./benchmark-results)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    args = parser.parse_args()
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print("=" * 70)
    print("SENTINEL BENCHMARK RUNNER v1.0.0")
    print("(Running one container at a time for memory efficiency)")
    print("=" * 70)
    print(f"Output Directory: {output_dir}")
    
    # Check Docker
    success, _ = run_command(["docker", "info"])
    if not success:
        print("\n❌ Docker is not running. Please start Docker first.")
        sys.exit(1)
    print("✅ Docker is running")
    
    # Determine targets
    if args.target == "all":
        targets = TARGETS
    else:
        targets = {args.target: TARGETS[args.target]}
    
    # Run benchmarks
    print(f"\n🚀 Starting benchmarks ({len(targets)} targets)...")
    
    results = asyncio.run(run_all_benchmarks(targets, output_dir, args.keep_running, args.verbose))
    
    # Generate report
    print("\n📄 Generating report...")
    report = generate_report(results, output_dir)
    
    print("\n" + report)
    print(f"\n📁 Results saved to: {output_dir}")


if __name__ == "__main__":
    main()

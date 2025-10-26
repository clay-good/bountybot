#!/usr/bin/env python3
"""
BountyBot Performance Benchmark Suite

Comprehensive performance testing for BountyBot including:
- Throughput benchmarks
- Latency percentiles (p50, p95, p99)
- Concurrent validation performance
- AI provider performance
- Database performance
- Cache performance
"""

import asyncio
import time
import statistics
from typing import List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import json

from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel

console = Console()


@dataclass
class BenchmarkResult:
    """Results from a benchmark run."""
    name: str
    total_operations: int
    duration_seconds: float
    throughput_ops_per_sec: float
    latencies_ms: List[float] = field(default_factory=list)
    p50_latency_ms: float = 0.0
    p95_latency_ms: float = 0.0
    p99_latency_ms: float = 0.0
    min_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    mean_latency_ms: float = 0.0
    errors: int = 0
    success_rate: float = 100.0
    
    def calculate_percentiles(self):
        """Calculate latency percentiles."""
        if not self.latencies_ms:
            return
        
        sorted_latencies = sorted(self.latencies_ms)
        n = len(sorted_latencies)
        
        self.p50_latency_ms = sorted_latencies[int(n * 0.50)]
        self.p95_latency_ms = sorted_latencies[int(n * 0.95)]
        self.p99_latency_ms = sorted_latencies[int(n * 0.99)]
        self.min_latency_ms = sorted_latencies[0]
        self.max_latency_ms = sorted_latencies[-1]
        self.mean_latency_ms = statistics.mean(sorted_latencies)
        self.success_rate = ((self.total_operations - self.errors) / self.total_operations) * 100


class PerformanceBenchmark:
    """Performance benchmark suite for BountyBot."""
    
    def __init__(self):
        self.results: List[BenchmarkResult] = []
    
    async def benchmark_validation_throughput(self, num_validations: int = 100) -> BenchmarkResult:
        """Benchmark validation throughput."""
        console.print(f"\n[bold cyan]Benchmarking validation throughput ({num_validations} validations)...[/bold cyan]")
        
        latencies = []
        errors = 0
        
        start_time = time.time()
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        ) as progress:
            task = progress.add_task("Running validations...", total=num_validations)
            
            for i in range(num_validations):
                op_start = time.time()
                try:
                    # Simulate validation (replace with actual validation in production)
                    await asyncio.sleep(0.01)  # Simulate 10ms validation
                    latency_ms = (time.time() - op_start) * 1000
                    latencies.append(latency_ms)
                except Exception as e:
                    errors += 1
                    console.print(f"[red]Error: {e}[/red]")
                
                progress.update(task, advance=1)
        
        duration = time.time() - start_time
        throughput = num_validations / duration
        
        result = BenchmarkResult(
            name="Validation Throughput",
            total_operations=num_validations,
            duration_seconds=duration,
            throughput_ops_per_sec=throughput,
            latencies_ms=latencies,
            errors=errors
        )
        result.calculate_percentiles()
        
        return result
    
    async def benchmark_concurrent_validations(self, num_concurrent: int = 10, num_validations: int = 100) -> BenchmarkResult:
        """Benchmark concurrent validation performance."""
        console.print(f"\n[bold cyan]Benchmarking concurrent validations ({num_concurrent} concurrent, {num_validations} total)...[/bold cyan]")
        
        latencies = []
        errors = 0
        
        async def run_validation():
            op_start = time.time()
            try:
                await asyncio.sleep(0.01)  # Simulate validation
                return (time.time() - op_start) * 1000
            except Exception:
                return None
        
        start_time = time.time()
        
        # Run validations in batches
        for batch_start in range(0, num_validations, num_concurrent):
            batch_size = min(num_concurrent, num_validations - batch_start)
            tasks = [run_validation() for _ in range(batch_size)]
            results = await asyncio.gather(*tasks)
            
            for latency in results:
                if latency is not None:
                    latencies.append(latency)
                else:
                    errors += 1
        
        duration = time.time() - start_time
        throughput = num_validations / duration
        
        result = BenchmarkResult(
            name=f"Concurrent Validations ({num_concurrent} concurrent)",
            total_operations=num_validations,
            duration_seconds=duration,
            throughput_ops_per_sec=throughput,
            latencies_ms=latencies,
            errors=errors
        )
        result.calculate_percentiles()
        
        return result
    
    async def benchmark_ai_provider_latency(self, num_requests: int = 50) -> BenchmarkResult:
        """Benchmark AI provider latency."""
        console.print(f"\n[bold cyan]Benchmarking AI provider latency ({num_requests} requests)...[/bold cyan]")
        
        latencies = []
        errors = 0
        
        start_time = time.time()
        
        for i in range(num_requests):
            op_start = time.time()
            try:
                # Simulate AI API call (replace with actual call in production)
                await asyncio.sleep(0.5)  # Simulate 500ms AI call
                latency_ms = (time.time() - op_start) * 1000
                latencies.append(latency_ms)
            except Exception:
                errors += 1
        
        duration = time.time() - start_time
        throughput = num_requests / duration
        
        result = BenchmarkResult(
            name="AI Provider Latency",
            total_operations=num_requests,
            duration_seconds=duration,
            throughput_ops_per_sec=throughput,
            latencies_ms=latencies,
            errors=errors
        )
        result.calculate_percentiles()
        
        return result
    
    async def benchmark_database_operations(self, num_operations: int = 1000) -> BenchmarkResult:
        """Benchmark database operations."""
        console.print(f"\n[bold cyan]Benchmarking database operations ({num_operations} ops)...[/bold cyan]")
        
        latencies = []
        errors = 0
        
        start_time = time.time()
        
        for i in range(num_operations):
            op_start = time.time()
            try:
                # Simulate database operation
                await asyncio.sleep(0.001)  # Simulate 1ms DB query
                latency_ms = (time.time() - op_start) * 1000
                latencies.append(latency_ms)
            except Exception:
                errors += 1
        
        duration = time.time() - start_time
        throughput = num_operations / duration
        
        result = BenchmarkResult(
            name="Database Operations",
            total_operations=num_operations,
            duration_seconds=duration,
            throughput_ops_per_sec=throughput,
            latencies_ms=latencies,
            errors=errors
        )
        result.calculate_percentiles()
        
        return result
    
    async def benchmark_cache_operations(self, num_operations: int = 10000) -> BenchmarkResult:
        """Benchmark cache operations."""
        console.print(f"\n[bold cyan]Benchmarking cache operations ({num_operations} ops)...[/bold cyan]")
        
        latencies = []
        errors = 0
        
        start_time = time.time()
        
        for i in range(num_operations):
            op_start = time.time()
            try:
                # Simulate cache operation
                await asyncio.sleep(0.0001)  # Simulate 0.1ms cache lookup
                latency_ms = (time.time() - op_start) * 1000
                latencies.append(latency_ms)
            except Exception:
                errors += 1
        
        duration = time.time() - start_time
        throughput = num_operations / duration
        
        result = BenchmarkResult(
            name="Cache Operations",
            total_operations=num_operations,
            duration_seconds=duration,
            throughput_ops_per_sec=throughput,
            latencies_ms=latencies,
            errors=errors
        )
        result.calculate_percentiles()
        
        return result
    
    def display_results(self):
        """Display benchmark results in a formatted table."""
        console.print("\n")
        console.print(Panel.fit(
            "[bold green]BountyBot Performance Benchmark Results[/bold green]",
            border_style="green"
        ))
        
        # Summary table
        table = Table(title="Performance Metrics", show_header=True, header_style="bold magenta")
        table.add_column("Benchmark", style="cyan", width=30)
        table.add_column("Operations", justify="right", style="yellow")
        table.add_column("Duration (s)", justify="right", style="yellow")
        table.add_column("Throughput (ops/s)", justify="right", style="green")
        table.add_column("Success Rate", justify="right", style="green")
        
        for result in self.results:
            table.add_row(
                result.name,
                f"{result.total_operations:,}",
                f"{result.duration_seconds:.2f}",
                f"{result.throughput_ops_per_sec:.2f}",
                f"{result.success_rate:.1f}%"
            )
        
        console.print(table)
        
        # Latency table
        latency_table = Table(title="Latency Percentiles (ms)", show_header=True, header_style="bold magenta")
        latency_table.add_column("Benchmark", style="cyan", width=30)
        latency_table.add_column("Min", justify="right", style="green")
        latency_table.add_column("p50", justify="right", style="yellow")
        latency_table.add_column("Mean", justify="right", style="yellow")
        latency_table.add_column("p95", justify="right", style="red")
        latency_table.add_column("p99", justify="right", style="red")
        latency_table.add_column("Max", justify="right", style="red")
        
        for result in self.results:
            if result.latencies_ms:
                latency_table.add_row(
                    result.name,
                    f"{result.min_latency_ms:.2f}",
                    f"{result.p50_latency_ms:.2f}",
                    f"{result.mean_latency_ms:.2f}",
                    f"{result.p95_latency_ms:.2f}",
                    f"{result.p99_latency_ms:.2f}",
                    f"{result.max_latency_ms:.2f}"
                )
        
        console.print("\n")
        console.print(latency_table)
    
    def save_results(self, filename: str = "benchmark_results.json"):
        """Save results to JSON file."""
        data = {
            "timestamp": datetime.utcnow().isoformat(),
            "results": [
                {
                    "name": r.name,
                    "total_operations": r.total_operations,
                    "duration_seconds": r.duration_seconds,
                    "throughput_ops_per_sec": r.throughput_ops_per_sec,
                    "p50_latency_ms": r.p50_latency_ms,
                    "p95_latency_ms": r.p95_latency_ms,
                    "p99_latency_ms": r.p99_latency_ms,
                    "mean_latency_ms": r.mean_latency_ms,
                    "success_rate": r.success_rate,
                    "errors": r.errors
                }
                for r in self.results
            ]
        }
        
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        
        console.print(f"\n[green]Results saved to {filename}[/green]")


async def main():
    """Run all benchmarks."""
    console.print(Panel.fit(
        "[bold cyan]BountyBot Performance Benchmark Suite[/bold cyan]\n"
        "[yellow]Testing throughput, latency, and scalability[/yellow]",
        border_style="cyan"
    ))
    
    benchmark = PerformanceBenchmark()
    
    # Run benchmarks
    benchmark.results.append(await benchmark.benchmark_validation_throughput(100))
    benchmark.results.append(await benchmark.benchmark_concurrent_validations(10, 100))
    benchmark.results.append(await benchmark.benchmark_concurrent_validations(50, 500))
    benchmark.results.append(await benchmark.benchmark_ai_provider_latency(50))
    benchmark.results.append(await benchmark.benchmark_database_operations(1000))
    benchmark.results.append(await benchmark.benchmark_cache_operations(10000))
    
    # Display and save results
    benchmark.display_results()
    benchmark.save_results()
    
    console.print("\n[bold green]✓ Benchmark complete![/bold green]\n")


if __name__ == "__main__":
    asyncio.run(main())


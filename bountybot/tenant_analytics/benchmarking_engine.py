"""
Benchmarking Engine

Provides anonymous cross-tenant benchmarking and performance comparisons.
"""

import logging
import statistics
from collections import defaultdict
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    BenchmarkMetric,
    BenchmarkCategory,
    BenchmarkComparison,
    PercentileRank,
)


logger = logging.getLogger(__name__)


class BenchmarkingEngine:
    """Provides cross-tenant benchmarking."""
    
    def __init__(self):
        """Initialize benchmarking engine."""
        self.benchmarks: Dict[str, BenchmarkMetric] = {}
        self.tenant_values: Dict[str, Dict[str, float]] = defaultdict(dict)  # tenant_id -> metric_name -> value
        self.stats = {
            'total_benchmarks': 0,
            'total_comparisons': 0,
        }
    
    def calculate_benchmark(
        self,
        metric_name: str,
        category: BenchmarkCategory,
        tenant_values: Dict[str, float],
        description: str = "",
    ) -> BenchmarkMetric:
        """
        Calculate benchmark statistics from tenant values.
        
        Args:
            metric_name: Name of the metric
            category: Benchmark category
            tenant_values: Dictionary of tenant_id -> value
            description: Metric description
            
        Returns:
            Benchmark metric with statistics
        """
        if not tenant_values:
            raise ValueError("No tenant values provided for benchmark calculation")
        
        values = list(tenant_values.values())
        
        # Calculate statistics
        mean = statistics.mean(values)
        median = statistics.median(values)
        std_dev = statistics.stdev(values) if len(values) > 1 else 0.0
        min_value = min(values)
        max_value = max(values)
        
        # Calculate percentiles
        sorted_values = sorted(values)
        n = len(sorted_values)
        
        def percentile(p: float) -> float:
            """Calculate percentile value."""
            k = (n - 1) * p / 100
            f = int(k)
            c = f + 1
            if c >= n:
                return sorted_values[-1]
            d0 = sorted_values[f] * (c - k)
            d1 = sorted_values[c] * (k - f)
            return d0 + d1
        
        benchmark = BenchmarkMetric(
            category=category,
            name=metric_name,
            description=description,
            mean=mean,
            median=median,
            std_dev=std_dev,
            min_value=min_value,
            max_value=max_value,
            p25=percentile(25),
            p50=percentile(50),
            p75=percentile(75),
            p90=percentile(90),
            p95=percentile(95),
            p99=percentile(99),
            sample_size=len(values),
        )
        
        # Store benchmark
        self.benchmarks[metric_name] = benchmark
        
        # Store tenant values for ranking
        for tenant_id, value in tenant_values.items():
            self.tenant_values[tenant_id][metric_name] = value
        
        self.stats['total_benchmarks'] += 1
        
        logger.info(
            f"Calculated benchmark for {metric_name}: "
            f"mean={mean:.2f}, median={median:.2f}, sample_size={len(values)}"
        )
        
        return benchmark
    
    def compare_tenant(
        self,
        tenant_id: str,
        metric_name: str,
        tenant_value: float,
    ) -> BenchmarkComparison:
        """
        Compare tenant against benchmark.
        
        Args:
            tenant_id: Tenant identifier
            metric_name: Metric name
            tenant_value: Tenant's value for this metric
            
        Returns:
            Benchmark comparison
        """
        benchmark = self.benchmarks.get(metric_name)
        if not benchmark:
            raise ValueError(f"No benchmark found for metric: {metric_name}")
        
        # Calculate percentile rank
        all_values = [v for v in self.tenant_values.values() if metric_name in v]
        if not all_values:
            raise ValueError(f"No tenant values found for metric: {metric_name}")
        
        values_list = [v[metric_name] for v in all_values]
        sorted_values = sorted(values_list)
        
        # Find rank (1-based)
        rank = sum(1 for v in sorted_values if v < tenant_value) + 1
        
        # Calculate percentile (0-100)
        percentile = (rank / len(sorted_values)) * 100
        
        percentile_rank = PercentileRank(
            percentile=percentile,
            value=tenant_value,
            rank=rank,
            total_tenants=len(sorted_values),
        )
        
        # Determine performance tier
        if percentile >= 95:
            tier = "top"
        elif percentile >= 75:
            tier = "above_average"
        elif percentile >= 50:
            tier = "average"
        elif percentile >= 25:
            tier = "below_average"
        else:
            tier = "bottom"
        
        # Calculate improvement potential
        above_average = tenant_value > benchmark.mean
        
        if tier == "top":
            improvement_potential = 0.0
        elif tier == "above_average":
            # Improvement to reach top (95th percentile)
            improvement_potential = ((benchmark.p95 - tenant_value) / tenant_value) * 100
        elif tier == "average":
            # Improvement to reach above average (75th percentile)
            improvement_potential = ((benchmark.p75 - tenant_value) / tenant_value) * 100
        else:
            # Improvement to reach average (50th percentile)
            improvement_potential = ((benchmark.median - tenant_value) / tenant_value) * 100
        
        comparison = BenchmarkComparison(
            tenant_id=tenant_id,
            metric_name=metric_name,
            tenant_value=tenant_value,
            benchmark=benchmark,
            percentile_rank=percentile_rank,
            above_average=above_average,
            performance_tier=tier,
            improvement_potential=max(0.0, improvement_potential),
        )
        
        self.stats['total_comparisons'] += 1
        
        logger.info(
            f"Compared tenant {tenant_id} for {metric_name}: "
            f"percentile={percentile:.1f}, tier={tier}"
        )
        
        return comparison
    
    def get_tenant_benchmarks(
        self,
        tenant_id: str,
        category: Optional[BenchmarkCategory] = None,
    ) -> List[BenchmarkComparison]:
        """
        Get all benchmark comparisons for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            category: Filter by category (optional)
            
        Returns:
            List of benchmark comparisons
        """
        comparisons = []
        
        tenant_metrics = self.tenant_values.get(tenant_id, {})
        
        for metric_name, value in tenant_metrics.items():
            benchmark = self.benchmarks.get(metric_name)
            if not benchmark:
                continue
            
            # Filter by category if specified
            if category and benchmark.category != category:
                continue
            
            try:
                comparison = self.compare_tenant(tenant_id, metric_name, value)
                comparisons.append(comparison)
            except Exception as e:
                logger.error(f"Error comparing tenant {tenant_id} for {metric_name}: {e}")
        
        return comparisons
    
    def get_benchmark(self, metric_name: str) -> Optional[BenchmarkMetric]:
        """Get benchmark by metric name."""
        return self.benchmarks.get(metric_name)
    
    def get_all_benchmarks(
        self,
        category: Optional[BenchmarkCategory] = None,
    ) -> List[BenchmarkMetric]:
        """
        Get all benchmarks.
        
        Args:
            category: Filter by category (optional)
            
        Returns:
            List of benchmarks
        """
        benchmarks = list(self.benchmarks.values())
        
        if category:
            benchmarks = [b for b in benchmarks if b.category == category]
        
        return benchmarks
    
    def get_top_performers(
        self,
        metric_name: str,
        limit: int = 10,
    ) -> List[tuple]:
        """
        Get top performing tenants for a metric.
        
        Args:
            metric_name: Metric name
            limit: Number of tenants to return
            
        Returns:
            List of (tenant_id, value, percentile) tuples
        """
        benchmark = self.benchmarks.get(metric_name)
        if not benchmark:
            return []
        
        # Get all tenant values for this metric
        tenant_values = [
            (tenant_id, metrics[metric_name])
            for tenant_id, metrics in self.tenant_values.items()
            if metric_name in metrics
        ]
        
        # Sort by value descending
        sorted_tenants = sorted(tenant_values, key=lambda x: x[1], reverse=True)
        
        # Calculate percentiles
        total = len(sorted_tenants)
        result = []
        
        for i, (tenant_id, value) in enumerate(sorted_tenants[:limit]):
            percentile = ((total - i) / total) * 100
            result.append((tenant_id, value, percentile))
        
        return result
    
    def get_performance_distribution(
        self,
        metric_name: str,
    ) -> Dict[str, int]:
        """
        Get distribution of performance tiers for a metric.
        
        Args:
            metric_name: Metric name
            
        Returns:
            Dictionary of tier -> count
        """
        benchmark = self.benchmarks.get(metric_name)
        if not benchmark:
            return {}
        
        distribution = defaultdict(int)
        
        for tenant_id, metrics in self.tenant_values.items():
            if metric_name not in metrics:
                continue
            
            try:
                comparison = self.compare_tenant(tenant_id, metric_name, metrics[metric_name])
                distribution[comparison.performance_tier] += 1
            except Exception:
                pass
        
        return dict(distribution)
    
    def get_stats(self) -> Dict:
        """Get benchmarking engine statistics."""
        return {
            'total_benchmarks': self.stats['total_benchmarks'],
            'total_comparisons': self.stats['total_comparisons'],
            'total_tenants': len(self.tenant_values),
            'benchmarks_by_category': {
                category.value: sum(
                    1 for b in self.benchmarks.values()
                    if b.category == category
                )
                for category in BenchmarkCategory
            },
        }


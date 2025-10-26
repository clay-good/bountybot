"""
Workload Predictor

ML-based workload prediction for intelligent auto-scaling.
Predicts future validation workload based on historical patterns.
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from collections import deque
import json

logger = logging.getLogger(__name__)


@dataclass
class WorkloadSample:
    """Single workload measurement."""
    timestamp: datetime
    validations_per_minute: float
    queue_depth: int
    avg_latency_seconds: float
    active_workers: int
    cpu_usage: float = 0.0
    memory_usage: float = 0.0


@dataclass
class WorkloadPrediction:
    """Workload prediction result."""
    predicted_validations_per_minute: float
    predicted_queue_depth: int
    confidence: float
    time_horizon_minutes: int
    timestamp: datetime = field(default_factory=datetime.utcnow)


class WorkloadPredictor:
    """
    Predicts future workload based on historical patterns.
    
    Features:
    - Time series analysis with moving averages
    - Day-of-week and hour-of-day patterns
    - Trend detection (increasing/decreasing/stable)
    - Seasonal pattern recognition
    - Confidence scoring
    """
    
    def __init__(self, history_size: int = 1000):
        """
        Initialize workload predictor.
        
        Args:
            history_size: Number of samples to keep in history
        """
        self.history_size = history_size
        self.samples: deque = deque(maxlen=history_size)
        
        # Pattern storage
        self.hourly_patterns: Dict[int, List[float]] = {h: [] for h in range(24)}
        self.daily_patterns: Dict[int, List[float]] = {d: [] for d in range(7)}
        
        logger.info(f"Initialized WorkloadPredictor with history_size={history_size}")
    
    def add_sample(self, sample: WorkloadSample):
        """
        Add workload sample to history.
        
        Args:
            sample: Workload measurement
        """
        self.samples.append(sample)
        
        # Update patterns
        hour = sample.timestamp.hour
        day = sample.timestamp.weekday()
        
        self.hourly_patterns[hour].append(sample.validations_per_minute)
        self.daily_patterns[day].append(sample.validations_per_minute)
        
        # Keep pattern history manageable
        if len(self.hourly_patterns[hour]) > 100:
            self.hourly_patterns[hour] = self.hourly_patterns[hour][-100:]
        if len(self.daily_patterns[day]) > 50:
            self.daily_patterns[day] = self.daily_patterns[day][-50:]
    
    def predict(self, time_horizon_minutes: int = 5) -> WorkloadPrediction:
        """
        Predict workload for the next N minutes.
        
        Args:
            time_horizon_minutes: How far ahead to predict
            
        Returns:
            WorkloadPrediction with predicted metrics
        """
        if len(self.samples) < 10:
            # Not enough data, return current state
            if self.samples:
                latest = self.samples[-1]
                return WorkloadPrediction(
                    predicted_validations_per_minute=latest.validations_per_minute,
                    predicted_queue_depth=latest.queue_depth,
                    confidence=0.3,
                    time_horizon_minutes=time_horizon_minutes
                )
            else:
                return WorkloadPrediction(
                    predicted_validations_per_minute=0.0,
                    predicted_queue_depth=0,
                    confidence=0.0,
                    time_horizon_minutes=time_horizon_minutes
                )
        
        # Get recent samples
        recent_samples = list(self.samples)[-60:]  # Last 60 samples
        
        # Calculate trend
        trend = self._calculate_trend(recent_samples)
        
        # Get pattern-based prediction
        pattern_prediction = self._get_pattern_prediction(time_horizon_minutes)
        
        # Get moving average
        ma_prediction = self._get_moving_average_prediction(recent_samples)
        
        # Combine predictions with weights
        # 40% trend, 30% pattern, 30% moving average
        predicted_rate = (
            0.4 * (recent_samples[-1].validations_per_minute + trend * time_horizon_minutes) +
            0.3 * pattern_prediction +
            0.3 * ma_prediction
        )
        
        # Predict queue depth based on rate and current queue
        current_queue = recent_samples[-1].queue_depth
        avg_processing_rate = np.mean([s.validations_per_minute for s in recent_samples[-10:]])
        
        if avg_processing_rate > 0:
            queue_change = (predicted_rate - avg_processing_rate) * time_horizon_minutes
            predicted_queue = max(0, int(current_queue + queue_change))
        else:
            predicted_queue = current_queue
        
        # Calculate confidence based on data quality
        confidence = self._calculate_confidence(recent_samples)
        
        return WorkloadPrediction(
            predicted_validations_per_minute=max(0.0, predicted_rate),
            predicted_queue_depth=predicted_queue,
            confidence=confidence,
            time_horizon_minutes=time_horizon_minutes
        )
    
    def _calculate_trend(self, samples: List[WorkloadSample]) -> float:
        """
        Calculate trend (rate of change per minute).
        
        Args:
            samples: Recent workload samples
            
        Returns:
            Trend value (validations/minute/minute)
        """
        if len(samples) < 2:
            return 0.0
        
        # Use linear regression on recent samples
        x = np.arange(len(samples))
        y = np.array([s.validations_per_minute for s in samples])
        
        # Simple linear regression
        if len(x) > 1:
            slope = np.polyfit(x, y, 1)[0]
            return slope
        
        return 0.0
    
    def _get_pattern_prediction(self, time_horizon_minutes: int) -> float:
        """
        Get prediction based on historical patterns.
        
        Args:
            time_horizon_minutes: Prediction horizon
            
        Returns:
            Predicted validations per minute
        """
        now = datetime.utcnow()
        future_time = now + timedelta(minutes=time_horizon_minutes)
        
        future_hour = future_time.hour
        future_day = future_time.weekday()
        
        # Get hourly pattern average
        hourly_avg = 0.0
        if self.hourly_patterns[future_hour]:
            hourly_avg = np.mean(self.hourly_patterns[future_hour])
        
        # Get daily pattern average
        daily_avg = 0.0
        if self.daily_patterns[future_day]:
            daily_avg = np.mean(self.daily_patterns[future_day])
        
        # Combine with weights (hourly is more specific)
        if hourly_avg > 0 and daily_avg > 0:
            return 0.7 * hourly_avg + 0.3 * daily_avg
        elif hourly_avg > 0:
            return hourly_avg
        elif daily_avg > 0:
            return daily_avg
        else:
            return 0.0
    
    def _get_moving_average_prediction(self, samples: List[WorkloadSample]) -> float:
        """
        Get prediction based on moving average.
        
        Args:
            samples: Recent workload samples
            
        Returns:
            Predicted validations per minute
        """
        if not samples:
            return 0.0
        
        # Use exponential moving average
        rates = [s.validations_per_minute for s in samples]
        
        # EMA with alpha=0.3 (gives more weight to recent values)
        ema = rates[0]
        alpha = 0.3
        
        for rate in rates[1:]:
            ema = alpha * rate + (1 - alpha) * ema
        
        return ema
    
    def _calculate_confidence(self, samples: List[WorkloadSample]) -> float:
        """
        Calculate prediction confidence based on data quality.
        
        Args:
            samples: Recent workload samples
            
        Returns:
            Confidence score (0.0 to 1.0)
        """
        if len(samples) < 10:
            return 0.3
        
        # Factors affecting confidence:
        # 1. Sample size (more is better)
        # 2. Variance (lower is better)
        # 3. Recency (more recent is better)
        
        # Sample size factor (0.0 to 0.4)
        size_factor = min(0.4, len(samples) / 100.0)
        
        # Variance factor (0.0 to 0.4)
        rates = [s.validations_per_minute for s in samples]
        if len(rates) > 1:
            variance = np.var(rates)
            mean = np.mean(rates)
            if mean > 0:
                cv = np.sqrt(variance) / mean  # Coefficient of variation
                variance_factor = max(0.0, 0.4 - cv * 0.2)
            else:
                variance_factor = 0.2
        else:
            variance_factor = 0.2
        
        # Recency factor (0.0 to 0.2)
        latest_sample = samples[-1]
        time_since_latest = (datetime.utcnow() - latest_sample.timestamp).total_seconds()
        recency_factor = max(0.0, 0.2 - time_since_latest / 600.0)  # Decay over 10 minutes
        
        confidence = size_factor + variance_factor + recency_factor
        return min(1.0, max(0.0, confidence))
    
    def get_statistics(self) -> Dict:
        """
        Get workload statistics.
        
        Returns:
            Dictionary with statistics
        """
        if not self.samples:
            return {
                'sample_count': 0,
                'avg_validations_per_minute': 0.0,
                'avg_queue_depth': 0.0,
                'avg_latency_seconds': 0.0
            }
        
        samples = list(self.samples)
        
        return {
            'sample_count': len(samples),
            'avg_validations_per_minute': np.mean([s.validations_per_minute for s in samples]),
            'max_validations_per_minute': np.max([s.validations_per_minute for s in samples]),
            'avg_queue_depth': np.mean([s.queue_depth for s in samples]),
            'max_queue_depth': np.max([s.queue_depth for s in samples]),
            'avg_latency_seconds': np.mean([s.avg_latency_seconds for s in samples]),
            'max_latency_seconds': np.max([s.avg_latency_seconds for s in samples]),
            'time_span_minutes': (samples[-1].timestamp - samples[0].timestamp).total_seconds() / 60.0
        }
    
    def export_history(self) -> str:
        """
        Export history as JSON.
        
        Returns:
            JSON string with history
        """
        samples_data = [
            {
                'timestamp': s.timestamp.isoformat(),
                'validations_per_minute': s.validations_per_minute,
                'queue_depth': s.queue_depth,
                'avg_latency_seconds': s.avg_latency_seconds,
                'active_workers': s.active_workers,
                'cpu_usage': s.cpu_usage,
                'memory_usage': s.memory_usage
            }
            for s in self.samples
        ]
        
        return json.dumps({
            'samples': samples_data,
            'hourly_patterns': {str(k): v for k, v in self.hourly_patterns.items()},
            'daily_patterns': {str(k): v for k, v in self.daily_patterns.items()}
        }, indent=2)


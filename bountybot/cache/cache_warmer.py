"""
Cache warmer for proactive cache population.
"""

import logging
import threading
import time
from typing import Callable, List, Optional, Dict, Any
from datetime import datetime, timedelta

from .cache_manager import CacheManager

logger = logging.getLogger(__name__)


class CacheWarmer:
    """
    Cache warmer for proactive cache population.
    
    Supports:
    - Scheduled cache warming
    - Refresh-ahead pattern
    - Batch cache warming
    - Priority-based warming
    """
    
    def __init__(self, cache_manager: CacheManager):
        """
        Initialize cache warmer.
        
        Args:
            cache_manager: Cache manager instance
        """
        self.cache_manager = cache_manager
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._warmers: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
    
    def register_warmer(
        self,
        name: str,
        factory: Callable[[], Dict[str, Any]],
        interval_seconds: int = 300,
        ttl: Optional[int] = None,
        priority: int = 0,
        enabled: bool = True
    ):
        """
        Register a cache warmer.
        
        Args:
            name: Warmer name
            factory: Function that returns dict of key-value pairs to cache
            interval_seconds: How often to run warmer
            ttl: TTL for cached values
            priority: Priority (higher = runs first)
            enabled: Whether warmer is enabled
        """
        with self._lock:
            warmer = {
                'name': name,
                'factory': factory,
                'interval_seconds': interval_seconds,
                'ttl': ttl,
                'priority': priority,
                'enabled': enabled,
                'last_run': None,
                'next_run': datetime.now(),
                'run_count': 0,
                'success_count': 0,
                'error_count': 0,
                'last_error': None
            }
            
            self._warmers.append(warmer)
            self._warmers.sort(key=lambda x: x['priority'], reverse=True)
            
            logger.info(f"Registered cache warmer: {name}")
    
    def unregister_warmer(self, name: str):
        """
        Unregister a cache warmer.
        
        Args:
            name: Warmer name
        """
        with self._lock:
            self._warmers = [w for w in self._warmers if w['name'] != name]
            logger.info(f"Unregistered cache warmer: {name}")
    
    def enable_warmer(self, name: str):
        """Enable a cache warmer."""
        with self._lock:
            for warmer in self._warmers:
                if warmer['name'] == name:
                    warmer['enabled'] = True
                    logger.info(f"Enabled cache warmer: {name}")
                    break
    
    def disable_warmer(self, name: str):
        """Disable a cache warmer."""
        with self._lock:
            for warmer in self._warmers:
                if warmer['name'] == name:
                    warmer['enabled'] = False
                    logger.info(f"Disabled cache warmer: {name}")
                    break
    
    def warm_now(self, name: Optional[str] = None) -> Dict[str, Any]:
        """
        Run cache warming immediately.
        
        Args:
            name: Warmer name (None = all warmers)
            
        Returns:
            Results dictionary
        """
        results = {}
        
        with self._lock:
            warmers_to_run = self._warmers if name is None else [
                w for w in self._warmers if w['name'] == name
            ]
        
        for warmer in warmers_to_run:
            if not warmer['enabled']:
                continue
            
            result = self._run_warmer(warmer)
            results[warmer['name']] = result
        
        return results
    
    def _run_warmer(self, warmer: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run a single warmer.
        
        Args:
            warmer: Warmer configuration
            
        Returns:
            Result dictionary
        """
        start_time = time.time()
        
        try:
            logger.info(f"Running cache warmer: {warmer['name']}")
            
            # Call factory function
            data = warmer['factory']()
            
            if not isinstance(data, dict):
                raise ValueError(f"Factory must return dict, got {type(data)}")
            
            # Cache all values
            self.cache_manager.set_many(data, ttl=warmer['ttl'])
            
            # Update statistics
            warmer['last_run'] = datetime.now()
            warmer['next_run'] = datetime.now() + timedelta(seconds=warmer['interval_seconds'])
            warmer['run_count'] += 1
            warmer['success_count'] += 1
            warmer['last_error'] = None
            
            duration = time.time() - start_time
            
            logger.info(
                f"Cache warmer {warmer['name']} completed: "
                f"{len(data)} keys cached in {duration:.2f}s"
            )
            
            return {
                'success': True,
                'keys_cached': len(data),
                'duration_seconds': duration
            }
            
        except Exception as e:
            warmer['error_count'] += 1
            warmer['last_error'] = str(e)
            
            logger.error(f"Cache warmer {warmer['name']} failed: {e}")
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def start(self):
        """Start cache warmer background thread."""
        if self._running:
            logger.warning("Cache warmer already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        
        logger.info("Cache warmer started")
    
    def stop(self):
        """Stop cache warmer background thread."""
        if not self._running:
            return
        
        self._running = False
        
        if self._thread:
            self._thread.join(timeout=5)
        
        logger.info("Cache warmer stopped")
    
    def _run_loop(self):
        """Main loop for cache warmer."""
        while self._running:
            try:
                now = datetime.now()
                
                with self._lock:
                    warmers_to_run = [
                        w for w in self._warmers
                        if w['enabled'] and w['next_run'] <= now
                    ]
                
                for warmer in warmers_to_run:
                    if not self._running:
                        break
                    
                    self._run_warmer(warmer)
                
                # Sleep for 1 second
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Cache warmer loop error: {e}")
                time.sleep(5)
    
    def get_status(self) -> Dict[str, Any]:
        """
        Get cache warmer status.
        
        Returns:
            Status dictionary
        """
        with self._lock:
            warmers_status = []
            
            for warmer in self._warmers:
                warmers_status.append({
                    'name': warmer['name'],
                    'enabled': warmer['enabled'],
                    'interval_seconds': warmer['interval_seconds'],
                    'priority': warmer['priority'],
                    'last_run': warmer['last_run'].isoformat() if warmer['last_run'] else None,
                    'next_run': warmer['next_run'].isoformat() if warmer['next_run'] else None,
                    'run_count': warmer['run_count'],
                    'success_count': warmer['success_count'],
                    'error_count': warmer['error_count'],
                    'last_error': warmer['last_error']
                })
            
            return {
                'running': self._running,
                'total_warmers': len(self._warmers),
                'enabled_warmers': sum(1 for w in self._warmers if w['enabled']),
                'warmers': warmers_status
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache warmer statistics.
        
        Returns:
            Statistics dictionary
        """
        with self._lock:
            total_runs = sum(w['run_count'] for w in self._warmers)
            total_successes = sum(w['success_count'] for w in self._warmers)
            total_errors = sum(w['error_count'] for w in self._warmers)
            
            success_rate = (total_successes / total_runs * 100) if total_runs > 0 else 0
            
            return {
                'running': self._running,
                'total_warmers': len(self._warmers),
                'enabled_warmers': sum(1 for w in self._warmers if w['enabled']),
                'total_runs': total_runs,
                'total_successes': total_successes,
                'total_errors': total_errors,
                'success_rate_percent': round(success_rate, 2)
            }


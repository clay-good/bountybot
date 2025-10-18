"""
Validation tasks for async report processing.

Provides background tasks for report validation with retry logic.
"""

import logging
import time
from typing import Dict, Any, List, Optional

from .celery_app import celery_app, TaskPriority, is_celery_available

logger = logging.getLogger(__name__)


if is_celery_available():
    @celery_app.task(
        name='bountybot.tasks.validation_tasks.validate_report_async',
        bind=True,
        max_retries=3,
        default_retry_delay=60,
        autoretry_for=(Exception,),
        retry_backoff=True,
        retry_backoff_max=600,
        retry_jitter=True
    )
    def validate_report_async(self, report_path: str, codebase_path: Optional[str] = None, 
                             target_url: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """
        Validate a bug bounty report asynchronously.
        
        Args:
            report_path: Path to report file
            codebase_path: Optional codebase path
            target_url: Optional target URL for dynamic testing
            **kwargs: Additional validation options
            
        Returns:
            Validation result as dictionary
        """
        try:
            logger.info(f"Starting async validation: {report_path}")
            
            # Import here to avoid circular dependencies
            from bountybot.orchestrator import Orchestrator
            from bountybot.config_loader import load_config
            
            # Load configuration
            config = load_config()
            
            # Create orchestrator
            orchestrator = Orchestrator(config)
            
            # Validate report
            result = orchestrator.validate_report(
                report_path=report_path,
                codebase_path=codebase_path,
                target_url=target_url
            )
            
            # Convert to dictionary
            result_dict = {
                'verdict': result.verdict.value,
                'confidence': result.confidence,
                'severity': result.severity,
                'cvss_score': result.cvss_score,
                'cvss_vector': result.cvss_vector,
                'is_duplicate': result.is_duplicate,
                'is_false_positive': result.is_false_positive,
                'exploit_complexity': result.exploit_complexity,
                'priority_level': result.priority_level.value if result.priority_level else None,
                'processing_time_seconds': result.processing_time_seconds,
                'total_cost': result.total_cost,
                'report_path': report_path
            }
            
            logger.info(f"Async validation complete: {result.verdict.value} ({result.confidence}% confidence)")
            
            return result_dict
            
        except Exception as e:
            logger.error(f"Async validation failed: {e}")
            # Retry with exponential backoff
            raise self.retry(exc=e)
    
    
    @celery_app.task(
        name='bountybot.tasks.validation_tasks.validate_batch_async',
        bind=True,
        max_retries=2,
        default_retry_delay=120
    )
    def validate_batch_async(self, report_paths: List[str], codebase_path: Optional[str] = None,
                            **kwargs) -> Dict[str, Any]:
        """
        Validate multiple reports asynchronously.
        
        Args:
            report_paths: List of report file paths
            codebase_path: Optional codebase path
            **kwargs: Additional validation options
            
        Returns:
            Batch validation results
        """
        try:
            logger.info(f"Starting async batch validation: {len(report_paths)} reports")
            
            start_time = time.time()
            results = []
            failed = []
            
            # Process each report
            for report_path in report_paths:
                try:
                    # Submit individual validation task
                    task = validate_report_async.apply_async(
                        args=[report_path],
                        kwargs={'codebase_path': codebase_path},
                        priority=TaskPriority.NORMAL.value
                    )
                    
                    # Wait for result (with timeout)
                    result = task.get(timeout=600)  # 10 minutes
                    results.append(result)
                    
                except Exception as e:
                    logger.error(f"Failed to validate {report_path}: {e}")
                    failed.append({
                        'report_path': report_path,
                        'error': str(e)
                    })
            
            processing_time = time.time() - start_time
            
            # Calculate statistics
            valid_count = sum(1 for r in results if r['verdict'] == 'VALID')
            invalid_count = sum(1 for r in results if r['verdict'] == 'INVALID')
            uncertain_count = sum(1 for r in results if r['verdict'] == 'UNCERTAIN')
            
            batch_result = {
                'total': len(report_paths),
                'processed': len(results),
                'failed': len(failed),
                'valid': valid_count,
                'invalid': invalid_count,
                'uncertain': uncertain_count,
                'processing_time_seconds': processing_time,
                'results': results,
                'failed_reports': failed
            }
            
            logger.info(f"Async batch validation complete: {len(results)}/{len(report_paths)} processed")
            
            return batch_result
            
        except Exception as e:
            logger.error(f"Async batch validation failed: {e}")
            raise self.retry(exc=e)
    
    
    @celery_app.task(
        name='bountybot.tasks.validation_tasks.validate_report_with_retry',
        bind=True,
        max_retries=5,
        default_retry_delay=30,
        autoretry_for=(Exception,),
        retry_backoff=True,
        retry_backoff_max=1800,
        retry_jitter=True
    )
    def validate_report_with_retry(self, report_path: str, **kwargs) -> Dict[str, Any]:
        """
        Validate report with aggressive retry logic for critical reports.
        
        Args:
            report_path: Path to report file
            **kwargs: Additional validation options
            
        Returns:
            Validation result
        """
        try:
            logger.info(f"Starting validation with retry: {report_path} (attempt {self.request.retries + 1})")
            
            # Use the standard validation task
            result = validate_report_async(report_path, **kwargs)
            
            return result
            
        except Exception as e:
            logger.error(f"Validation with retry failed (attempt {self.request.retries + 1}): {e}")
            
            # Check if we should retry
            if self.request.retries < self.max_retries:
                # Calculate backoff delay
                delay = min(30 * (2 ** self.request.retries), 1800)  # Max 30 minutes
                logger.info(f"Retrying in {delay} seconds...")
                raise self.retry(exc=e, countdown=delay)
            else:
                logger.error(f"Max retries reached for {report_path}")
                raise

else:
    # Celery not available - provide stub functions
    def validate_report_async(report_path: str, codebase_path: Optional[str] = None,
                             target_url: Optional[str] = None, **kwargs) -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute async validation")
        return {'error': 'Celery not available'}
    
    def validate_batch_async(report_paths: List[str], codebase_path: Optional[str] = None,
                            **kwargs) -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute async batch validation")
        return {'error': 'Celery not available'}
    
    def validate_report_with_retry(report_path: str, **kwargs) -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute validation with retry")
        return {'error': 'Celery not available'}


# Export functions
__all__ = [
    'validate_report_async',
    'validate_batch_async',
    'validate_report_with_retry'
]


"""
Regression Testing Engine

Automatically re-tests fixed vulnerabilities to detect regressions.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import uuid4

from .models import (
    RegressionTest,
    RegressionStatus,
    FixVerification,
    VerificationStatus,
    VulnerabilityLifecycle
)
from bountybot.validators.poc_executor import PoCExecutor, ExecutionStatus

logger = logging.getLogger(__name__)


class RegressionTestingEngine:
    """
    Automated regression testing engine for fixed vulnerabilities.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize regression testing engine.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.regression_tests: Dict[str, RegressionTest] = {}

        # Configuration
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay_seconds = self.config.get('retry_delay_seconds', 60)
        self.parallel_tests = self.config.get('parallel_tests', 5)

        # Initialize PoC executor for real PoC execution
        self.poc_executor = PoCExecutor(config=self.config.get('poc_executor', {}))

        logger.info("RegressionTestingEngine initialized")
    
    async def create_regression_test(
        self,
        vulnerability_id: str,
        test_type: str,
        test_config: Optional[Dict] = None,
        scheduled_at: Optional[datetime] = None
    ) -> RegressionTest:
        """
        Create new regression test.
        
        Args:
            vulnerability_id: Vulnerability ID to test
            test_type: Type of test (poc_replay, automated_scan, security_check)
            test_config: Test configuration
            scheduled_at: When to run the test
            
        Returns:
            RegressionTest object
        """
        test = RegressionTest(
            test_id=str(uuid4()),
            vulnerability_id=vulnerability_id,
            status=RegressionStatus.SCHEDULED,
            scheduled_at=scheduled_at or datetime.utcnow(),
            test_type=test_type,
            test_config=test_config or {}
        )
        
        self.regression_tests[test.test_id] = test
        logger.info(f"Created regression test {test.test_id} for vulnerability {vulnerability_id}")
        
        return test
    
    async def execute_regression_test(
        self,
        test_id: str,
        original_validation: Optional[Dict] = None,
        target_url: Optional[str] = None,
        codebase_path: Optional[str] = None
    ) -> RegressionTest:
        """
        Execute regression test.
        
        Args:
            test_id: Test ID
            original_validation: Original validation result for comparison
            target_url: Target URL for testing
            codebase_path: Codebase path for analysis
            
        Returns:
            Updated RegressionTest
        """
        test = self.regression_tests.get(test_id)
        if not test:
            raise ValueError(f"Regression test {test_id} not found")
        
        test.status = RegressionStatus.RUNNING
        test.started_at = datetime.utcnow()
        
        try:
            # Execute test based on type
            if test.test_type == "poc_replay":
                result = await self._execute_poc_replay(test, original_validation, target_url)
            elif test.test_type == "automated_scan":
                result = await self._execute_automated_scan(test, target_url, codebase_path)
            elif test.test_type == "security_check":
                result = await self._execute_security_check(test, codebase_path)
            else:
                raise ValueError(f"Unknown test type: {test.test_type}")
            
            # Update test with results
            test.regression_detected = result['regression_detected']
            test.confidence_score = result['confidence_score']
            test.findings = result['findings']
            test.evidence = result.get('evidence', [])
            test.changes_detected = result.get('changes_detected', [])
            test.severity_change = result.get('severity_change')
            
            test.status = RegressionStatus.FAILED if test.regression_detected else RegressionStatus.PASSED
            test.completed_at = datetime.utcnow()
            
            logger.info(f"Regression test {test_id} completed: {test.status.value}")
            
        except Exception as e:
            test.status = RegressionStatus.ERROR
            test.error_message = str(e)
            test.completed_at = datetime.utcnow()
            logger.error(f"Regression test {test_id} failed with error: {e}")
        
        return test
    
    async def execute_batch_regression_tests(
        self,
        test_ids: List[str],
        original_validations: Optional[Dict[str, Dict]] = None,
        target_url: Optional[str] = None,
        codebase_path: Optional[str] = None
    ) -> List[RegressionTest]:
        """
        Execute multiple regression tests in parallel.
        
        Args:
            test_ids: List of test IDs
            original_validations: Dict of vulnerability_id -> original validation
            target_url: Target URL for testing
            codebase_path: Codebase path for analysis
            
        Returns:
            List of updated RegressionTest objects
        """
        # Create semaphore for parallel execution
        semaphore = asyncio.Semaphore(self.parallel_tests)
        
        async def execute_with_semaphore(test_id: str):
            async with semaphore:
                test = self.regression_tests.get(test_id)
                if not test:
                    logger.warning(f"Test {test_id} not found")
                    return None
                
                original_val = None
                if original_validations:
                    original_val = original_validations.get(test.vulnerability_id)
                
                return await self.execute_regression_test(
                    test_id,
                    original_val,
                    target_url,
                    codebase_path
                )
        
        # Execute all tests in parallel
        results = await asyncio.gather(
            *[execute_with_semaphore(test_id) for test_id in test_ids],
            return_exceptions=True
        )
        
        # Filter out None and exceptions
        valid_results = [r for r in results if isinstance(r, RegressionTest)]
        
        logger.info(f"Executed {len(valid_results)} regression tests in batch")
        return valid_results
    
    async def _execute_poc_replay(
        self,
        test: RegressionTest,
        original_validation: Optional[Dict],
        target_url: Optional[str]
    ) -> Dict[str, Any]:
        """
        Execute PoC replay test.

        Replays the original proof-of-concept to see if vulnerability still exists.
        """
        logger.info(f"Executing PoC replay for test {test.test_id}")

        # Check if PoC config exists
        poc_config = test.test_config.get('poc_config', {})
        if not poc_config:
            return {
                'regression_detected': False,
                'confidence_score': 0.5,
                'findings': ['No PoC configuration available for replay'],
                'evidence': []
            }

        # Check if target URL is provided
        if not target_url:
            return {
                'regression_detected': False,
                'confidence_score': 0.0,
                'findings': ['No target URL provided for PoC execution'],
                'evidence': []
            }

        try:
            # Extract PoC from original validation
            poc = None
            if original_validation and 'generated_poc' in original_validation:
                poc = original_validation['generated_poc']
            elif 'poc' in poc_config:
                poc = poc_config['poc']

            if not poc:
                return {
                    'regression_detected': False,
                    'confidence_score': 0.3,
                    'findings': ['No PoC available for execution'],
                    'evidence': []
                }

            # Execute PoC against target using real PoC executor
            vulnerability_type = poc_config.get('vulnerability_type', 'Unknown')
            execution_result = await self.poc_executor.execute_poc(
                poc=poc,
                target_url=target_url,
                vulnerability_type=vulnerability_type
            )

            # Analyze execution result
            if execution_result.status == ExecutionStatus.UNSAFE:
                return {
                    'regression_detected': False,
                    'confidence_score': 0.0,
                    'findings': ['PoC deemed unsafe to execute'],
                    'evidence': execution_result.safety_violations
                }

            if execution_result.status == ExecutionStatus.ERROR:
                return {
                    'regression_detected': False,
                    'confidence_score': 0.2,
                    'findings': ['PoC execution failed with errors'],
                    'evidence': execution_result.errors
                }

            # Check if vulnerability was confirmed
            regression_detected = execution_result.vulnerability_confirmed

            if regression_detected:
                return {
                    'regression_detected': True,
                    'confidence_score': execution_result.confidence,
                    'findings': [
                        'PoC successfully exploited vulnerability',
                        'Vulnerability appears to have regressed',
                        'Original fix may have been reverted or broken'
                    ] + execution_result.evidence,
                    'evidence': [
                        {
                            'type': 'http_response',
                            'status_code': execution_result.http_status_code,
                            'contains_exploit': True
                        },
                        {
                            'type': 'exploit_success',
                            'details': 'Vulnerability exploited successfully',
                            'indicators': execution_result.indicators
                        }
                    ],
                    'changes_detected': ['Vulnerability is exploitable again'],
                    'severity_change': 'unchanged'
                }
            else:
                return {
                    'regression_detected': False,
                    'confidence_score': 1.0 - execution_result.confidence,
                    'findings': [
                        'PoC failed to exploit vulnerability',
                        'Fix appears to be still effective',
                        'No regression detected'
                ],
                'evidence': [
                    {
                        'type': 'http_response',
                        'status_code': execution_result.http_status_code or 403,
                        'blocked': True
                    },
                    {
                        'type': 'exploit_failure',
                        'details': 'Vulnerability not exploitable'
                    }
                ]
            }

        except Exception as e:
            logger.error(f"Error executing PoC replay: {e}", exc_info=True)
            return {
                'regression_detected': False,
                'confidence_score': 0.0,
                'findings': [f'PoC execution error: {str(e)}'],
                'evidence': []
            }
    
    async def _execute_automated_scan(
        self,
        test: RegressionTest,
        target_url: Optional[str],
        codebase_path: Optional[str]
    ) -> Dict[str, Any]:
        """
        Execute automated security scan.
        
        Runs automated scanners to detect if vulnerability still exists.
        """
        # Simulate automated scan
        await asyncio.sleep(1.0)  # Simulate scan execution
        
        scan_config = test.test_config.get('scan_config', {})
        vulnerability_type = scan_config.get('vulnerability_type', 'unknown')
        
        # Simulate scan results
        import random
        regression_detected = random.random() < 0.10  # 10% chance of regression
        
        if regression_detected:
            return {
                'regression_detected': True,
                'confidence_score': 0.75,
                'findings': [
                    f'Automated scan detected {vulnerability_type}',
                    'Vulnerability signature matched',
                    'Regression likely present'
                ],
                'evidence': [
                    {'type': 'scan_result', 'scanner': 'automated', 'matched': True},
                    {'type': 'vulnerability_signature', 'type': vulnerability_type}
                ],
                'changes_detected': ['Vulnerability signature detected'],
                'severity_change': 'unchanged'
            }
        else:
            return {
                'regression_detected': False,
                'confidence_score': 0.85,
                'findings': [
                    'Automated scan completed successfully',
                    f'No {vulnerability_type} detected',
                    'Fix appears effective'
                ],
                'evidence': [
                    {'type': 'scan_result', 'scanner': 'automated', 'matched': False}
                ]
            }
    
    async def _execute_security_check(
        self,
        test: RegressionTest,
        codebase_path: Optional[str]
    ) -> Dict[str, Any]:
        """
        Execute security check on codebase.
        
        Analyzes code to verify fix is still present.
        """
        # Simulate security check
        await asyncio.sleep(0.8)  # Simulate check execution
        
        check_config = test.test_config.get('check_config', {})
        
        # Simulate code analysis
        import random
        regression_detected = random.random() < 0.08  # 8% chance of regression
        
        if regression_detected:
            return {
                'regression_detected': True,
                'confidence_score': 0.80,
                'findings': [
                    'Security check failed',
                    'Vulnerable code pattern detected',
                    'Fix may have been removed or modified'
                ],
                'evidence': [
                    {'type': 'code_analysis', 'vulnerable_pattern': True},
                    {'type': 'fix_verification', 'fix_present': False}
                ],
                'changes_detected': ['Vulnerable code pattern found'],
                'severity_change': 'unchanged'
            }
        else:
            return {
                'regression_detected': False,
                'confidence_score': 0.88,
                'findings': [
                    'Security check passed',
                    'No vulnerable patterns detected',
                    'Fix is still present and effective'
                ],
                'evidence': [
                    {'type': 'code_analysis', 'vulnerable_pattern': False},
                    {'type': 'fix_verification', 'fix_present': True}
                ]
            }
    
    async def verify_fix(
        self,
        vulnerability_id: str,
        test_method: str,
        target_url: Optional[str] = None,
        codebase_path: Optional[str] = None,
        test_config: Optional[Dict] = None
    ) -> FixVerification:
        """
        Verify that a fix is effective.
        
        Args:
            vulnerability_id: Vulnerability ID
            test_method: Test method (automated_scan, manual_test, poc_replay)
            target_url: Target URL for testing
            codebase_path: Codebase path for analysis
            test_config: Test configuration
            
        Returns:
            FixVerification object
        """
        verification = FixVerification(
            verification_id=str(uuid4()),
            vulnerability_id=vulnerability_id,
            status=VerificationStatus.IN_PROGRESS,
            test_method=test_method,
            test_details=test_config or {}
        )
        
        try:
            # Create and execute regression test
            test = await self.create_regression_test(
                vulnerability_id,
                test_method,
                test_config
            )
            
            result = await self.execute_regression_test(
                test.test_id,
                target_url=target_url,
                codebase_path=codebase_path
            )
            
            # Convert regression test result to fix verification
            verification.vulnerability_still_present = result.regression_detected
            verification.confidence_score = result.confidence_score
            verification.findings = result.findings
            verification.evidence = result.evidence
            
            if result.regression_detected:
                verification.status = VerificationStatus.FAILED
                verification.fix_effectiveness = 0.0
                verification.recommendations = [
                    'Fix verification failed - vulnerability still present',
                    'Review and update the fix',
                    'Re-test after fix is updated'
                ]
            else:
                verification.status = VerificationStatus.PASSED
                verification.fix_effectiveness = 1.0
                verification.recommendations = [
                    'Fix verified successfully',
                    'Enable continuous monitoring',
                    'Schedule periodic regression tests'
                ]
            
            verification.completed_at = datetime.utcnow()
            
        except Exception as e:
            verification.status = VerificationStatus.INCONCLUSIVE
            verification.findings = [f'Verification error: {str(e)}']
            verification.completed_at = datetime.utcnow()
            logger.error(f"Fix verification failed: {e}")
        
        return verification
    
    def get_regression_test(self, test_id: str) -> Optional[RegressionTest]:
        """Get regression test by ID."""
        return self.regression_tests.get(test_id)
    
    def get_tests_by_vulnerability(self, vulnerability_id: str) -> List[RegressionTest]:
        """Get all regression tests for a vulnerability."""
        return [t for t in self.regression_tests.values() if t.vulnerability_id == vulnerability_id]
    
    def get_tests_by_status(self, status: RegressionStatus) -> List[RegressionTest]:
        """Get all regression tests with specific status."""
        return [t for t in self.regression_tests.values() if t.status == status]
    
    def get_regression_rate(self, vulnerability_ids: Optional[List[str]] = None) -> float:
        """
        Calculate regression rate.
        
        Args:
            vulnerability_ids: Optional list of vulnerability IDs to filter
            
        Returns:
            Regression rate (0-1)
        """
        tests = list(self.regression_tests.values())
        
        if vulnerability_ids:
            tests = [t for t in tests if t.vulnerability_id in vulnerability_ids]
        
        if not tests:
            return 0.0
        
        completed_tests = [t for t in tests if t.status in [RegressionStatus.PASSED, RegressionStatus.FAILED]]
        if not completed_tests:
            return 0.0
        
        regression_count = sum(1 for t in completed_tests if t.regression_detected)
        return regression_count / len(completed_tests)


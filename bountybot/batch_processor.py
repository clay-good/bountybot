import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from bountybot.orchestrator import Orchestrator
from bountybot.models import ValidationResult, Verdict

logger = logging.getLogger(__name__)


class BatchProcessor:
    """
    Process multiple bug reports in batch mode.
    Supports parallel processing and progress tracking.
    """
    
    def __init__(self, orchestrator: Orchestrator, max_workers: int = 3):
        """
        Initialize batch processor.
        
        Args:
            orchestrator: Validation orchestrator
            max_workers: Maximum number of parallel workers
        """
        self.orchestrator = orchestrator
        self.max_workers = max_workers
    
    def process_directory(
        self,
        input_dir: str,
        output_dir: str,
        codebase_path: Optional[str] = None,
        output_formats: Optional[List[str]] = None,
        parallel: bool = True
    ) -> Dict[str, Any]:
        """
        Process all reports in a directory.
        
        Args:
            input_dir: Directory containing report files
            output_dir: Directory for output files
            codebase_path: Optional path to codebase for analysis
            output_formats: List of output formats
            parallel: Whether to process in parallel
            
        Returns:
            Dictionary with batch processing results
        """
        input_path = Path(input_dir)
        
        if not input_path.exists():
            raise ValueError(f"Input directory does not exist: {input_dir}")
        
        # Find all report files
        report_files = []
        for ext in ['.json', '.md', '.txt']:
            report_files.extend(input_path.glob(f"*{ext}"))
        
        if not report_files:
            logger.warning(f"No report files found in {input_dir}")
            return {
                'total': 0,
                'processed': 0,
                'failed': 0,
                'results': []
            }
        
        logger.info(f"Found {len(report_files)} report files to process")
        
        start_time = time.time()
        results = []
        failed = []
        
        if parallel and len(report_files) > 1:
            results, failed = self._process_parallel(
                report_files, output_dir, codebase_path, output_formats
            )
        else:
            results, failed = self._process_sequential(
                report_files, output_dir, codebase_path, output_formats
            )
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # Calculate statistics
        stats = self._calculate_statistics(results)
        
        summary = {
            'total': len(report_files),
            'processed': len(results),
            'failed': len(failed),
            'processing_time': total_time,
            'statistics': stats,
            'results': results,
            'failed_files': failed
        }
        
        logger.info(f"Batch processing complete: {len(results)}/{len(report_files)} successful")
        
        return summary
    
    def _process_sequential(
        self,
        report_files: List[Path],
        output_dir: str,
        codebase_path: Optional[str],
        output_formats: Optional[List[str]]
    ) -> tuple:
        """Process reports sequentially."""
        results = []
        failed = []
        
        for i, report_file in enumerate(report_files, 1):
            logger.info(f"Processing {i}/{len(report_files)}: {report_file.name}")
            
            try:
                result = self.orchestrator.validate_report(
                    report_path=str(report_file),
                    codebase_path=codebase_path
                )
                results.append({
                    'file': str(report_file),
                    'result': result
                })
            except Exception as e:
                logger.error(f"Failed to process {report_file.name}: {e}")
                failed.append({
                    'file': str(report_file),
                    'error': str(e)
                })
        
        return results, failed
    
    def _process_parallel(
        self,
        report_files: List[Path],
        output_dir: str,
        codebase_path: Optional[str],
        output_formats: Optional[List[str]]
    ) -> tuple:
        """Process reports in parallel."""
        results = []
        failed = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_file = {
                executor.submit(
                    self.orchestrator.validate_report,
                    str(report_file),
                    codebase_path
                ): report_file
                for report_file in report_files
            }
            
            # Process completed tasks
            for i, future in enumerate(as_completed(future_to_file), 1):
                report_file = future_to_file[future]
                logger.info(f"Completed {i}/{len(report_files)}: {report_file.name}")
                
                try:
                    result = future.result()
                    results.append({
                        'file': str(report_file),
                        'result': result
                    })
                except Exception as e:
                    logger.error(f"Failed to process {report_file.name}: {e}")
                    failed.append({
                        'file': str(report_file),
                        'error': str(e)
                    })
        
        return results, failed
    
    def _calculate_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate statistics from batch results.
        
        Args:
            results: List of result dictionaries
            
        Returns:
            Statistics dictionary
        """
        if not results:
            return {}
        
        verdicts = {
            'VALID': 0,
            'INVALID': 0,
            'UNCERTAIN': 0
        }
        
        total_cost = 0.0
        total_time = 0.0
        confidence_scores = []
        
        for item in results:
            result: ValidationResult = item['result']
            
            # Count verdicts
            verdict_str = result.verdict.value if hasattr(result.verdict, 'value') else str(result.verdict)
            if verdict_str in verdicts:
                verdicts[verdict_str] += 1
            
            # Sum costs and times
            total_cost += result.total_cost
            total_time += result.processing_time_seconds
            
            # Collect confidence scores
            confidence_scores.append(result.confidence)
        
        avg_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0
        
        return {
            'verdicts': verdicts,
            'total_cost': total_cost,
            'total_time': total_time,
            'average_confidence': avg_confidence,
            'average_cost_per_report': total_cost / len(results) if results else 0,
            'average_time_per_report': total_time / len(results) if results else 0
        }
    
    def generate_batch_report(self, summary: Dict[str, Any], output_path: str):
        """
        Generate a summary report for batch processing.
        
        Args:
            summary: Batch processing summary
            output_path: Path to save report
        """
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'w') as f:
            f.write("# Batch Validation Report\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- Total Reports: {summary['total']}\n")
            f.write(f"- Successfully Processed: {summary['processed']}\n")
            f.write(f"- Failed: {summary['failed']}\n")
            f.write(f"- Processing Time: {summary['processing_time']:.2f}s\n\n")
            
            # Statistics
            if 'statistics' in summary and summary['statistics']:
                stats = summary['statistics']
                f.write("## Statistics\n\n")
                
                if 'verdicts' in stats:
                    f.write("### Verdicts\n\n")
                    for verdict, count in stats['verdicts'].items():
                        f.write(f"- {verdict}: {count}\n")
                    f.write("\n")
                
                f.write(f"- Average Confidence: {stats.get('average_confidence', 0):.1f}%\n")
                f.write(f"- Total Cost: ${stats.get('total_cost', 0):.4f}\n")
                f.write(f"- Average Cost per Report: ${stats.get('average_cost_per_report', 0):.4f}\n")
                f.write(f"- Average Time per Report: {stats.get('average_time_per_report', 0):.2f}s\n\n")
            
            # Individual Results
            f.write("## Individual Results\n\n")
            for item in summary.get('results', []):
                result: ValidationResult = item['result']
                file_name = Path(item['file']).name
                
                verdict_str = result.verdict.value if hasattr(result.verdict, 'value') else str(result.verdict)
                
                f.write(f"### {result.report.title}\n\n")
                f.write(f"- File: {file_name}\n")
                f.write(f"- Verdict: {verdict_str}\n")
                f.write(f"- Confidence: {result.confidence}%\n")
                f.write(f"- Cost: ${result.total_cost:.4f}\n")
                f.write(f"- Time: {result.processing_time_seconds:.2f}s\n\n")
            
            # Failed Reports
            if summary.get('failed_files'):
                f.write("## Failed Reports\n\n")
                for item in summary['failed_files']:
                    file_name = Path(item['file']).name
                    f.write(f"- {file_name}: {item['error']}\n")
        
        logger.info(f"Batch report saved to: {output_file}")


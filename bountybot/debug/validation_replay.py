"""
Validation replay and debugging tools.

Allows replaying validations, comparing results, and debugging failures.
"""

import logging
import json
import pickle
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, asdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich import box

logger = logging.getLogger(__name__)
console = Console()


@dataclass
class ValidationSnapshot:
    """Snapshot of validation execution."""
    timestamp: str
    report_path: str
    config: Dict[str, Any]
    report_data: Dict[str, Any]
    http_requests: List[Dict[str, Any]]
    quality_assessment: Dict[str, Any]
    plausibility_analysis: Dict[str, Any]
    code_analysis: Optional[Dict[str, Any]]
    dynamic_scan: Optional[Dict[str, Any]]
    validation_result: Dict[str, Any]
    performance_metrics: Dict[str, Any]
    errors: List[Dict[str, Any]]


class ValidationReplay:
    """
    Replay and debug validation executions.
    
    Features:
    - Save validation snapshots
    - Replay validations with same inputs
    - Compare results across runs
    - Debug failures with full context
    - Export/import snapshots
    """
    
    def __init__(self, snapshot_dir: str = "./validation_snapshots"):
        """
        Initialize validation replay.
        
        Args:
            snapshot_dir: Directory to store snapshots
        """
        self.snapshot_dir = Path(snapshot_dir)
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        
    def save_snapshot(
        self,
        report_path: str,
        config: Dict[str, Any],
        report_data: Dict[str, Any],
        http_requests: List[Dict[str, Any]],
        quality_assessment: Dict[str, Any],
        plausibility_analysis: Dict[str, Any],
        validation_result: Dict[str, Any],
        code_analysis: Optional[Dict[str, Any]] = None,
        dynamic_scan: Optional[Dict[str, Any]] = None,
        performance_metrics: Optional[Dict[str, Any]] = None,
        errors: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Save validation snapshot.
        
        Args:
            report_path: Path to report file
            config: Configuration used
            report_data: Parsed report data
            http_requests: Extracted HTTP requests
            quality_assessment: Quality assessment results
            plausibility_analysis: Plausibility analysis results
            validation_result: Final validation result
            code_analysis: Code analysis results
            dynamic_scan: Dynamic scan results
            performance_metrics: Performance metrics
            errors: List of errors encountered
            
        Returns:
            Snapshot ID
        """
        timestamp = datetime.utcnow().isoformat()
        snapshot_id = f"snapshot_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        snapshot = ValidationSnapshot(
            timestamp=timestamp,
            report_path=report_path,
            config=config,
            report_data=report_data,
            http_requests=http_requests,
            quality_assessment=quality_assessment,
            plausibility_analysis=plausibility_analysis,
            code_analysis=code_analysis,
            dynamic_scan=dynamic_scan,
            validation_result=validation_result,
            performance_metrics=performance_metrics or {},
            errors=errors or []
        )
        
        # Save as JSON
        snapshot_path = self.snapshot_dir / f"{snapshot_id}.json"
        with open(snapshot_path, 'w') as f:
            json.dump(asdict(snapshot), f, indent=2, default=str)
        
        logger.info(f"Snapshot saved: {snapshot_id}")
        console.print(f"[green]✓ Snapshot saved: {snapshot_id}[/green]")
        
        return snapshot_id
    
    def load_snapshot(self, snapshot_id: str) -> ValidationSnapshot:
        """
        Load validation snapshot.
        
        Args:
            snapshot_id: Snapshot ID
            
        Returns:
            ValidationSnapshot object
        """
        snapshot_path = self.snapshot_dir / f"{snapshot_id}.json"
        
        if not snapshot_path.exists():
            raise FileNotFoundError(f"Snapshot not found: {snapshot_id}")
        
        with open(snapshot_path, 'r') as f:
            data = json.load(f)
        
        return ValidationSnapshot(**data)
    
    def list_snapshots(self) -> List[str]:
        """
        List all available snapshots.
        
        Returns:
            List of snapshot IDs
        """
        snapshots = []
        for path in self.snapshot_dir.glob("snapshot_*.json"):
            snapshots.append(path.stem)
        
        return sorted(snapshots, reverse=True)
    
    def display_snapshot(self, snapshot_id: str):
        """
        Display snapshot details.
        
        Args:
            snapshot_id: Snapshot ID
        """
        snapshot = self.load_snapshot(snapshot_id)
        
        console.print(Panel.fit(
            f"[bold cyan]Validation Snapshot: {snapshot_id}[/bold cyan]",
            border_style="cyan"
        ))
        
        # Basic info table
        table = Table(title="Snapshot Details", box=box.ROUNDED)
        table.add_column("Field", style="cyan", no_wrap=True)
        table.add_column("Value", style="white")
        
        table.add_row("Timestamp", snapshot.timestamp)
        table.add_row("Report Path", snapshot.report_path)
        table.add_row("Verdict", snapshot.validation_result.get('verdict', 'Unknown'))
        table.add_row("Confidence", f"{snapshot.validation_result.get('confidence', 0):.1%}")
        table.add_row("Severity", snapshot.validation_result.get('severity', 'Unknown'))
        
        console.print(table)
        
        # Performance metrics
        if snapshot.performance_metrics:
            console.print("\n[bold]Performance Metrics:[/bold]")
            perf_table = Table(box=box.SIMPLE)
            perf_table.add_column("Stage", style="cyan")
            perf_table.add_column("Duration", style="white")
            
            for stage, duration in snapshot.performance_metrics.items():
                perf_table.add_row(stage, f"{duration:.2f}s")
            
            console.print(perf_table)
        
        # Errors
        if snapshot.errors:
            console.print(f"\n[bold red]Errors ({len(snapshot.errors)}):[/bold red]")
            for idx, error in enumerate(snapshot.errors, 1):
                console.print(f"  {idx}. {error.get('message', 'Unknown error')}")
    
    def compare_snapshots(self, snapshot_id1: str, snapshot_id2: str):
        """
        Compare two snapshots.
        
        Args:
            snapshot_id1: First snapshot ID
            snapshot_id2: Second snapshot ID
        """
        snapshot1 = self.load_snapshot(snapshot_id1)
        snapshot2 = self.load_snapshot(snapshot_id2)
        
        console.print(Panel.fit(
            f"[bold cyan]Comparing Snapshots[/bold cyan]\n"
            f"Snapshot 1: {snapshot_id1}\n"
            f"Snapshot 2: {snapshot_id2}",
            border_style="cyan"
        ))
        
        # Compare verdicts
        table = Table(title="Comparison", box=box.ROUNDED)
        table.add_column("Field", style="cyan")
        table.add_column("Snapshot 1", style="white")
        table.add_column("Snapshot 2", style="white")
        table.add_column("Match", style="white")
        
        verdict1 = snapshot1.validation_result.get('verdict')
        verdict2 = snapshot2.validation_result.get('verdict')
        match_verdict = "✓" if verdict1 == verdict2 else "✗"
        table.add_row("Verdict", verdict1, verdict2, match_verdict)
        
        conf1 = snapshot1.validation_result.get('confidence', 0)
        conf2 = snapshot2.validation_result.get('confidence', 0)
        conf_diff = abs(conf1 - conf2)
        match_conf = "✓" if conf_diff < 0.05 else "✗"
        table.add_row("Confidence", f"{conf1:.1%}", f"{conf2:.1%}", match_conf)
        
        sev1 = snapshot1.validation_result.get('severity')
        sev2 = snapshot2.validation_result.get('severity')
        match_sev = "✓" if sev1 == sev2 else "✗"
        table.add_row("Severity", sev1, sev2, match_sev)
        
        console.print(table)
        
        # Performance comparison
        if snapshot1.performance_metrics and snapshot2.performance_metrics:
            console.print("\n[bold]Performance Comparison:[/bold]")
            perf_table = Table(box=box.SIMPLE)
            perf_table.add_column("Stage", style="cyan")
            perf_table.add_column("Snapshot 1", style="white")
            perf_table.add_column("Snapshot 2", style="white")
            perf_table.add_column("Diff", style="white")
            
            all_stages = set(snapshot1.performance_metrics.keys()) | set(snapshot2.performance_metrics.keys())
            for stage in sorted(all_stages):
                dur1 = snapshot1.performance_metrics.get(stage, 0)
                dur2 = snapshot2.performance_metrics.get(stage, 0)
                diff = dur2 - dur1
                diff_str = f"{diff:+.2f}s" if diff != 0 else "0.00s"
                perf_table.add_row(stage, f"{dur1:.2f}s", f"{dur2:.2f}s", diff_str)
            
            console.print(perf_table)
    
    def export_snapshot(self, snapshot_id: str, output_path: str):
        """
        Export snapshot to file.
        
        Args:
            snapshot_id: Snapshot ID
            output_path: Output file path
        """
        snapshot = self.load_snapshot(snapshot_id)
        
        with open(output_path, 'w') as f:
            json.dump(asdict(snapshot), f, indent=2, default=str)
        
        console.print(f"[green]✓ Snapshot exported to {output_path}[/green]")
    
    def import_snapshot(self, input_path: str) -> str:
        """
        Import snapshot from file.
        
        Args:
            input_path: Input file path
            
        Returns:
            Snapshot ID
        """
        with open(input_path, 'r') as f:
            data = json.load(f)
        
        snapshot = ValidationSnapshot(**data)
        snapshot_id = f"snapshot_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_imported"
        
        snapshot_path = self.snapshot_dir / f"{snapshot_id}.json"
        with open(snapshot_path, 'w') as f:
            json.dump(asdict(snapshot), f, indent=2, default=str)
        
        console.print(f"[green]✓ Snapshot imported: {snapshot_id}[/green]")
        
        return snapshot_id


"""
Demo script for BountyBot Collaborative Workflow & Team Coordination (v2.13.0).

Demonstrates:
1. Workflow orchestration with state machines
2. Task assignments and approval chains
3. Real-time comments and @mentions
4. Activity feeds and notifications
5. SLA tracking and automated escalation
"""

from datetime import datetime, timedelta
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn

from bountybot.collaboration import (
    # Workflow
    WorkflowEngine,
    WorkflowExecutor,
    WorkflowState,
    TaskStatus,
    TaskPriority,
    
    # Collaboration
    CollaborationManager,
    NotificationType,
    
    # Activity feed
    ActivityFeedManager,
    ActivityType,
    
    # SLA
    SLAManager,
    SLAMonitor,
    EscalationEngine,
    SLAStatus,
    EscalationLevel,
)

console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.13.0[/bold cyan]\n"
        "[yellow]Collaborative Workflow & Team Coordination[/yellow]\n"
        "[dim]Transform security teams with real-time collaboration[/dim]",
        border_style="cyan"
    ))
    console.print()


def demo_workflow_orchestration():
    """Demonstrate workflow orchestration."""
    console.print("[bold]1. Workflow Orchestration[/bold]")
    console.print()
    
    # Create workflow engine
    engine = WorkflowEngine()
    
    # Get default security review workflow
    workflow_defs = list(engine.workflow_definitions.values())
    security_review = workflow_defs[0]
    
    console.print(f"[cyan]Workflow:[/cyan] {security_review.name}")
    console.print(f"[dim]Description: {security_review.description}[/dim]")
    console.print()
    
    # Create workflow instance
    instance = engine.create_workflow_instance(
        security_review.workflow_id,
        entity_type="report",
        entity_id="report-12345",
        started_by="analyst@acme.com",
        assigned_to="analyst@acme.com"
    )
    
    console.print(f"[green]✓[/green] Workflow instance created: {instance.instance_id[:8]}...")
    console.print(f"[cyan]Current State:[/cyan] {instance.current_state.value}")
    console.print()
    
    # Transition workflow
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Processing workflow...", total=3)
        
        # Start review
        engine.transition_workflow(instance.instance_id, "start_review", "analyst@acme.com")
        progress.advance(task)

        # Request approval - this transition requires approval metadata
        engine.transition_workflow(
            instance.instance_id,
            "request_approval",
            "analyst@acme.com",
            metadata={'approved': True}  # Analyst has approval to request approval
        )
        progress.advance(task)

        # Manager approves the request
        engine.transition_workflow(
            instance.instance_id,
            "approve",
            "manager@acme.com"
        )
        progress.advance(task)
    
    # Display workflow history
    table = Table(title="Workflow State History", box=box.ROUNDED)
    table.add_column("State", style="cyan")
    table.add_column("Action", style="magenta")
    table.add_column("User", style="yellow")
    table.add_column("Timestamp", style="dim")
    
    for entry in instance.state_history:
        table.add_row(
            entry['state'],
            entry.get('action', 'N/A'),
            entry.get('user', 'N/A'),
            entry['timestamp'][:19]
        )
    
    console.print(table)
    console.print()


def demo_task_assignments():
    """Demonstrate task assignments."""
    console.print("[bold]2. Task Assignments & Tracking[/bold]")
    console.print()
    
    engine = WorkflowEngine()
    workflow_defs = list(engine.workflow_definitions.values())
    
    instance = engine.create_workflow_instance(
        workflow_defs[0].workflow_id,
        entity_type="report",
        entity_id="report-12345",
        started_by="analyst@acme.com"
    )
    
    # Assign tasks
    tasks = []
    task_data = [
        ("Review vulnerability details", "analyst@acme.com", TaskPriority.HIGH, 4.0),
        ("Verify exploit PoC", "security@acme.com", TaskPriority.CRITICAL, 2.0),
        ("Approve remediation plan", "manager@acme.com", TaskPriority.MEDIUM, 8.0),
    ]
    
    for title, assignee, priority, due_hours in task_data:
        task = engine.assign_task(
            instance.instance_id,
            assigned_to=assignee,
            title=title,
            priority=priority,
            assigned_by="lead@acme.com",
            due_hours=due_hours
        )
        tasks.append(task)
    
    # Display tasks
    table = Table(title="Assigned Tasks", box=box.ROUNDED)
    table.add_column("Task", style="cyan")
    table.add_column("Assigned To", style="magenta")
    table.add_column("Priority", style="yellow")
    table.add_column("Status", style="green")
    table.add_column("Due In", style="dim")
    
    for task in tasks:
        priority_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "green"
        }
        priority_color = priority_colors.get(task.priority.value, "white")
        
        due_hours = (task.due_date - datetime.utcnow()).total_seconds() / 3600
        
        table.add_row(
            task.title,
            task.assigned_to,
            f"[{priority_color}]{task.priority.value.upper()}[/{priority_color}]",
            task.status.value,
            f"{due_hours:.1f}h"
        )
    
    console.print(table)
    console.print()
    
    # Complete a task
    engine.update_task_status(tasks[0].task_id, TaskStatus.COMPLETED, "analyst@acme.com")
    console.print(f"[green]✓[/green] Task completed: {tasks[0].title}")
    console.print()


def demo_comments_and_mentions():
    """Demonstrate comments and mentions."""
    console.print("[bold]3. Comments & @Mentions[/bold]")
    console.print()
    
    manager = CollaborationManager()
    
    # Add comments with mentions
    comment1 = manager.add_comment(
        entity_type="report",
        entity_id="report-12345",
        user_id="analyst@acme.com",
        user_name="Alice Analyst",
        content="This looks like a critical SQL injection. @bob can you verify the PoC? @charlie for approval."
    )
    
    comment2 = manager.add_comment(
        entity_type="report",
        entity_id="report-12345",
        user_id="bob@acme.com",
        user_name="Bob Security",
        content="@alice Verified! The PoC works. This is definitely exploitable.",
        parent_comment_id=comment1.comment_id
    )
    
    comment3 = manager.add_comment(
        entity_type="report",
        entity_id="report-12345",
        user_id="charlie@acme.com",
        user_name="Charlie Manager",
        content="Approved for immediate remediation. Great work team! 👍"
    )
    
    # Add reactions
    manager.add_reaction(comment2.comment_id, "alice@acme.com", "👍")
    manager.add_reaction(comment2.comment_id, "charlie@acme.com", "🎯")
    
    # Display comments
    table = Table(title="Comment Thread", box=box.ROUNDED)
    table.add_column("User", style="cyan")
    table.add_column("Comment", style="white")
    table.add_column("Mentions", style="magenta")
    table.add_column("Reactions", style="yellow")
    
    for comment in [comment1, comment2, comment3]:
        mentions_str = ", ".join(f"@{m}" for m in comment.mentions) if comment.mentions else "-"
        reactions_str = " ".join(f"{emoji}×{len(users)}" for emoji, users in comment.reactions.items()) if comment.reactions else "-"
        
        table.add_row(
            comment.user_name,
            comment.content[:60] + "..." if len(comment.content) > 60 else comment.content,
            mentions_str,
            reactions_str
        )
    
    console.print(table)
    console.print()
    
    # Display notifications
    console.print("[bold]Notifications:[/bold]")
    bob_notifications = manager.get_user_notifications("bob")
    charlie_notifications = manager.get_user_notifications("charlie")
    
    console.print(f"[cyan]@bob:[/cyan] {len(bob_notifications)} notification(s)")
    console.print(f"[cyan]@charlie:[/cyan] {len(charlie_notifications)} notification(s)")
    console.print()


def demo_activity_feed():
    """Demonstrate activity feed."""
    console.print("[bold]4. Activity Feed[/bold]")
    console.print()
    
    feed_manager = ActivityFeedManager()
    
    # Record activities
    activities_data = [
        (ActivityType.REPORT_CREATED, "Report #12345 created", "analyst@acme.com", "Alice Analyst"),
        (ActivityType.REPORT_VALIDATED, "Report #12345 validated as critical", "analyst@acme.com", "Alice Analyst"),
        (ActivityType.WORKFLOW_STARTED, "Security review workflow started", "analyst@acme.com", "Alice Analyst"),
        (ActivityType.TASK_ASSIGNED, "Task assigned to Bob Security", "lead@acme.com", "Lead Security"),
        (ActivityType.COMMENT_ADDED, "Alice commented on report", "analyst@acme.com", "Alice Analyst"),
        (ActivityType.USER_MENTIONED, "Bob mentioned in comment", "analyst@acme.com", "Alice Analyst"),
        (ActivityType.TASK_COMPLETED, "Vulnerability review completed", "bob@acme.com", "Bob Security"),
        (ActivityType.TASK_APPROVED, "Remediation plan approved", "charlie@acme.com", "Charlie Manager"),
    ]
    
    for activity_type, title, user_id, user_name in activities_data:
        feed_manager.record_activity(
            activity_type=activity_type,
            entity_type="report",
            entity_id="report-12345",
            user_id=user_id,
            user_name=user_name,
            title=title
        )
    
    # Display activity feed
    activities = feed_manager.get_activity_feed()
    
    table = Table(title="Recent Activity", box=box.ROUNDED)
    table.add_column("Activity", style="cyan")
    table.add_column("User", style="magenta")
    table.add_column("Time", style="dim")
    
    for activity in activities[:8]:
        table.add_row(
            activity.title,
            activity.user_name,
            "Just now"
        )
    
    console.print(table)
    console.print()
    
    # Display activity stats
    stats = feed_manager.get_activity_stats()
    
    console.print(Panel(
        f"[bold]Total Activities:[/bold] {stats['total_activities']}\n"
        f"[bold]Unique Users:[/bold] {stats['unique_users']}\n"
        f"[bold]Unique Entities:[/bold] {stats['unique_entities']}",
        title="[bold]Activity Statistics[/bold]",
        border_style="cyan"
    ))
    console.print()


def demo_sla_tracking():
    """Demonstrate SLA tracking."""
    console.print("[bold]5. SLA Tracking & Escalation[/bold]")
    console.print()
    
    sla_manager = SLAManager()
    
    # Create SLAs with different severities
    slas_data = [
        ("report-001", "critical", 4.0),
        ("report-002", "high", 24.0),
        ("report-003", "medium", 72.0),
    ]
    
    slas = []
    for entity_id, severity, target_hours in slas_data:
        sla = sla_manager.create_sla(
            entity_type="report",
            entity_id=entity_id,
            severity=severity
        )
        slas.append(sla)
    
    # Update SLAs
    for sla in slas:
        sla_manager.update_sla(sla.sla_id)
    
    # Display SLAs
    table = Table(title="Active SLAs", box=box.ROUNDED)
    table.add_column("Entity", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Target", style="yellow")
    table.add_column("Elapsed", style="white")
    table.add_column("Remaining", style="green")
    table.add_column("Status", style="bold")
    
    for sla in slas:
        severity_colors = {
            "critical": "red",
            "high": "orange",
            "medium": "yellow",
            "low": "green"
        }
        severity = sla.metadata.get('severity', 'medium')
        severity_color = severity_colors.get(severity, "white")
        
        status_colors = {
            "active": "green",
            "warning": "yellow",
            "breached": "red"
        }
        status_color = status_colors.get(sla.status.value, "white")
        
        table.add_row(
            sla.entity_id,
            f"[{severity_color}]{severity.upper()}[/{severity_color}]",
            f"{sla.target_hours:.1f}h",
            f"{sla.elapsed_hours:.2f}h",
            f"{sla.remaining_hours:.1f}h",
            f"[{status_color}]{sla.status.value.upper()}[/{status_color}]"
        )
    
    console.print(table)
    console.print()
    
    # Display SLA stats
    stats = sla_manager.get_sla_stats()
    
    console.print(Panel(
        f"[bold]Total SLAs:[/bold] {stats['total_slas']}\n"
        f"[bold]Active:[/bold] {stats['active']}\n"
        f"[bold]Warning:[/bold] {stats['warning']}\n"
        f"[bold]Breached:[/bold] {stats['breached']}",
        title="[bold]SLA Statistics[/bold]",
        border_style="yellow"
    ))
    console.print()


def demo_escalation_engine():
    """Demonstrate escalation engine."""
    console.print("[bold]6. Automated Escalation[/bold]")
    console.print()
    
    sla_manager = SLAManager()
    escalation_engine = EscalationEngine(sla_manager)
    
    # Add escalation rules
    rules = [
        ("Critical - Level 1", "report", "critical", 1.0, EscalationLevel.LEVEL_1, ["lead@acme.com"]),
        ("Critical - Level 2", "report", "critical", 2.0, EscalationLevel.LEVEL_2, ["manager@acme.com"]),
        ("High - Level 1", "report", "high", 4.0, EscalationLevel.LEVEL_1, ["lead@acme.com"]),
    ]
    
    for name, entity_type, severity, breach_hours, level, escalate_to in rules:
        escalation_engine.add_escalation_rule(
            name=name,
            entity_type=entity_type,
            severity=severity,
            breach_duration_hours=breach_hours,
            escalation_level=level,
            escalate_to=escalate_to
        )
    
    # Display escalation rules
    table = Table(title="Escalation Rules", box=box.ROUNDED)
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Breach Duration", style="yellow")
    table.add_column("Level", style="red")
    table.add_column("Escalate To", style="green")
    
    for rule in escalation_engine.escalation_rules.values():
        table.add_row(
            rule.name,
            rule.severity or "All",
            f"{rule.breach_duration_hours:.1f}h",
            rule.escalation_level.value.replace("_", " ").title(),
            ", ".join(rule.escalate_to)
        )
    
    console.print(table)
    console.print()


def main():
    """Run all demos."""
    print_header()
    
    demo_workflow_orchestration()
    demo_task_assignments()
    demo_comments_and_mentions()
    demo_activity_feed()
    demo_sla_tracking()
    demo_escalation_engine()
    
    console.print(Panel.fit(
        "[bold green]✓ Demo Complete![/bold green]\n"
        "[yellow]BountyBot v2.13.0 - Collaborative Workflow & Team Coordination[/yellow]\n"
        "[dim]Transform security teams with real-time collaboration and automated workflows[/dim]",
        border_style="green"
    ))


if __name__ == '__main__':
    main()


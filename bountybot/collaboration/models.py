"""
Data models for collaborative workflow and team coordination.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4


# ============================================================================
# Workflow Models
# ============================================================================

class WorkflowState(str, Enum):
    """Workflow states."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    WAITING_APPROVAL = "waiting_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"


class TaskStatus(str, Enum):
    """Task status."""
    TODO = "todo"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    WAITING_REVIEW = "waiting_review"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class TaskPriority(str, Enum):
    """Task priority."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    """Approval status."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


@dataclass
class WorkflowTransition:
    """Workflow state transition."""
    from_state: WorkflowState
    to_state: WorkflowState
    action: str
    condition: Optional[str] = None
    auto_transition: bool = False
    requires_approval: bool = False
    approvers: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowDefinition:
    """Workflow definition with states and transitions."""
    workflow_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    description: str = ""
    initial_state: WorkflowState = WorkflowState.PENDING
    states: List[WorkflowState] = field(default_factory=list)
    transitions: List[WorkflowTransition] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowInstance:
    """Running instance of a workflow."""
    instance_id: str = field(default_factory=lambda: str(uuid4()))
    workflow_id: str = ""
    workflow_name: str = ""
    entity_type: str = ""  # e.g., "report", "vulnerability"
    entity_id: str = ""
    current_state: WorkflowState = WorkflowState.PENDING
    previous_state: Optional[WorkflowState] = None
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    started_by: str = ""
    assigned_to: Optional[str] = None
    state_history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowTask:
    """Task within a workflow."""
    task_id: str = field(default_factory=lambda: str(uuid4()))
    workflow_instance_id: str = ""
    title: str = ""
    description: str = ""
    status: TaskStatus = TaskStatus.TODO
    priority: TaskPriority = TaskPriority.MEDIUM
    assigned_to: Optional[str] = None
    assigned_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    due_date: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    blocked_reason: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)  # task_ids
    approval_status: Optional[ApprovalStatus] = None
    approvers: List[str] = field(default_factory=list)
    approved_by: List[str] = field(default_factory=list)
    rejected_by: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# Collaboration Models
# ============================================================================

@dataclass
class Comment:
    """Comment on a report or vulnerability."""
    comment_id: str = field(default_factory=lambda: str(uuid4()))
    entity_type: str = ""  # "report", "vulnerability", "task"
    entity_id: str = ""
    user_id: str = ""
    user_name: str = ""
    content: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    edited: bool = False
    parent_comment_id: Optional[str] = None  # For threaded comments
    mentions: List[str] = field(default_factory=list)  # user_ids mentioned
    attachments: List[Dict[str, str]] = field(default_factory=list)
    reactions: Dict[str, List[str]] = field(default_factory=dict)  # emoji -> [user_ids]
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Mention:
    """User mention in a comment or activity."""
    mention_id: str = field(default_factory=lambda: str(uuid4()))
    mentioned_user_id: str = ""
    mentioned_by_user_id: str = ""
    entity_type: str = ""
    entity_id: str = ""
    comment_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    read: bool = False
    read_at: Optional[datetime] = None


class ActivityType(str, Enum):
    """Activity types."""
    # Report activities
    REPORT_CREATED = "report_created"
    REPORT_UPDATED = "report_updated"
    REPORT_VALIDATED = "report_validated"
    REPORT_ASSIGNED = "report_assigned"
    
    # Workflow activities
    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_STATE_CHANGED = "workflow_state_changed"
    WORKFLOW_COMPLETED = "workflow_completed"
    
    # Task activities
    TASK_CREATED = "task_created"
    TASK_ASSIGNED = "task_assigned"
    TASK_COMPLETED = "task_completed"
    TASK_APPROVED = "task_approved"
    TASK_REJECTED = "task_rejected"
    
    # Collaboration activities
    COMMENT_ADDED = "comment_added"
    USER_MENTIONED = "user_mentioned"
    
    # SLA activities
    SLA_CREATED = "sla_created"
    SLA_WARNING = "sla_warning"
    SLA_BREACHED = "sla_breached"
    SLA_ESCALATED = "sla_escalated"


@dataclass
class Activity:
    """Activity feed entry."""
    activity_id: str = field(default_factory=lambda: str(uuid4()))
    activity_type: ActivityType = ActivityType.REPORT_CREATED
    entity_type: str = ""
    entity_id: str = ""
    user_id: str = ""
    user_name: str = ""
    title: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


class NotificationType(str, Enum):
    """Notification types."""
    TASK_ASSIGNED = "task_assigned"
    TASK_DUE_SOON = "task_due_soon"
    TASK_OVERDUE = "task_overdue"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_COMPLETED = "approval_completed"
    MENTION = "mention"
    COMMENT_REPLY = "comment_reply"
    SLA_WARNING = "sla_warning"
    SLA_BREACH = "sla_breach"
    WORKFLOW_COMPLETED = "workflow_completed"


class NotificationStatus(str, Enum):
    """Notification status."""
    UNREAD = "unread"
    READ = "read"
    ARCHIVED = "archived"


@dataclass
class Notification:
    """User notification."""
    notification_id: str = field(default_factory=lambda: str(uuid4()))
    user_id: str = ""
    notification_type: NotificationType = NotificationType.TASK_ASSIGNED
    title: str = ""
    message: str = ""
    status: NotificationStatus = NotificationStatus.UNREAD
    created_at: datetime = field(default_factory=datetime.utcnow)
    read_at: Optional[datetime] = None
    entity_type: Optional[str] = None
    entity_id: Optional[str] = None
    action_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ============================================================================
# SLA Models
# ============================================================================

class SLAStatus(str, Enum):
    """SLA status."""
    ACTIVE = "active"
    WARNING = "warning"  # Within warning threshold
    BREACHED = "breached"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EscalationLevel(str, Enum):
    """Escalation levels."""
    LEVEL_1 = "level_1"  # Team lead
    LEVEL_2 = "level_2"  # Manager
    LEVEL_3 = "level_3"  # Director
    LEVEL_4 = "level_4"  # VP/C-level


@dataclass
class SLA:
    """Service Level Agreement for a report or task."""
    sla_id: str = field(default_factory=lambda: str(uuid4()))
    entity_type: str = ""  # "report", "task", "vulnerability"
    entity_id: str = ""
    target_hours: float = 24.0
    warning_threshold_percent: float = 0.75  # Warn at 75% of target
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: datetime = field(default_factory=datetime.utcnow)
    target_completion_time: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))
    completed_at: Optional[datetime] = None
    status: SLAStatus = SLAStatus.ACTIVE
    elapsed_hours: float = 0.0
    remaining_hours: float = 24.0
    percent_elapsed: float = 0.0
    breached: bool = False
    breach_time: Optional[datetime] = None
    breach_duration_hours: float = 0.0
    escalation_level: Optional[EscalationLevel] = None
    escalated_to: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SLABreach:
    """SLA breach record."""
    breach_id: str = field(default_factory=lambda: str(uuid4()))
    sla_id: str = ""
    entity_type: str = ""
    entity_id: str = ""
    breach_time: datetime = field(default_factory=datetime.utcnow)
    target_hours: float = 24.0
    actual_hours: float = 0.0
    breach_duration_hours: float = 0.0
    severity: str = "medium"  # low, medium, high, critical
    notified_users: List[str] = field(default_factory=list)
    escalation_level: Optional[EscalationLevel] = None
    resolved: bool = False
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EscalationRule:
    """Escalation rule for SLA breaches."""
    rule_id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    entity_type: str = ""  # "report", "task", "vulnerability"
    severity: Optional[str] = None  # Filter by severity
    breach_duration_hours: float = 0.0  # Escalate after X hours of breach
    escalation_level: EscalationLevel = EscalationLevel.LEVEL_1
    escalate_to: List[str] = field(default_factory=list)  # user_ids or roles
    notification_template: str = ""
    active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


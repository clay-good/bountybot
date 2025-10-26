"""
Workflow engine for orchestrating security review workflows.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Callable
from bountybot.collaboration.models import (
    WorkflowState,
    WorkflowTransition,
    WorkflowDefinition,
    WorkflowInstance,
    WorkflowTask,
    TaskStatus,
    TaskPriority,
    ApprovalStatus,
)


class StateTransitionError(Exception):
    """Raised when a state transition is invalid."""
    pass


class WorkflowEngine:
    """
    Workflow engine for managing workflow definitions and instances.
    
    Example:
        >>> engine = WorkflowEngine()
        >>> 
        >>> # Create workflow definition
        >>> workflow_def = engine.create_workflow_definition(
        ...     name="security_review",
        ...     description="Security vulnerability review workflow"
        ... )
        >>> 
        >>> # Add transitions
        >>> engine.add_transition(
        ...     workflow_def.workflow_id,
        ...     WorkflowState.PENDING,
        ...     WorkflowState.IN_PROGRESS,
        ...     "start_review"
        ... )
        >>> 
        >>> # Create workflow instance
        >>> instance = engine.create_workflow_instance(
        ...     workflow_def.workflow_id,
        ...     entity_type="report",
        ...     entity_id="report-123",
        ...     started_by="analyst@acme.com"
        ... )
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize workflow engine."""
        self.config = config or {}
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.workflow_instances: Dict[str, WorkflowInstance] = {}
        self.tasks: Dict[str, WorkflowTask] = {}
        
        # Create default security review workflow
        self._create_default_workflows()
    
    def _create_default_workflows(self):
        """Create default workflow definitions."""
        # Security review workflow
        security_review = self.create_workflow_definition(
            name="security_review",
            description="Standard security vulnerability review workflow",
            initial_state=WorkflowState.PENDING
        )
        
        # Define transitions
        transitions = [
            (WorkflowState.PENDING, WorkflowState.IN_PROGRESS, "start_review", False),
            (WorkflowState.IN_PROGRESS, WorkflowState.WAITING_APPROVAL, "request_approval", True),
            (WorkflowState.WAITING_APPROVAL, WorkflowState.APPROVED, "approve", False),
            (WorkflowState.WAITING_APPROVAL, WorkflowState.REJECTED, "reject", False),
            (WorkflowState.APPROVED, WorkflowState.COMPLETED, "complete", False),
            (WorkflowState.REJECTED, WorkflowState.IN_PROGRESS, "revise", False),
            (WorkflowState.IN_PROGRESS, WorkflowState.CANCELLED, "cancel", False),
        ]
        
        for from_state, to_state, action, requires_approval in transitions:
            self.add_transition(
                security_review.workflow_id,
                from_state,
                to_state,
                action,
                requires_approval=requires_approval
            )
    
    def create_workflow_definition(
        self,
        name: str,
        description: str = "",
        initial_state: WorkflowState = WorkflowState.PENDING,
        created_by: str = "system"
    ) -> WorkflowDefinition:
        """Create a new workflow definition."""
        workflow_def = WorkflowDefinition(
            name=name,
            description=description,
            initial_state=initial_state,
            created_by=created_by
        )
        
        self.workflow_definitions[workflow_def.workflow_id] = workflow_def
        return workflow_def
    
    def add_transition(
        self,
        workflow_id: str,
        from_state: WorkflowState,
        to_state: WorkflowState,
        action: str,
        condition: Optional[str] = None,
        auto_transition: bool = False,
        requires_approval: bool = False,
        approvers: Optional[List[str]] = None
    ) -> WorkflowTransition:
        """Add a transition to a workflow definition."""
        workflow_def = self.workflow_definitions.get(workflow_id)
        if not workflow_def:
            raise ValueError(f"Workflow definition not found: {workflow_id}")
        
        transition = WorkflowTransition(
            from_state=from_state,
            to_state=to_state,
            action=action,
            condition=condition,
            auto_transition=auto_transition,
            requires_approval=requires_approval,
            approvers=approvers or []
        )
        
        workflow_def.transitions.append(transition)
        
        # Add states if not already present
        if from_state not in workflow_def.states:
            workflow_def.states.append(from_state)
        if to_state not in workflow_def.states:
            workflow_def.states.append(to_state)
        
        return transition
    
    def create_workflow_instance(
        self,
        workflow_id: str,
        entity_type: str,
        entity_id: str,
        started_by: str,
        assigned_to: Optional[str] = None
    ) -> WorkflowInstance:
        """Create a new workflow instance."""
        workflow_def = self.workflow_definitions.get(workflow_id)
        if not workflow_def:
            raise ValueError(f"Workflow definition not found: {workflow_id}")
        
        instance = WorkflowInstance(
            workflow_id=workflow_id,
            workflow_name=workflow_def.name,
            entity_type=entity_type,
            entity_id=entity_id,
            current_state=workflow_def.initial_state,
            started_by=started_by,
            assigned_to=assigned_to
        )
        
        # Record initial state
        instance.state_history.append({
            'state': workflow_def.initial_state.value,
            'timestamp': datetime.utcnow().isoformat(),
            'user': started_by,
            'action': 'created'
        })
        
        self.workflow_instances[instance.instance_id] = instance
        return instance
    
    def transition_workflow(
        self,
        instance_id: str,
        action: str,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> WorkflowInstance:
        """Transition a workflow instance to a new state."""
        instance = self.workflow_instances.get(instance_id)
        if not instance:
            raise ValueError(f"Workflow instance not found: {instance_id}")
        
        workflow_def = self.workflow_definitions.get(instance.workflow_id)
        if not workflow_def:
            raise ValueError(f"Workflow definition not found: {instance.workflow_id}")
        
        # Find valid transition
        transition = None
        for t in workflow_def.transitions:
            if t.from_state == instance.current_state and t.action == action:
                transition = t
                break
        
        if not transition:
            raise StateTransitionError(
                f"Invalid transition: {instance.current_state.value} -> {action}"
            )
        
        # Check if approval is required
        if transition.requires_approval and not (metadata or {}).get('approved'):
            raise StateTransitionError(
                f"Transition requires approval: {action}"
            )
        
        # Perform transition
        instance.previous_state = instance.current_state
        instance.current_state = transition.to_state
        
        # Record state change
        instance.state_history.append({
            'state': transition.to_state.value,
            'previous_state': transition.from_state.value,
            'timestamp': datetime.utcnow().isoformat(),
            'user': user_id,
            'action': action,
            'metadata': metadata or {}
        })
        
        # Mark as completed if in terminal state
        if transition.to_state in [WorkflowState.COMPLETED, WorkflowState.CANCELLED, WorkflowState.FAILED]:
            instance.completed_at = datetime.utcnow()
        
        return instance
    
    def assign_task(
        self,
        workflow_instance_id: str,
        assigned_to: str,
        title: str,
        description: str = "",
        priority: TaskPriority = TaskPriority.MEDIUM,
        assigned_by: Optional[str] = None,
        due_hours: Optional[float] = None
    ) -> WorkflowTask:
        """Assign a task within a workflow."""
        instance = self.workflow_instances.get(workflow_instance_id)
        if not instance:
            raise ValueError(f"Workflow instance not found: {workflow_instance_id}")
        
        task = WorkflowTask(
            workflow_instance_id=workflow_instance_id,
            title=title,
            description=description,
            priority=priority,
            assigned_to=assigned_to,
            assigned_by=assigned_by
        )
        
        if due_hours:
            from datetime import timedelta
            task.due_date = datetime.utcnow() + timedelta(hours=due_hours)
        
        self.tasks[task.task_id] = task
        return task
    
    def update_task_status(
        self,
        task_id: str,
        status: TaskStatus,
        user_id: str
    ) -> WorkflowTask:
        """Update task status."""
        task = self.tasks.get(task_id)
        if not task:
            raise ValueError(f"Task not found: {task_id}")
        
        task.status = status
        task.updated_at = datetime.utcnow()
        
        if status == TaskStatus.COMPLETED:
            task.completed_at = datetime.utcnow()
        
        return task
    
    def get_workflow_instance(self, instance_id: str) -> Optional[WorkflowInstance]:
        """Get workflow instance by ID."""
        return self.workflow_instances.get(instance_id)
    
    def get_workflow_tasks(self, instance_id: str) -> List[WorkflowTask]:
        """Get all tasks for a workflow instance."""
        return [
            task for task in self.tasks.values()
            if task.workflow_instance_id == instance_id
        ]
    
    def get_user_tasks(
        self,
        user_id: str,
        status: Optional[TaskStatus] = None
    ) -> List[WorkflowTask]:
        """Get all tasks assigned to a user."""
        tasks = [
            task for task in self.tasks.values()
            if task.assigned_to == user_id
        ]
        
        if status:
            tasks = [task for task in tasks if task.status == status]
        
        return tasks


class WorkflowExecutor:
    """
    Executes workflow actions and manages workflow lifecycle.
    
    Example:
        >>> executor = WorkflowExecutor(engine)
        >>> executor.start_workflow(instance_id, user_id="analyst@acme.com")
        >>> executor.complete_task(task_id, user_id="analyst@acme.com")
    """
    
    def __init__(self, engine: WorkflowEngine):
        """Initialize workflow executor."""
        self.engine = engine
        self.action_handlers: Dict[str, Callable] = {}
    
    def register_action_handler(self, action: str, handler: Callable) -> None:
        """Register a custom action handler."""
        self.action_handlers[action] = handler
    
    def execute_action(
        self,
        instance_id: str,
        action: str,
        user_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> WorkflowInstance:
        """Execute a workflow action."""
        # Call custom handler if registered
        if action in self.action_handlers:
            self.action_handlers[action](instance_id, user_id, metadata)
        
        # Transition workflow
        return self.engine.transition_workflow(instance_id, action, user_id, metadata)


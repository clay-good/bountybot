"""
Tests for collaborative workflow and team coordination system.
"""

import pytest
from datetime import datetime, timedelta
from bountybot.collaboration import (
    # Workflow
    WorkflowEngine,
    WorkflowExecutor,
    WorkflowState,
    TaskStatus,
    TaskPriority,
    StateTransitionError,
    
    # Collaboration
    CollaborationManager,
    MentionParser,
    NotificationType,
    NotificationStatus,
    
    # Activity feed
    ActivityFeedManager,
    ActivityFilter,
    ActivityType,
    
    # SLA
    SLAManager,
    SLAMonitor,
    EscalationEngine,
    SLAStatus,
    EscalationLevel,
)


# ============================================================================
# Workflow Engine Tests
# ============================================================================

class TestWorkflowEngine:
    """Test workflow engine."""
    
    def test_workflow_engine_creation(self):
        """Test workflow engine creation."""
        engine = WorkflowEngine()
        assert engine is not None
        assert len(engine.workflow_definitions) > 0  # Has default workflows
    
    def test_create_workflow_definition(self):
        """Test creating a workflow definition."""
        engine = WorkflowEngine()
        
        workflow_def = engine.create_workflow_definition(
            name="test_workflow",
            description="Test workflow",
            created_by="admin@acme.com"
        )
        
        assert workflow_def.name == "test_workflow"
        assert workflow_def.description == "Test workflow"
        assert workflow_def.created_by == "admin@acme.com"
        assert workflow_def.initial_state == WorkflowState.PENDING
    
    def test_add_transition(self):
        """Test adding a transition to a workflow."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        transition = engine.add_transition(
            workflow_def.workflow_id,
            WorkflowState.PENDING,
            WorkflowState.IN_PROGRESS,
            "start"
        )
        
        assert transition.from_state == WorkflowState.PENDING
        assert transition.to_state == WorkflowState.IN_PROGRESS
        assert transition.action == "start"
        assert len(workflow_def.transitions) == 1
    
    def test_create_workflow_instance(self):
        """Test creating a workflow instance."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        assert instance.workflow_id == workflow_def.workflow_id
        assert instance.entity_type == "report"
        assert instance.entity_id == "report-123"
        assert instance.current_state == WorkflowState.PENDING
        assert len(instance.state_history) == 1
    
    def test_transition_workflow(self):
        """Test transitioning a workflow."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        # Add transition
        engine.add_transition(
            workflow_def.workflow_id,
            WorkflowState.PENDING,
            WorkflowState.IN_PROGRESS,
            "start"
        )
        
        # Create instance
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        # Transition
        updated_instance = engine.transition_workflow(
            instance.instance_id,
            "start",
            "analyst@acme.com"
        )
        
        assert updated_instance.current_state == WorkflowState.IN_PROGRESS
        assert updated_instance.previous_state == WorkflowState.PENDING
        assert len(updated_instance.state_history) == 2
    
    def test_invalid_transition(self):
        """Test invalid state transition."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        # Try invalid transition
        with pytest.raises(StateTransitionError):
            engine.transition_workflow(
                instance.instance_id,
                "invalid_action",
                "analyst@acme.com"
            )
    
    def test_assign_task(self):
        """Test assigning a task."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        task = engine.assign_task(
            instance.instance_id,
            assigned_to="analyst@acme.com",
            title="Review vulnerability",
            description="Review and validate the SQL injection",
            priority=TaskPriority.HIGH,
            due_hours=24.0
        )
        
        assert task.title == "Review vulnerability"
        assert task.assigned_to == "analyst@acme.com"
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.TODO
        assert task.due_date is not None
    
    def test_update_task_status(self):
        """Test updating task status."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        task = engine.assign_task(
            instance.instance_id,
            assigned_to="analyst@acme.com",
            title="Review vulnerability"
        )
        
        # Update status
        updated_task = engine.update_task_status(
            task.task_id,
            TaskStatus.COMPLETED,
            "analyst@acme.com"
        )
        
        assert updated_task.status == TaskStatus.COMPLETED
        assert updated_task.completed_at is not None
    
    def test_get_user_tasks(self):
        """Test getting user tasks."""
        engine = WorkflowEngine()
        workflow_def = engine.create_workflow_definition("test_workflow")
        
        instance = engine.create_workflow_instance(
            workflow_def.workflow_id,
            entity_type="report",
            entity_id="report-123",
            started_by="analyst@acme.com"
        )
        
        # Create multiple tasks
        task1 = engine.assign_task(
            instance.instance_id,
            assigned_to="analyst@acme.com",
            title="Task 1"
        )
        
        task2 = engine.assign_task(
            instance.instance_id,
            assigned_to="analyst@acme.com",
            title="Task 2"
        )
        
        task3 = engine.assign_task(
            instance.instance_id,
            assigned_to="other@acme.com",
            title="Task 3"
        )
        
        # Get user tasks
        user_tasks = engine.get_user_tasks("analyst@acme.com")
        
        assert len(user_tasks) == 2
        assert task1 in user_tasks
        assert task2 in user_tasks
        assert task3 not in user_tasks


# ============================================================================
# Collaboration Manager Tests
# ============================================================================

class TestMentionParser:
    """Test mention parser."""
    
    def test_parse_mentions(self):
        """Test parsing mentions from text."""
        content = "Hey @john, can you review this? cc @sarah and @bob"
        mentions = MentionParser.parse_mentions(content)
        
        assert len(mentions) == 3
        assert "john" in mentions
        assert "sarah" in mentions
        assert "bob" in mentions
    
    def test_parse_mentions_with_special_chars(self):
        """Test parsing mentions with special characters."""
        content = "@john.doe and @sarah_smith and @bob-jones"
        mentions = MentionParser.parse_mentions(content)
        
        assert len(mentions) == 3
        assert "john.doe" in mentions
        assert "sarah_smith" in mentions
        assert "bob-jones" in mentions
    
    def test_parse_no_mentions(self):
        """Test parsing text with no mentions."""
        content = "This is a comment without any mentions"
        mentions = MentionParser.parse_mentions(content)
        
        assert len(mentions) == 0


class TestCollaborationManager:
    """Test collaboration manager."""
    
    def test_collaboration_manager_creation(self):
        """Test collaboration manager creation."""
        manager = CollaborationManager()
        assert manager is not None
    
    def test_add_comment(self):
        """Test adding a comment."""
        manager = CollaborationManager()
        
        comment = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="This looks like a critical SQL injection"
        )
        
        assert comment.entity_type == "report"
        assert comment.entity_id == "report-123"
        assert comment.user_id == "analyst@acme.com"
        assert comment.content == "This looks like a critical SQL injection"
    
    def test_add_comment_with_mentions(self):
        """Test adding a comment with mentions."""
        manager = CollaborationManager()
        
        comment = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="@bob can you verify this? @charlie for approval"
        )
        
        assert len(comment.mentions) == 2
        assert "bob" in comment.mentions
        assert "charlie" in comment.mentions
        
        # Check mentions were created
        bob_mentions = manager.get_user_mentions("bob")
        assert len(bob_mentions) == 1
        
        charlie_mentions = manager.get_user_mentions("charlie")
        assert len(charlie_mentions) == 1
    
    def test_reply_to_comment(self):
        """Test replying to a comment."""
        manager = CollaborationManager()
        
        # Add parent comment
        parent = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="This looks critical"
        )
        
        # Add reply
        reply = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="bob@acme.com",
            user_name="Bob Security",
            content="Confirmed. It's a SQL injection.",
            parent_comment_id=parent.comment_id
        )
        
        assert reply.parent_comment_id == parent.comment_id
        
        # Check notification was created for parent author
        notifications = manager.get_user_notifications("analyst@acme.com")
        assert len(notifications) == 1
        assert notifications[0].notification_type == NotificationType.COMMENT_REPLY
    
    def test_update_comment(self):
        """Test updating a comment."""
        manager = CollaborationManager()
        
        comment = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="Original content"
        )
        
        # Update comment
        updated = manager.update_comment(
            comment.comment_id,
            "Updated content",
            "analyst@acme.com"
        )
        
        assert updated.content == "Updated content"
        assert updated.edited is True
        assert updated.updated_at is not None
    
    def test_delete_comment(self):
        """Test deleting a comment."""
        manager = CollaborationManager()
        
        comment = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="Test comment"
        )
        
        # Delete comment
        result = manager.delete_comment(comment.comment_id, "analyst@acme.com")
        
        assert result is True
        assert comment.comment_id not in manager.comments
    
    def test_add_reaction(self):
        """Test adding a reaction to a comment."""
        manager = CollaborationManager()
        
        comment = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="Great find!"
        )
        
        # Add reaction
        updated = manager.add_reaction(
            comment.comment_id,
            "bob@acme.com",
            "👍"
        )
        
        assert "👍" in updated.reactions
        assert "bob@acme.com" in updated.reactions["👍"]
    
    def test_get_comments(self):
        """Test getting comments for an entity."""
        manager = CollaborationManager()
        
        # Add multiple comments
        comment1 = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="Comment 1"
        )
        
        comment2 = manager.add_comment(
            entity_type="report",
            entity_id="report-123",
            user_id="bob@acme.com",
            user_name="Bob Security",
            content="Comment 2"
        )
        
        comment3 = manager.add_comment(
            entity_type="report",
            entity_id="report-456",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            content="Comment 3"
        )
        
        # Get comments for report-123
        comments = manager.get_comments("report", "report-123")
        
        assert len(comments) == 2
        assert comment1 in comments
        assert comment2 in comments
        assert comment3 not in comments


# ============================================================================
# Activity Feed Tests
# ============================================================================

class TestActivityFeedManager:
    """Test activity feed manager."""
    
    def test_activity_feed_manager_creation(self):
        """Test activity feed manager creation."""
        manager = ActivityFeedManager()
        assert manager is not None
    
    def test_record_activity(self):
        """Test recording an activity."""
        manager = ActivityFeedManager()
        
        activity = manager.record_activity(
            activity_type=ActivityType.REPORT_VALIDATED,
            entity_type="report",
            entity_id="report-123",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            title="Report validated",
            description="Report #123 validated as critical SQL injection"
        )
        
        assert activity.activity_type == ActivityType.REPORT_VALIDATED
        assert activity.entity_type == "report"
        assert activity.user_id == "analyst@acme.com"
        assert activity.title == "Report validated"
    
    def test_get_activity_feed(self):
        """Test getting activity feed."""
        manager = ActivityFeedManager()
        
        # Record multiple activities
        for i in range(5):
            manager.record_activity(
                activity_type=ActivityType.REPORT_CREATED,
                entity_type="report",
                entity_id=f"report-{i}",
                user_id="analyst@acme.com",
                user_name="Alice Analyst",
                title=f"Report {i} created"
            )
        
        # Get activity feed
        activities = manager.get_activity_feed()
        
        assert len(activities) == 5
    
    def test_get_user_activity(self):
        """Test getting user activity."""
        manager = ActivityFeedManager()
        
        # Record activities for different users
        manager.record_activity(
            activity_type=ActivityType.REPORT_CREATED,
            entity_type="report",
            entity_id="report-1",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            title="Report 1"
        )
        
        manager.record_activity(
            activity_type=ActivityType.REPORT_CREATED,
            entity_type="report",
            entity_id="report-2",
            user_id="bob@acme.com",
            user_name="Bob Security",
            title="Report 2"
        )
        
        # Get user activity
        user_activities = manager.get_user_activity("analyst@acme.com")
        
        assert len(user_activities) == 1
        assert user_activities[0].user_id == "analyst@acme.com"
    
    def test_get_activity_stats(self):
        """Test getting activity statistics."""
        manager = ActivityFeedManager()
        
        # Record activities
        manager.record_activity(
            activity_type=ActivityType.REPORT_CREATED,
            entity_type="report",
            entity_id="report-1",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            title="Report 1"
        )
        
        manager.record_activity(
            activity_type=ActivityType.REPORT_VALIDATED,
            entity_type="report",
            entity_id="report-1",
            user_id="analyst@acme.com",
            user_name="Alice Analyst",
            title="Report validated"
        )
        
        # Get stats
        stats = manager.get_activity_stats()
        
        assert stats['total_activities'] == 2
        assert stats['unique_users'] == 1
        assert 'report_created' in stats['activities_by_type']
        assert 'report_validated' in stats['activities_by_type']


# ============================================================================
# SLA Manager Tests
# ============================================================================

class TestSLAManager:
    """Test SLA manager."""

    def test_sla_manager_creation(self):
        """Test SLA manager creation."""
        manager = SLAManager()
        assert manager is not None

    def test_create_sla(self):
        """Test creating an SLA."""
        manager = SLAManager()

        sla = manager.create_sla(
            entity_type="report",
            entity_id="report-123",
            target_hours=24.0
        )

        assert sla.entity_type == "report"
        assert sla.entity_id == "report-123"
        assert sla.target_hours == 24.0
        assert sla.status == SLAStatus.ACTIVE
        assert sla.breached is False

    def test_create_sla_with_severity(self):
        """Test creating an SLA with severity-based target."""
        manager = SLAManager()

        sla = manager.create_sla(
            entity_type="report",
            entity_id="report-123",
            severity="critical"
        )

        # Should use default target for critical reports (4 hours)
        assert sla.target_hours == 4.0

    def test_update_sla(self):
        """Test updating SLA status."""
        manager = SLAManager()

        sla = manager.create_sla(
            entity_type="report",
            entity_id="report-123",
            target_hours=24.0
        )

        # Update SLA
        updated = manager.update_sla(sla.sla_id)

        assert updated.elapsed_hours >= 0
        assert updated.remaining_hours <= 24.0
        assert updated.percent_elapsed >= 0

    def test_complete_sla(self):
        """Test completing an SLA."""
        manager = SLAManager()

        sla = manager.create_sla(
            entity_type="report",
            entity_id="report-123",
            target_hours=24.0
        )

        # Complete SLA
        completed = manager.complete_sla(sla.sla_id)

        assert completed.status == SLAStatus.COMPLETED
        assert completed.completed_at is not None

    def test_cancel_sla(self):
        """Test cancelling an SLA."""
        manager = SLAManager()

        sla = manager.create_sla(
            entity_type="report",
            entity_id="report-123",
            target_hours=24.0
        )

        # Cancel SLA
        cancelled = manager.cancel_sla(sla.sla_id)

        assert cancelled.status == SLAStatus.CANCELLED

    def test_get_active_slas(self):
        """Test getting active SLAs."""
        manager = SLAManager()

        # Create multiple SLAs
        sla1 = manager.create_sla("report", "report-1", target_hours=24.0)
        sla2 = manager.create_sla("report", "report-2", target_hours=24.0)
        sla3 = manager.create_sla("report", "report-3", target_hours=24.0)

        # Complete one
        manager.complete_sla(sla3.sla_id)

        # Get active SLAs
        active = manager.get_active_slas()

        assert len(active) == 2
        assert sla1 in active
        assert sla2 in active
        assert sla3 not in active

    def test_get_sla_stats(self):
        """Test getting SLA statistics."""
        manager = SLAManager()

        # Create SLAs
        sla1 = manager.create_sla("report", "report-1", target_hours=24.0)
        sla2 = manager.create_sla("report", "report-2", target_hours=24.0)

        # Complete one
        manager.complete_sla(sla1.sla_id)

        # Get stats
        stats = manager.get_sla_stats()

        assert stats['total_slas'] == 2
        assert stats['active'] == 1
        assert stats['completed'] == 1


class TestSLAMonitor:
    """Test SLA monitor."""

    def test_sla_monitor_creation(self):
        """Test SLA monitor creation."""
        manager = SLAManager()
        monitor = SLAMonitor(manager)
        assert monitor is not None

    def test_monitor_slas(self):
        """Test monitoring SLAs."""
        manager = SLAManager()
        monitor = SLAMonitor(manager)

        # Create SLAs
        sla1 = manager.create_sla("report", "report-1", target_hours=24.0)
        sla2 = manager.create_sla("report", "report-2", target_hours=24.0)

        # Monitor
        results = monitor.monitor_slas()

        assert results['monitored'] == 2
        assert 'warnings' in results
        assert 'breaches' in results


class TestEscalationEngine:
    """Test escalation engine."""

    def test_escalation_engine_creation(self):
        """Test escalation engine creation."""
        manager = SLAManager()
        engine = EscalationEngine(manager)
        assert engine is not None

    def test_add_escalation_rule(self):
        """Test adding an escalation rule."""
        manager = SLAManager()
        engine = EscalationEngine(manager)

        rule = engine.add_escalation_rule(
            name="Critical Report Escalation",
            entity_type="report",
            breach_duration_hours=2.0,
            escalation_level=EscalationLevel.LEVEL_2,
            escalate_to=["manager@acme.com"],
            severity="critical"
        )

        assert rule.name == "Critical Report Escalation"
        assert rule.entity_type == "report"
        assert rule.breach_duration_hours == 2.0
        assert rule.escalation_level == EscalationLevel.LEVEL_2
        assert "manager@acme.com" in rule.escalate_to

    def test_process_escalations(self):
        """Test processing escalations."""
        manager = SLAManager()
        engine = EscalationEngine(manager)

        # Add escalation rule
        rule = engine.add_escalation_rule(
            name="Test Escalation",
            entity_type="report",
            breach_duration_hours=0.0,  # Immediate escalation
            escalation_level=EscalationLevel.LEVEL_1,
            escalate_to=["lead@acme.com"]
        )

        # Create SLA (won't be breached immediately)
        sla = manager.create_sla("report", "report-1", target_hours=24.0)

        # Process escalations (no breaches yet)
        results = engine.process_escalations()

        assert results['processed'] >= 0
        assert 'escalated' in results


"""
Demo: Async Task Queue & Background Jobs

Demonstrates the distributed task queue capabilities of BountyBot.
"""

import time
from datetime import datetime

from bountybot.tasks import (
    TaskManager,
    TaskPriority,
    TaskStatus,
    celery_app
)
from bountybot.tasks.celery_app import is_celery_available


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_celery_availability():
    """Demonstrate Celery availability check."""
    print_section("1. Celery Availability Check")
    
    available = is_celery_available()
    
    if available:
        print("✓ Celery is available and configured")
        print(f"  - Broker: Redis")
        print(f"  - Backend: Redis")
        print(f"  - Queues: validation, maintenance")
        print(f"  - Task priorities: HIGH (0), NORMAL (5), LOW (9)")
    else:
        print("⚠️  Celery is not available")
        print("   Install Celery: pip install celery[redis]")
        print("   Start Redis: redis-server")
        print("   Start Worker: celery -A bountybot.tasks.celery_app worker --loglevel=info")
        print("\n💡 Demo will continue with mock operations...")


def demo_task_manager():
    """Demonstrate task manager."""
    print_section("2. Task Manager - High-Level Interface")
    
    # Create task manager
    task_manager = TaskManager()
    
    print("✓ Task manager created")
    print(f"  - Celery available: {task_manager.celery_available}")
    
    if not task_manager.celery_available:
        print("\n⚠️  Celery not available - skipping task submission demos")
        return
    
    # Submit validation task
    print("\n📤 Submitting validation task:")
    print("   task_manager.submit_validation_task('report.json', priority=HIGH)")
    
    task_id = task_manager.submit_validation_task(
        report_path='examples/sql_injection.json',
        priority=TaskPriority.HIGH
    )
    
    if task_id:
        print(f"   ✓ Task submitted: {task_id}")
        
        # Get task status
        print(f"\n📊 Getting task status:")
        status = task_manager.get_task_status(task_id)
        
        if status:
            print(f"   - Task ID: {status.task_id}")
            print(f"   - Status: {status.status.value}")
            print(f"   - Submitted: {status.submitted_at}")
    else:
        print("   ✗ Failed to submit task (worker may not be running)")
    
    # Submit batch validation task
    print("\n📤 Submitting batch validation task:")
    print("   task_manager.submit_batch_validation_task([...], priority=NORMAL)")
    
    batch_task_id = task_manager.submit_batch_validation_task(
        report_paths=[
            'examples/sql_injection.json',
            'examples/xss.json'
        ],
        priority=TaskPriority.NORMAL
    )
    
    if batch_task_id:
        print(f"   ✓ Batch task submitted: {batch_task_id}")
    else:
        print("   ✗ Failed to submit batch task")


def demo_task_priorities():
    """Demonstrate task priorities."""
    print_section("3. Task Priorities")
    
    print("📊 Task Priority Levels:")
    print(f"  - HIGH: {TaskPriority.HIGH.value} (critical reports, security alerts)")
    print(f"  - NORMAL: {TaskPriority.NORMAL.value} (standard validation)")
    print(f"  - LOW: {TaskPriority.LOW.value} (maintenance, cleanup)")
    
    print("\n💡 Priority Usage:")
    print("  • HIGH: Critical security vulnerabilities, urgent reports")
    print("  • NORMAL: Standard bug bounty report validation")
    print("  • LOW: Background maintenance, analytics, cleanup")
    
    print("\n🔄 Task Execution Order:")
    print("  1. Tasks are executed in priority order (0 = highest)")
    print("  2. Within same priority, FIFO (first in, first out)")
    print("  3. Workers can process multiple priorities concurrently")


def demo_scheduled_tasks():
    """Demonstrate scheduled tasks."""
    print_section("4. Scheduled Periodic Tasks (Celery Beat)")
    
    print("📅 Scheduled Tasks:")
    
    tasks = [
        {
            'name': 'cleanup-old-results',
            'schedule': 'Daily at 2:00 AM',
            'description': 'Clean up old validation results (30+ days)',
            'queue': 'maintenance',
            'priority': 'LOW'
        },
        {
            'name': 'backup-database',
            'schedule': 'Daily at 3:00 AM',
            'description': 'Create automated database backup',
            'queue': 'maintenance',
            'priority': 'HIGH'
        },
        {
            'name': 'warm-cache',
            'schedule': 'Every 30 minutes',
            'description': 'Warm cache with frequently accessed data',
            'queue': 'maintenance',
            'priority': 'NORMAL'
        },
        {
            'name': 'generate-analytics',
            'schedule': 'Daily at 1:00 AM',
            'description': 'Generate daily analytics report',
            'queue': 'maintenance',
            'priority': 'NORMAL'
        },
        {
            'name': 'health-check',
            'schedule': 'Every 5 minutes',
            'description': 'Check system health and create alerts',
            'queue': 'maintenance',
            'priority': 'HIGH'
        }
    ]
    
    for i, task in enumerate(tasks, 1):
        print(f"\n{i}. {task['name']}")
        print(f"   Schedule: {task['schedule']}")
        print(f"   Description: {task['description']}")
        print(f"   Queue: {task['queue']}")
        print(f"   Priority: {task['priority']}")
    
    print("\n🚀 Starting Celery Beat:")
    print("   celery -A bountybot.tasks.celery_app beat --loglevel=info")


def demo_task_retry():
    """Demonstrate task retry logic."""
    print_section("5. Task Retry & Failure Handling")
    
    print("🔄 Retry Configuration:")
    print("  - Max retries: 3 (validation), 5 (critical)")
    print("  - Retry delay: 60 seconds (initial)")
    print("  - Backoff: Exponential (2x each retry)")
    print("  - Max backoff: 600 seconds (10 minutes)")
    print("  - Jitter: Enabled (prevents thundering herd)")
    
    print("\n📊 Retry Example:")
    print("  Attempt 1: Immediate")
    print("  Attempt 2: 60 seconds delay")
    print("  Attempt 3: 120 seconds delay")
    print("  Attempt 4: 240 seconds delay")
    print("  Attempt 5: 480 seconds delay")
    print("  Failed: Move to dead letter queue")
    
    print("\n💡 Retry Triggers:")
    print("  • Network errors (API timeouts)")
    print("  • Temporary service unavailability")
    print("  • Rate limit exceeded")
    print("  • Database connection errors")


def demo_worker_management():
    """Demonstrate worker management."""
    print_section("6. Worker Pool Management")
    
    print("👷 Starting Workers:")
    print("\n1. Validation Worker (high concurrency):")
    print("   celery -A bountybot.tasks.celery_app worker \\")
    print("     --queue=validation \\")
    print("     --concurrency=8 \\")
    print("     --loglevel=info \\")
    print("     --hostname=validation@%h")
    
    print("\n2. Maintenance Worker (low concurrency):")
    print("   celery -A bountybot.tasks.celery_app worker \\")
    print("     --queue=maintenance \\")
    print("     --concurrency=2 \\")
    print("     --loglevel=info \\")
    print("     --hostname=maintenance@%h")
    
    print("\n3. Multi-Queue Worker:")
    print("   celery -A bountybot.tasks.celery_app worker \\")
    print("     --queue=validation,maintenance \\")
    print("     --concurrency=4 \\")
    print("     --loglevel=info")
    
    print("\n📊 Worker Monitoring:")
    print("   celery -A bountybot.tasks.celery_app inspect active")
    print("   celery -A bountybot.tasks.celery_app inspect stats")
    print("   celery -A bountybot.tasks.celery_app inspect registered")
    
    print("\n🌸 Flower (Web UI):")
    print("   pip install flower")
    print("   celery -A bountybot.tasks.celery_app flower")
    print("   Open: http://localhost:5555")


def demo_task_monitoring():
    """Demonstrate task monitoring."""
    print_section("7. Task Monitoring & Statistics")
    
    task_manager = TaskManager()
    
    if not task_manager.celery_available:
        print("⚠️  Celery not available - showing example output")
        
        print("\n📊 Example Queue Statistics:")
        print("  - Active tasks: 5")
        print("  - Registered tasks: 8")
        print("  - Workers: 2")
        print("    • validation@worker1 (pool: prefork, concurrency: 8)")
        print("    • maintenance@worker1 (pool: prefork, concurrency: 2)")
        
        print("\n📈 Example Active Tasks:")
        print("  1. validate_report_async")
        print("     Task ID: abc123...")
        print("     Worker: validation@worker1")
        print("     Args: ['report.json']")
        print("\n  2. backup_database")
        print("     Task ID: def456...")
        print("     Worker: maintenance@worker1")
        print("     Args: []")
        
        return
    
    # Get queue stats
    print("📊 Queue Statistics:")
    stats = task_manager.get_queue_stats()
    
    if stats:
        print(f"  - Active tasks: {stats.get('active_tasks', 0)}")
        print(f"  - Registered tasks: {len(stats.get('registered_tasks', []))}")
        print(f"  - Workers: {len(stats.get('workers', []))}")
        
        for worker in stats.get('workers', []):
            print(f"    • {worker['name']} (pool: {worker['pool']}, concurrency: {worker['max_concurrency']})")
    
    # Get active tasks
    print("\n📈 Active Tasks:")
    active_tasks = task_manager.get_active_tasks()
    
    if active_tasks:
        for i, task in enumerate(active_tasks, 1):
            print(f"\n  {i}. {task['task_name']}")
            print(f"     Task ID: {task['task_id'][:8]}...")
            print(f"     Worker: {task['worker']}")
            print(f"     Args: {task['args']}")
    else:
        print("  No active tasks")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot - Async Task Queue & Background Jobs Demo")
    print("=" * 80)
    
    try:
        demo_celery_availability()
        demo_task_manager()
        demo_task_priorities()
        demo_scheduled_tasks()
        demo_task_retry()
        demo_worker_management()
        demo_task_monitoring()
        
        print_section("Demo Complete!")
        print("✅ All async task queue features demonstrated!")
        print("\n📚 Key Features:")
        print("  ✓ Celery-based distributed task queue")
        print("  ✓ Redis as message broker and result backend")
        print("  ✓ Background validation tasks")
        print("  ✓ Scheduled periodic tasks (beat)")
        print("  ✓ Task retry with exponential backoff")
        print("  ✓ Task prioritization (high, normal, low)")
        print("  ✓ Task result tracking and storage")
        print("  ✓ Worker pool management")
        print("  ✓ Task monitoring and statistics")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()


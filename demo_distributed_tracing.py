#!/usr/bin/env python3
"""
BountyBot Distributed Tracing Demo

Demonstrates OpenTelemetry distributed tracing capabilities:
- End-to-end request tracking
- AI provider call instrumentation
- Validation pipeline tracing
- Performance bottleneck identification
- Jaeger UI visualization

Prerequisites:
    pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation
    pip install opentelemetry-exporter-jaeger opentelemetry-exporter-otlp

Optional - Run Jaeger locally:
    docker run -d --name jaeger \
      -e COLLECTOR_ZIPKIN_HOST_PORT=:9411 \
      -p 5775:5775/udp \
      -p 6831:6831/udp \
      -p 6832:6832/udp \
      -p 5778:5778 \
      -p 16686:16686 \
      -p 14268:14268 \
      -p 14250:14250 \
      -p 9411:9411 \
      jaegertracing/all-in-one:latest
    
    Then open http://localhost:16686 to view traces
"""

import asyncio
import time
from pathlib import Path

# Import tracing
try:
    from bountybot.monitoring.tracing import initialize_tracing, get_tracing_manager
    TRACING_AVAILABLE = True
except ImportError:
    print("❌ OpenTelemetry not available")
    print("Install with: pip install opentelemetry-api opentelemetry-sdk opentelemetry-instrumentation")
    TRACING_AVAILABLE = False


def print_header(title: str):
    """Print section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def print_section(title: str):
    """Print subsection."""
    print(f"\n{'─' * 80}")
    print(f"  {title}")
    print(f"{'─' * 80}\n")


async def demo_basic_tracing():
    """Demonstrate basic tracing functionality."""
    print_section("1. Basic Tracing")
    
    # Initialize tracing with console export
    manager = initialize_tracing(
        service_name="bountybot-demo",
        service_version="2.7.0",
        console_export=True,
        enabled=True
    )
    
    print("✅ Tracing initialized with console export")
    print(f"   Service: {manager.service_name}")
    print(f"   Version: {manager.service_version}")
    print(f"   Enabled: {manager.enabled}")
    
    # Create a simple span
    print("\n📊 Creating a simple span...")
    with manager.start_span("demo.simple_operation", attributes={"demo": "true"}) as span:
        print("   ✓ Span started")
        time.sleep(0.1)
        manager.add_event("operation.halfway")
        time.sleep(0.1)
        print("   ✓ Span completed")
    
    print("\n✅ Basic tracing demo complete")


async def demo_nested_spans():
    """Demonstrate nested spans for complex operations."""
    print_section("2. Nested Spans")
    
    manager = get_tracing_manager()
    
    print("📊 Creating nested spans to track complex workflow...")
    
    with manager.start_span("demo.validation_workflow") as parent_span:
        print("   ✓ Parent span: validation_workflow")
        
        # Parsing phase
        with manager.start_span("demo.parsing") as parse_span:
            print("      ✓ Child span: parsing")
            manager.set_attribute("file.type", "json")
            time.sleep(0.05)
        
        # Analysis phase
        with manager.start_span("demo.analysis") as analysis_span:
            print("      ✓ Child span: analysis")
            manager.set_attribute("analysis.type", "static")
            time.sleep(0.1)
        
        # AI validation phase
        with manager.start_span("demo.ai_validation") as ai_span:
            print("      ✓ Child span: ai_validation")
            manager.set_attribute("ai.provider", "anthropic")
            manager.set_attribute("ai.model", "claude-sonnet-4")
            manager.set_attribute("ai.tokens.input", 1500)
            manager.set_attribute("ai.tokens.output", 300)
            manager.set_attribute("ai.cost", 0.0045)
            time.sleep(0.15)
    
    print("\n✅ Nested spans demo complete")


async def demo_async_tracing():
    """Demonstrate tracing with async operations."""
    print_section("3. Async Operations Tracing")
    
    manager = get_tracing_manager()
    
    print("📊 Tracing concurrent async operations...")
    
    @manager.trace_async_function(name="demo.async_task")
    async def async_task(task_id: int, duration: float):
        """Simulated async task."""
        manager.set_attribute("task.id", task_id)
        await asyncio.sleep(duration)
        manager.add_event("task.complete", {"task_id": task_id})
        return f"Task {task_id} complete"
    
    # Run multiple tasks concurrently
    with manager.start_span("demo.concurrent_batch") as span:
        print("   ✓ Starting 5 concurrent tasks...")
        tasks = [
            async_task(1, 0.1),
            async_task(2, 0.15),
            async_task(3, 0.08),
            async_task(4, 0.12),
            async_task(5, 0.09)
        ]
        results = await asyncio.gather(*tasks)
        print(f"   ✓ All tasks complete: {len(results)} results")
    
    print("\n✅ Async tracing demo complete")


async def demo_error_tracking():
    """Demonstrate error tracking in traces."""
    print_section("4. Error Tracking")
    
    manager = get_tracing_manager()
    
    print("📊 Demonstrating error tracking...")
    
    # Successful operation
    with manager.start_span("demo.successful_operation") as span:
        print("   ✓ Successful operation")
        manager.add_event("operation.success")
    
    # Failed operation
    print("\n   ⚠️  Simulating failed operation...")
    try:
        with manager.start_span("demo.failed_operation") as span:
            manager.set_attribute("operation.type", "validation")
            raise ValueError("Simulated validation error")
    except ValueError as e:
        print(f"   ✓ Error captured in trace: {e}")
    
    print("\n✅ Error tracking demo complete")


async def demo_ai_provider_tracing():
    """Demonstrate AI provider call tracing."""
    print_section("5. AI Provider Call Tracing")
    
    manager = get_tracing_manager()
    
    print("📊 Simulating AI provider calls with tracing...")
    
    with manager.start_span("demo.ai_complete", attributes={
        "ai.provider": "anthropic",
        "ai.model": "claude-sonnet-4-20250514",
        "ai.operation": "complete"
    }) as span:
        print("   ✓ AI call span started")
        
        # Simulate API call
        await asyncio.sleep(0.2)
        
        # Add metrics
        manager.set_attribute("ai.tokens.input", 2048)
        manager.set_attribute("ai.tokens.output", 512)
        manager.set_attribute("ai.tokens.cache_read", 1500)
        manager.set_attribute("ai.cost", 0.0032)
        manager.set_attribute("ai.duration_ms", 200)
        
        manager.add_event("ai.call.success", {
            "tokens": 2560,
            "cost": 0.0032
        })
        
        print("   ✓ AI call complete with metrics")
    
    print("\n✅ AI provider tracing demo complete")


async def demo_jaeger_export():
    """Demonstrate Jaeger export."""
    print_section("6. Jaeger Export")
    
    print("📊 To export traces to Jaeger:")
    print("\n1. Start Jaeger (if not running):")
    print("   docker run -d --name jaeger \\")
    print("     -p 16686:16686 -p 6831:6831/udp \\")
    print("     jaegertracing/all-in-one:latest")
    
    print("\n2. Update config/default.yaml:")
    print("   tracing:")
    print("     enabled: true")
    print("     jaeger_endpoint: localhost:6831")
    
    print("\n3. Run BountyBot validation:")
    print("   python -m bountybot.cli validate report.json")
    
    print("\n4. View traces in Jaeger UI:")
    print("   http://localhost:16686")
    
    print("\n✅ Jaeger export instructions complete")


async def demo_performance_analysis():
    """Demonstrate performance analysis with tracing."""
    print_section("7. Performance Analysis")
    
    manager = get_tracing_manager()
    
    print("📊 Simulating validation pipeline for performance analysis...")
    
    with manager.start_span("demo.full_validation") as span:
        start_time = time.time()
        
        # Parsing (fast)
        with manager.start_span("demo.parsing") as parse_span:
            await asyncio.sleep(0.05)
            manager.set_attribute("parsing.duration_ms", 50)
        
        # Code analysis (medium)
        with manager.start_span("demo.code_analysis") as code_span:
            await asyncio.sleep(0.15)
            manager.set_attribute("code_analysis.duration_ms", 150)
        
        # AI validation (slow - bottleneck)
        with manager.start_span("demo.ai_validation") as ai_span:
            await asyncio.sleep(0.5)
            manager.set_attribute("ai_validation.duration_ms", 500)
            manager.add_event("bottleneck.detected", {
                "component": "ai_validation",
                "duration_ms": 500
            })
        
        # Dynamic scanning (medium)
        with manager.start_span("demo.dynamic_scan") as scan_span:
            await asyncio.sleep(0.2)
            manager.set_attribute("dynamic_scan.duration_ms", 200)
        
        total_duration = (time.time() - start_time) * 1000
        manager.set_attribute("total.duration_ms", total_duration)
        
        print(f"   ✓ Total validation time: {total_duration:.0f}ms")
        print(f"   ✓ Bottleneck identified: AI validation (500ms)")
    
    print("\n✅ Performance analysis demo complete")


async def main():
    """Run all demos."""
    print_header("BountyBot Distributed Tracing Demo")
    
    if not TRACING_AVAILABLE:
        print("❌ OpenTelemetry not available - cannot run demo")
        return
    
    print("This demo showcases OpenTelemetry distributed tracing capabilities")
    print("for BountyBot's bug bounty validation pipeline.")
    
    try:
        await demo_basic_tracing()
        await demo_nested_spans()
        await demo_async_tracing()
        await demo_error_tracking()
        await demo_ai_provider_tracing()
        await demo_jaeger_export()
        await demo_performance_analysis()
        
        print_header("Demo Complete! 🎉")
        
        print("📚 Key Takeaways:")
        print("   ✅ End-to-end request tracking across all components")
        print("   ✅ AI provider calls instrumented with token/cost metrics")
        print("   ✅ Async operations traced with proper context propagation")
        print("   ✅ Errors automatically captured in traces")
        print("   ✅ Performance bottlenecks easily identified")
        print("   ✅ Jaeger UI for visual trace analysis")
        
        print("\n🚀 Next Steps:")
        print("   1. Install OpenTelemetry: pip install opentelemetry-api opentelemetry-sdk")
        print("   2. Start Jaeger: docker run -p 16686:16686 -p 6831:6831/udp jaegertracing/all-in-one")
        print("   3. Enable tracing in config/default.yaml")
        print("   4. Run validations and view traces at http://localhost:16686")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    asyncio.run(main())


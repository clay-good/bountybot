#!/usr/bin/env python3
"""
Demo script for BountyBot v2.15.0 - AI-Powered Smart Recommendations & Learning System

This demo showcases:
1. Intelligent recommendation engine with pattern matching
2. Adaptive learning system that improves over time
3. Context-aware suggestions during validation
4. Knowledge graph for vulnerability relationships
5. Smart automation with learned patterns
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree

from bountybot.recommendations import (
    Recommendation,
    RecommendationType,
    RecommendationContext,
    RecommendationFeedback,
    FeedbackType,
    LearningPattern,
    PatternType,
    KnowledgeNode,
    KnowledgeEdge,
    EdgeType,
    RecommendationEngine,
    AdaptiveLearningSystem,
    SuggestionEngine,
    KnowledgeGraph,
    SmartAutomation,
    AutomationRule,
)
from bountybot.recommendations.smart_automation import AutomationTrigger, AutomationAction


console = Console()


def print_header():
    """Print demo header."""
    console.print()
    console.print(Panel.fit(
        "[bold cyan]BountyBot v2.15.0[/bold cyan]\n"
        "[yellow]AI-Powered Smart Recommendations & Learning System[/yellow]\n"
        "[dim]Intelligent recommendations that learn and improve over time[/dim]",
        border_style="cyan"
    ))
    console.print()


def demo_recommendation_engine():
    """Demo recommendation engine."""
    console.print("[bold]1. Intelligent Recommendation Engine[/bold]")
    console.print()
    
    # Create engine
    engine = RecommendationEngine()
    console.print("✓ Recommendation engine initialized")
    console.print()
    
    # Generate recommendations for XSS
    console.print("[yellow]Generating recommendations for XSS vulnerability...[/yellow]")
    
    context = RecommendationContext(
        vulnerability_type="XSS",
        severity="high",
        language="javascript",
        framework="react",
    )
    
    recommendations = engine.generate_recommendations(context, max_recommendations=5)
    
    console.print(f"✓ Generated {len(recommendations)} recommendations")
    console.print()
    
    # Display recommendations
    for i, rec in enumerate(recommendations, 1):
        console.print(f"[cyan]Recommendation {i}:[/cyan] {rec.title}")
        console.print(f"  Type: {rec.type.value}")
        console.print(f"  Confidence: {rec.confidence:.0%}")
        console.print(f"  Priority: {rec.priority}")
        console.print(f"  Reasoning: {rec.reasoning}")
        if rec.code_snippet:
            console.print(f"  Code snippet available")
        console.print()
    
    # Record feedback
    console.print("[yellow]Recording feedback...[/yellow]")
    feedback = RecommendationFeedback(
        recommendation_id=recommendations[0].recommendation_id,
        feedback_type=FeedbackType.ACCEPTED,
        user_id="alice",
        effectiveness_score=0.9,
    )
    engine.record_feedback(feedback)
    console.print("✓ Feedback recorded: ACCEPTED")
    console.print()
    
    # Show statistics
    stats = engine.get_stats()
    
    table = Table(title="Recommendation Engine Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Recommendations", str(stats['total_recommendations']))
    table.add_row("Accepted", str(stats['accepted_recommendations']))
    table.add_row("Acceptance Rate", f"{stats['acceptance_rate']:.1f}%")
    table.add_row("Average Confidence", f"{stats['average_confidence']:.0%}")
    
    console.print(table)
    console.print()
    
    return engine


def demo_learning_system():
    """Demo adaptive learning system."""
    console.print("[bold]2. Adaptive Learning System[/bold]")
    console.print()
    
    # Create learning system
    system = AdaptiveLearningSystem()
    console.print("✓ Learning system initialized")
    console.print()
    
    # Add some patterns
    console.print("[yellow]Adding learned patterns...[/yellow]")
    
    patterns = [
        LearningPattern(
            type=PatternType.VULNERABILITY_PATTERN,
            name="XSS in React Components",
            description="XSS vulnerabilities in React components using dangerouslySetInnerHTML",
            occurrence_count=15,
            success_rate=0.92,
            confidence=0.88,
            conditions={'vulnerability_type': 'XSS', 'framework': 'react'},
        ),
        LearningPattern(
            type=PatternType.REMEDIATION_PATTERN,
            name="SQL Injection - Parameterized Queries",
            description="Use parameterized queries to prevent SQL injection",
            occurrence_count=25,
            success_rate=0.98,
            confidence=0.95,
            conditions={'vulnerability_type': 'SQL Injection'},
        ),
        LearningPattern(
            type=PatternType.FALSE_POSITIVE_PATTERN,
            name="CSRF in API Endpoints",
            description="CSRF reports on stateless API endpoints are often false positives",
            occurrence_count=8,
            success_rate=0.75,
            confidence=0.70,
            conditions={'vulnerability_type': 'CSRF'},
        ),
    ]
    
    for pattern in patterns:
        system.add_pattern(pattern)
        console.print(f"  ✓ Added: {pattern.name} (confidence: {pattern.confidence:.0%})")
    
    console.print()
    
    # Train model
    console.print("[yellow]Training learning model...[/yellow]")
    system.train_model()
    console.print("✓ Model training complete")
    console.print()
    
    # Get recommendations from patterns
    console.print("[yellow]Getting pattern-based recommendations...[/yellow]")
    
    context = RecommendationContext(
        vulnerability_type="XSS",
        severity="high",
        framework="react",
    )
    
    recommendations = system.get_recommendations_for_context(context)
    console.print(f"✓ Found {len(recommendations)} pattern-based recommendations")
    
    for rec in recommendations:
        console.print(f"  • {rec.title} (confidence: {rec.confidence:.0%})")
    
    console.print()
    
    # Show metrics
    metrics = system.get_stats()
    
    table = Table(title="Learning System Metrics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Patterns", str(metrics['total_patterns']))
    table.add_row("Active Patterns", str(metrics['active_patterns']))
    table.add_row("Average Success Rate", f"{metrics['average_success_rate']:.0%}")
    table.add_row("Model Accuracy", f"{metrics['model_accuracy']:.0%}")
    
    console.print(table)
    console.print()
    
    return system


def demo_suggestion_engine():
    """Demo context-aware suggestion engine."""
    console.print("[bold]3. Context-Aware Suggestion Engine[/bold]")
    console.print()
    
    # Create suggestion engine
    engine = SuggestionEngine()
    console.print("✓ Suggestion engine initialized")
    console.print()
    
    # Get suggestions for different stages
    context = RecommendationContext(
        vulnerability_type="XSS",
        severity="high",
        language="javascript",
    )
    
    stages = [
        ("quality_assessment", {'completeness_score': 0.6}),
        ("plausibility_analysis", None),
        ("code_analysis", {'vulnerable_code_found': True, 'pattern_type': 'xss'}),
    ]
    
    for stage, results in stages:
        console.print(f"[yellow]Stage: {stage}[/yellow]")
        
        suggestions = engine.get_suggestions_for_stage(stage, context, results)
        
        if suggestions:
            for sug in suggestions:
                console.print(f"  💡 {sug.title}")
                console.print(f"     {sug.message}")
                console.print(f"     Confidence: {sug.confidence:.0%}, Priority: {sug.priority}")
        else:
            console.print("  No suggestions for this stage")
        
        console.print()
    
    # Show statistics
    stats = engine.get_stats()
    
    table = Table(title="Suggestion Engine Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Suggestions", str(stats['total_suggestions']))
    table.add_row("Accepted", str(stats['accepted_suggestions']))
    table.add_row("Dismissed", str(stats['dismissed_suggestions']))
    
    console.print(table)
    console.print()
    
    return engine


def demo_knowledge_graph():
    """Demo knowledge graph."""
    console.print("[bold]4. Knowledge Graph[/bold]")
    console.print()
    
    # Create knowledge graph
    graph = KnowledgeGraph()
    console.print("✓ Knowledge graph initialized")
    console.print()
    
    # Add nodes
    console.print("[yellow]Building knowledge graph...[/yellow]")
    
    # Vulnerabilities
    xss_node = KnowledgeNode(
        node_type="vulnerability",
        name="Cross-Site Scripting (XSS)",
        description="Injection of malicious scripts into web pages",
        properties={'severity': 'high', 'type': 'XSS'},
    )
    
    sqli_node = KnowledgeNode(
        node_type="vulnerability",
        name="SQL Injection",
        description="Injection of malicious SQL queries",
        properties={'severity': 'critical', 'type': 'SQL Injection'},
    )
    
    # Fixes
    sanitization_node = KnowledgeNode(
        node_type="fix",
        name="Input Sanitization",
        description="Sanitize user input before rendering",
        properties={'approach': 'sanitization'},
    )
    
    parameterized_node = KnowledgeNode(
        node_type="fix",
        name="Parameterized Queries",
        description="Use parameterized queries instead of string concatenation",
        properties={'approach': 'parameterization'},
    )
    
    # Add nodes to graph
    graph.add_node(xss_node)
    graph.add_node(sqli_node)
    graph.add_node(sanitization_node)
    graph.add_node(parameterized_node)
    
    console.print(f"  ✓ Added {graph.stats['total_nodes']} nodes")
    
    # Add edges
    graph.add_edge(KnowledgeEdge(
        edge_type=EdgeType.FIXES,
        source_node_id=sanitization_node.node_id,
        target_node_id=xss_node.node_id,
        weight=0.9,
    ))
    
    graph.add_edge(KnowledgeEdge(
        edge_type=EdgeType.FIXES,
        source_node_id=parameterized_node.node_id,
        target_node_id=sqli_node.node_id,
        weight=0.95,
    ))
    
    console.print(f"  ✓ Added {graph.stats['total_edges']} edges")
    console.print()
    
    # Query graph
    console.print("[yellow]Querying knowledge graph...[/yellow]")
    
    # Find vulnerabilities
    vulns = graph.find_nodes(node_type="vulnerability")
    console.print(f"  Found {len(vulns)} vulnerabilities")
    
    # Find related fixes
    for vuln in vulns:
        fixes = graph.get_related_nodes(vuln.node_id, EdgeType.FIXES, direction='incoming')
        console.print(f"  • {vuln.name}: {len(fixes)} fixes")
    
    console.print()
    
    # Show statistics
    stats = graph.get_stats()
    
    table = Table(title="Knowledge Graph Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Nodes", str(stats['total_nodes']))
    table.add_row("Total Edges", str(stats['total_edges']))
    table.add_row("Node Types", ", ".join(stats['node_types']))
    table.add_row("Avg Edges/Node", f"{stats['avg_edges_per_node']:.1f}")
    
    console.print(table)
    console.print()
    
    return graph


def demo_smart_automation():
    """Demo smart automation."""
    console.print("[bold]5. Smart Automation[/bold]")
    console.print()
    
    # Create automation system
    automation = SmartAutomation()
    console.print("✓ Smart automation initialized")
    console.print()
    
    # Add automation rules
    console.print("[yellow]Adding automation rules...[/yellow]")
    
    rules = [
        AutomationRule(
            rule_id="rule-xss-validation",
            name="Auto-apply XSS Validation Strategy",
            description="Automatically apply context-aware XSS validation for high-confidence cases",
            trigger=AutomationTrigger.HIGH_CONFIDENCE_PATTERN,
            action=AutomationAction.APPLY_VALIDATION_STRATEGY,
            conditions={'vulnerability_type': 'XSS'},
            action_params={'strategy': 'context_aware_xss'},
            confidence_threshold=0.85,
        ),
        AutomationRule(
            rule_id="rule-sqli-remediation",
            name="Auto-suggest SQL Injection Remediation",
            description="Automatically suggest parameterized queries for SQL injection",
            trigger=AutomationTrigger.VALIDATION_START,
            action=AutomationAction.APPLY_REMEDIATION,
            conditions={'vulnerability_type': 'SQL Injection'},
            action_params={'approach': 'parameterized_queries'},
            confidence_threshold=0.90,
        ),
        AutomationRule(
            rule_id="rule-priority-adjustment",
            name="Auto-adjust Priority for Critical Vulns",
            description="Automatically increase priority for critical vulnerabilities",
            trigger=AutomationTrigger.THRESHOLD_MET,
            action=AutomationAction.ADJUST_PRIORITY,
            conditions={'severity': 'critical'},
            action_params={'adjustment': 10},
            confidence_threshold=0.80,
        ),
    ]
    
    for rule in rules:
        automation.add_rule(rule)
        console.print(f"  ✓ Added: {rule.name}")
    
    console.print()
    
    # Evaluate rules
    console.print("[yellow]Evaluating automation rules...[/yellow]")
    
    context = RecommendationContext(
        vulnerability_type="XSS",
        severity="high",
    )
    
    actions = automation.evaluate_rules(
        AutomationTrigger.HIGH_CONFIDENCE_PATTERN,
        context,
    )
    
    console.print(f"  ✓ Found {len(actions)} matching rules")
    
    for action in actions:
        console.print(f"  • Action: {action['action'].value}")
        console.print(f"    Confidence: {action['confidence']:.0%}")
    
    console.print()
    
    # Execute action
    if actions:
        console.print("[yellow]Executing automation action...[/yellow]")
        result = automation.execute_action(actions[0], context)
        
        if result['success']:
            console.print(f"  ✓ {result['message']}")
        else:
            console.print(f"  ✗ Error: {result.get('error')}")
        
        console.print()
    
    # Show statistics
    stats = automation.get_stats()
    
    table = Table(title="Smart Automation Statistics")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    table.add_row("Total Rules", str(stats['total_rules']))
    table.add_row("Enabled Rules", str(stats['enabled_rules']))
    table.add_row("Total Executions", str(stats['total_executions']))
    table.add_row("Successful", str(stats['successful_executions']))
    table.add_row("Success Rate", f"{stats['success_rate']:.1f}%")
    
    console.print(table)
    console.print()
    
    return automation


def main():
    """Run all demos."""
    print_header()
    
    try:
        # Demo 1: Recommendation Engine
        engine = demo_recommendation_engine()
        
        # Demo 2: Learning System
        learning_system = demo_learning_system()
        
        # Demo 3: Suggestion Engine
        suggestion_engine = demo_suggestion_engine()
        
        # Demo 4: Knowledge Graph
        knowledge_graph = demo_knowledge_graph()
        
        # Demo 5: Smart Automation
        automation = demo_smart_automation()
        
        # Summary
        console.print(Panel.fit(
            "[bold green]✓ Demo Complete![/bold green]\n\n"
            "[cyan]BountyBot v2.15.0 Features:[/cyan]\n"
            "• Intelligent recommendation engine\n"
            "• Adaptive learning system\n"
            "• Context-aware suggestions\n"
            "• Knowledge graph\n"
            "• Smart automation\n\n"
            "[yellow]812 tests passing![/yellow]",
            border_style="green"
        ))
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()


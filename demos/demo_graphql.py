#!/usr/bin/env python3
"""
Demo script for GraphQL API & WebSocket Subscriptions.

Demonstrates:
- GraphQL schema and types
- Queries for data retrieval
- Mutations for data modification
- Subscriptions for real-time updates
- WebSocket connections
- Authentication and authorization
"""

import sys


def print_header(title: str):
    """Print section header."""
    print()
    print("=" * 80)
    print(f"  {title}")
    print("=" * 80)
    print()


def print_subheader(title: str):
    """Print subsection header."""
    print()
    print(f"📌 {title}")
    print("-" * 80)


def demo_graphql_availability():
    """Demonstrate GraphQL availability check."""
    print_header("GraphQL API & WebSocket Subscriptions - Availability Check")
    
    try:
        import strawberry
        print("✓ Strawberry GraphQL is available")
        print(f"  Version: {strawberry.__version__ if hasattr(strawberry, '__version__') else 'unknown'}")
    except ImportError:
        print("⚠️  Strawberry GraphQL is not available")
        print("   Install with: pip install 'strawberry-graphql[fastapi]'")
        return False
    
    try:
        from fastapi import FastAPI
        print("✓ FastAPI is available")
    except ImportError:
        print("⚠️  FastAPI is not available")
        print("   Install with: pip install fastapi")
        return False
    
    try:
        import uvicorn
        print("✓ Uvicorn is available")
    except ImportError:
        print("⚠️  Uvicorn is not available")
        print("   Install with: pip install uvicorn")
        return False
    
    return True


def demo_graphql_types():
    """Demonstrate GraphQL types."""
    print_header("GraphQL Types")
    
    from bountybot.graphql.types import (
        VerdictEnum,
        SeverityEnum,
        PriorityLevelEnum
    )
    
    print_subheader("Enums")
    
    if hasattr(VerdictEnum, 'VALID'):
        print("VerdictEnum:")
        print(f"  - VALID: {VerdictEnum.VALID.value}")
        print(f"  - INVALID: {VerdictEnum.INVALID.value}")
        print(f"  - UNCERTAIN: {VerdictEnum.UNCERTAIN.value}")
        print()
    
    if hasattr(SeverityEnum, 'CRITICAL'):
        print("SeverityEnum:")
        print(f"  - CRITICAL: {SeverityEnum.CRITICAL.value}")
        print(f"  - HIGH: {SeverityEnum.HIGH.value}")
        print(f"  - MEDIUM: {SeverityEnum.MEDIUM.value}")
        print(f"  - LOW: {SeverityEnum.LOW.value}")
        print(f"  - INFO: {SeverityEnum.INFO.value}")
        print()
    
    if hasattr(PriorityLevelEnum, 'P0'):
        print("PriorityLevelEnum:")
        print(f"  - P0: {PriorityLevelEnum.P0.value}")
        print(f"  - P1: {PriorityLevelEnum.P1.value}")
        print(f"  - P2: {PriorityLevelEnum.P2.value}")
        print(f"  - P3: {PriorityLevelEnum.P3.value}")
        print(f"  - P4: {PriorityLevelEnum.P4.value}")


def demo_graphql_schema():
    """Demonstrate GraphQL schema."""
    print_header("GraphQL Schema")
    
    from bountybot.graphql.schema import schema
    
    if not schema:
        print("⚠️  GraphQL schema not available")
        return
    
    print("✓ GraphQL schema created successfully")
    print()
    
    print_subheader("Schema Components")
    print(f"Query Type: {schema.query_type}")
    print(f"Mutation Type: {schema.mutation_type}")
    print(f"Subscription Type: {schema.subscription_type}")


def demo_graphql_queries():
    """Demonstrate GraphQL queries."""
    print_header("GraphQL Queries")
    
    from bountybot.graphql.queries import Query
    
    query = Query()
    
    print_subheader("Basic Queries")
    
    if hasattr(query, 'hello'):
        result = query.hello()
        print(f"hello: {result}")
    
    if hasattr(query, 'version'):
        result = query.version()
        print(f"version: {result}")
    
    print()
    print_subheader("Available Queries")
    print("  - hello: String!")
    print("  - version: String!")
    print("  - validationReport(id: ID!): ValidationReportType")
    print("  - validationReports(filter: ValidationReportFilterInput, limit: Int, offset: Int): ValidationReportConnection!")
    print("  - metrics: MetricsType!")


def demo_graphql_mutations():
    """Demonstrate GraphQL mutations."""
    print_header("GraphQL Mutations")
    
    print_subheader("Available Mutations")
    print("  - submitValidation(input: ValidationReportInput!): ValidationReportType | ErrorResponse!")
    print("  - deleteValidationReport(id: ID!): SuccessResponse | ErrorResponse!")
    print("  - updateValidationReport(id: ID!, title: String, description: String): ValidationReportType | ErrorResponse!")
    print()
    
    print_subheader("Example Mutation")
    print("""
mutation {
  submitValidation(input: {
    reportPath: "examples/sql_injection.json"
    codebasePath: "/path/to/code"
    priority: "HIGH"
  }) {
    ... on ValidationReportType {
      id
      reportId
      title
      verdict
      confidence
    }
    ... on ErrorResponse {
      error
      message
    }
  }
}
    """)


def demo_graphql_subscriptions():
    """Demonstrate GraphQL subscriptions."""
    print_header("GraphQL Subscriptions")
    
    print_subheader("Available Subscriptions")
    print("  - validationStatusUpdates(reportId: String): ValidationStatusUpdate!")
    print("  - metricsUpdates: MetricsUpdate!")
    print("  - heartbeat(interval: Int): String!")
    print()
    
    print_subheader("Example Subscription - Heartbeat")
    print("""
subscription {
  heartbeat(interval: 5)
}
    """)
    
    print_subheader("Example Subscription - Validation Status")
    print("""
subscription {
  validationStatusUpdates(reportId: "report123") {
    reportId
    status
    progress
    message
    timestamp
  }
}
    """)
    
    print_subheader("Example Subscription - Metrics")
    print("""
subscription {
  metricsUpdates {
    totalReports
    validReports
    invalidReports
    timestamp
  }
}
    """)


def demo_graphql_context():
    """Demonstrate GraphQL context."""
    print_header("GraphQL Context & Authentication")
    
    from bountybot.graphql.context import GraphQLContext
    
    print_subheader("Unauthenticated Context")
    context = GraphQLContext()
    print(f"  is_authenticated: {context.is_authenticated}")
    print(f"  user_id: {context.user_id}")
    print(f"  api_key: {context.api_key}")
    print()
    
    print_subheader("Authenticated Context (with user)")
    context = GraphQLContext(user_id="user123", organization_id="org456")
    print(f"  is_authenticated: {context.is_authenticated}")
    print(f"  user_id: {context.user_id}")
    print(f"  organization_id: {context.organization_id}")
    print()
    
    print_subheader("Authenticated Context (with API key)")
    context = GraphQLContext(api_key="key789")
    print(f"  is_authenticated: {context.is_authenticated}")
    print(f"  api_key: {context.api_key}")


def demo_graphql_app():
    """Demonstrate GraphQL FastAPI app."""
    print_header("GraphQL FastAPI Application")
    
    from bountybot.graphql.app import graphql_app
    
    if not graphql_app:
        print("⚠️  GraphQL app not available")
        print("   Install dependencies: pip install 'strawberry-graphql[fastapi]'")
        return
    
    print("✓ GraphQL FastAPI app created successfully")
    print()
    
    print_subheader("Endpoints")
    print("  - GET  /           - Root endpoint")
    print("  - GET  /health     - Health check")
    print("  - POST /graphql    - GraphQL API")
    print("  - GET  /graphql    - GraphiQL IDE (in browser)")
    print("  - WS   /graphql    - WebSocket subscriptions")
    print()
    
    print_subheader("Starting the Server")
    print("  python -m bountybot.graphql.cli serve")
    print("  python -m bountybot.graphql.cli serve --host 0.0.0.0 --port 8001")
    print("  python -m bountybot.graphql.cli serve --reload")


def demo_graphql_features():
    """Demonstrate GraphQL features."""
    print_header("GraphQL Features Summary")
    
    features = [
        ("Type-Safe Schema", [
            "Strawberry GraphQL with Python type hints",
            "Automatic schema generation",
            "Schema introspection",
            "GraphiQL IDE for exploration"
        ]),
        ("Queries (Read Operations)", [
            "hello - Test query",
            "version - API version",
            "validationReport - Get single report",
            "validationReports - Get paginated reports with filters",
            "metrics - Get validation metrics"
        ]),
        ("Mutations (Write Operations)", [
            "submitValidation - Submit report for validation",
            "deleteValidationReport - Delete report",
            "updateValidationReport - Update report"
        ]),
        ("Subscriptions (Real-Time)", [
            "validationStatusUpdates - Real-time validation progress",
            "metricsUpdates - Real-time metrics updates",
            "heartbeat - WebSocket connection test"
        ]),
        ("Authentication & Authorization", [
            "Bearer token authentication",
            "Field-level authorization",
            "Permission checking",
            "Context-based access control"
        ]),
        ("WebSocket Support", [
            "Real-time bidirectional communication",
            "Subscription filtering",
            "Connection authentication",
            "Automatic reconnection"
        ])
    ]
    
    for feature_name, items in features:
        print(f"✅ {feature_name}:")
        for item in items:
            print(f"   • {item}")
        print()


def main():
    """Main demo function."""
    print()
    print("╔" + "═" * 78 + "╗")
    print("║" + " " * 78 + "║")
    print("║" + "  🚀 BountyBot GraphQL API & WebSocket Subscriptions Demo".center(78) + "║")
    print("║" + " " * 78 + "║")
    print("╚" + "═" * 78 + "╝")
    
    # Check availability
    if not demo_graphql_availability():
        print()
        print("⚠️  Some dependencies are missing. Install them to use GraphQL API.")
        print()
        return
    
    # Run demos
    demo_graphql_types()
    demo_graphql_schema()
    demo_graphql_queries()
    demo_graphql_mutations()
    demo_graphql_subscriptions()
    demo_graphql_context()
    demo_graphql_app()
    demo_graphql_features()
    
    # Final message
    print_header("Next Steps")
    print("1. Start the GraphQL server:")
    print("   python -m bountybot.graphql.cli serve")
    print()
    print("2. Open GraphiQL IDE in browser:")
    print("   http://localhost:8001/graphql")
    print()
    print("3. Try example queries, mutations, and subscriptions")
    print()
    print("4. Test WebSocket subscriptions:")
    print("   subscription { heartbeat(interval: 5) }")
    print()
    print("5. Integrate with your application using GraphQL client")
    print()


if __name__ == '__main__':
    main()


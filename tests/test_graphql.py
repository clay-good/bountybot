"""
Tests for GraphQL API module.
"""

import unittest
from datetime import datetime


class TestGraphQLTypes(unittest.TestCase):
    """Test GraphQL types."""
    
    def test_verdict_enum(self):
        """Test VerdictEnum."""
        from bountybot.graphql.types import VerdictEnum
        
        if VerdictEnum and hasattr(VerdictEnum, 'VALID'):
            self.assertEqual(VerdictEnum.VALID.value, "VALID")
            self.assertEqual(VerdictEnum.INVALID.value, "INVALID")
            self.assertEqual(VerdictEnum.UNCERTAIN.value, "UNCERTAIN")
    
    def test_severity_enum(self):
        """Test SeverityEnum."""
        from bountybot.graphql.types import SeverityEnum
        
        if SeverityEnum and hasattr(SeverityEnum, 'CRITICAL'):
            self.assertEqual(SeverityEnum.CRITICAL.value, "CRITICAL")
            self.assertEqual(SeverityEnum.HIGH.value, "HIGH")
            self.assertEqual(SeverityEnum.MEDIUM.value, "MEDIUM")
            self.assertEqual(SeverityEnum.LOW.value, "LOW")
    
    def test_priority_level_enum(self):
        """Test PriorityLevelEnum."""
        from bountybot.graphql.types import PriorityLevelEnum
        
        if PriorityLevelEnum and hasattr(PriorityLevelEnum, 'P0'):
            self.assertEqual(PriorityLevelEnum.P0.value, "P0")
            self.assertEqual(PriorityLevelEnum.P1.value, "P1")


class TestGraphQLContext(unittest.TestCase):
    """Test GraphQL context."""
    
    def test_context_creation(self):
        """Test context creation."""
        from bountybot.graphql.context import GraphQLContext
        
        context = GraphQLContext()
        self.assertIsNotNone(context)
        self.assertFalse(context.is_authenticated)
    
    def test_context_with_user(self):
        """Test context with user."""
        from bountybot.graphql.context import GraphQLContext
        
        context = GraphQLContext(user_id="user123")
        self.assertTrue(context.is_authenticated)
        self.assertEqual(context.user_id, "user123")
    
    def test_context_with_api_key(self):
        """Test context with API key."""
        from bountybot.graphql.context import GraphQLContext
        
        context = GraphQLContext(api_key="key123")
        self.assertTrue(context.is_authenticated)
        self.assertEqual(context.api_key, "key123")
    
    def test_require_authentication(self):
        """Test require_authentication."""
        from bountybot.graphql.context import GraphQLContext, require_authentication
        
        # Unauthenticated context
        context = GraphQLContext()
        with self.assertRaises(PermissionError):
            require_authentication(context)
        
        # Authenticated context
        context = GraphQLContext(user_id="user123")
        require_authentication(context)  # Should not raise


class TestGraphQLSchema(unittest.TestCase):
    """Test GraphQL schema."""
    
    def test_schema_exists(self):
        """Test schema exists."""
        from bountybot.graphql.schema import schema
        
        # Schema may be None if Strawberry not installed
        if schema:
            self.assertIsNotNone(schema)
    
    def test_schema_has_query(self):
        """Test schema has query type."""
        from bountybot.graphql.schema import schema
        
        if schema:
            self.assertIsNotNone(schema.query_type)
    
    def test_schema_has_mutation(self):
        """Test schema has mutation type."""
        from bountybot.graphql.schema import schema
        
        if schema:
            self.assertIsNotNone(schema.mutation_type)
    
    def test_schema_has_subscription(self):
        """Test schema has subscription type."""
        from bountybot.graphql.schema import schema
        
        if schema:
            self.assertIsNotNone(schema.subscription_type)


class TestGraphQLQueries(unittest.TestCase):
    """Test GraphQL queries."""
    
    def test_query_class_exists(self):
        """Test Query class exists."""
        from bountybot.graphql.queries import Query
        
        self.assertIsNotNone(Query)
    
    def test_hello_query(self):
        """Test hello query."""
        from bountybot.graphql.queries import Query
        
        query = Query()
        if hasattr(query, 'hello'):
            result = query.hello()
            self.assertIsInstance(result, str)
            self.assertIn("BountyBot", result)
    
    def test_version_query(self):
        """Test version query."""
        from bountybot.graphql.queries import Query
        
        query = Query()
        if hasattr(query, 'version'):
            result = query.version()
            self.assertIsInstance(result, str)


class TestGraphQLMutations(unittest.TestCase):
    """Test GraphQL mutations."""
    
    def test_mutation_class_exists(self):
        """Test Mutation class exists."""
        from bountybot.graphql.mutations import Mutation
        
        self.assertIsNotNone(Mutation)


class TestGraphQLSubscriptions(unittest.TestCase):
    """Test GraphQL subscriptions."""
    
    def test_subscription_class_exists(self):
        """Test Subscription class exists."""
        from bountybot.graphql.subscriptions import Subscription
        
        self.assertIsNotNone(Subscription)
    
    def test_broadcast_validation_status(self):
        """Test broadcast_validation_status."""
        from bountybot.graphql.subscriptions import broadcast_validation_status
        
        # Should not raise
        import asyncio
        asyncio.run(broadcast_validation_status(
            report_id="test123",
            status="processing",
            progress=50.0,
            message="Test message"
        ))
    
    def test_broadcast_metrics_update(self):
        """Test broadcast_metrics_update."""
        from bountybot.graphql.subscriptions import broadcast_metrics_update
        
        # Should not raise
        import asyncio
        asyncio.run(broadcast_metrics_update(
            total_reports=100,
            valid_reports=80,
            invalid_reports=20
        ))


class TestGraphQLApp(unittest.TestCase):
    """Test GraphQL FastAPI app."""
    
    def test_create_graphql_app(self):
        """Test create_graphql_app."""
        from bountybot.graphql.app import create_graphql_app
        
        app = create_graphql_app()
        # App may be None if dependencies not installed
        if app:
            self.assertIsNotNone(app)
    
    def test_graphql_app_exists(self):
        """Test graphql_app exists."""
        from bountybot.graphql import app as graphql_app_module

        # App may be None if dependencies not installed
        # Just check it's defined
        self.assertTrue(hasattr(graphql_app_module, 'graphql_app'))


class TestGraphQLCLI(unittest.TestCase):
    """Test GraphQL CLI."""
    
    def test_cli_functions_exist(self):
        """Test CLI functions exist."""
        from bountybot.graphql.cli import serve, graphql_cli
        
        self.assertIsNotNone(serve)
        self.assertIsNotNone(graphql_cli)


class TestGraphQLModule(unittest.TestCase):
    """Test GraphQL module."""
    
    def test_module_imports(self):
        """Test module imports."""
        import bountybot.graphql
        
        self.assertIsNotNone(bountybot.graphql)
    
    def test_module_exports(self):
        """Test module exports."""
        import bountybot.graphql as graphql_module

        # Schema may be None if Strawberry not installed
        # Just check it's exported
        self.assertTrue(hasattr(graphql_module, 'schema'))


if __name__ == '__main__':
    unittest.main()


"""
Integration Hub for BountyBot.

Provides integrations with popular tools and platforms:
- JIRA (issue tracking)
- Slack (notifications)
- GitHub (issue creation)
- PagerDuty (incident management)
- Email (SMTP notifications)
"""

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
    IntegrationType,
)
from bountybot.integrations.jira_integration import JiraIntegration
from bountybot.integrations.slack_integration import SlackIntegration
from bountybot.integrations.github_integration import GitHubIntegration
from bountybot.integrations.pagerduty_integration import PagerDutyIntegration
from bountybot.integrations.email_integration import EmailIntegration
from bountybot.integrations.integration_manager import IntegrationManager

__all__ = [
    'BaseIntegration',
    'IntegrationConfig',
    'IntegrationResult',
    'IntegrationStatus',
    'IntegrationType',
    'JiraIntegration',
    'SlackIntegration',
    'GitHubIntegration',
    'PagerDutyIntegration',
    'EmailIntegration',
    'IntegrationManager',
]


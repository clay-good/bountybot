"""
Tests for CI/CD Configuration

Validates that CI/CD configuration files are properly structured and functional.
"""

import os
import unittest
import yaml
import json
from pathlib import Path


class TestCICDConfiguration(unittest.TestCase):
    """Test CI/CD configuration files."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
        self.github_workflows = self.repo_root / ".github" / "workflows"
        self.k8s_dir = self.repo_root / "k8s"
        self.monitoring_dir = self.repo_root / "monitoring"
    
    def test_github_workflows_exist(self):
        """Test that GitHub workflow files exist."""
        workflows = [
            "ci.yml",
            "cd.yml",
            "scheduled.yml",
            "pr-checks.yml"
        ]
        
        for workflow in workflows:
            workflow_path = self.github_workflows / workflow
            self.assertTrue(
                workflow_path.exists(),
                f"Workflow file {workflow} does not exist"
            )
    
    def test_ci_workflow_structure(self):
        """Test CI workflow structure."""
        ci_path = self.github_workflows / "ci.yml"

        with open(ci_path, 'r') as f:
            ci_config = yaml.safe_load(f)

        # Check required fields
        self.assertIn('name', ci_config)
        # YAML parses 'on:' as True (boolean), not string 'on'
        self.assertTrue(True in ci_config or 'on' in ci_config, "'on' trigger not found in CI workflow")
        self.assertIn('jobs', ci_config)

        # Check required jobs
        required_jobs = [
            'code-quality',
            'unit-tests',
            'integration-tests',
            'security-scan',
            'docker-build'
        ]

        for job in required_jobs:
            self.assertIn(job, ci_config['jobs'], f"Job {job} not found in CI workflow")
    
    def test_cd_workflow_structure(self):
        """Test CD workflow structure."""
        cd_path = self.github_workflows / "cd.yml"

        with open(cd_path, 'r') as f:
            cd_config = yaml.safe_load(f)

        # Check required fields
        self.assertIn('name', cd_config)
        # YAML parses 'on:' as True (boolean), not string 'on'
        self.assertTrue(True in cd_config or 'on' in cd_config, "'on' trigger not found in CD workflow")
        self.assertIn('jobs', cd_config)

        # Check required jobs
        required_jobs = [
            'build',
            'docker-build-push',
            'create-release',
            'deploy-staging',
            'deploy-production'
        ]

        for job in required_jobs:
            self.assertIn(job, cd_config['jobs'], f"Job {job} not found in CD workflow")
    
    def test_scheduled_workflow_structure(self):
        """Test scheduled workflow structure."""
        scheduled_path = self.github_workflows / "scheduled.yml"

        with open(scheduled_path, 'r') as f:
            scheduled_config = yaml.safe_load(f)

        # Check required fields
        self.assertIn('name', scheduled_config)
        # YAML parses 'on:' as True (boolean), not string 'on'
        on_config = scheduled_config.get(True) or scheduled_config.get('on')
        self.assertIsNotNone(on_config, "'on' trigger not found in scheduled workflow")
        self.assertIn('schedule', on_config)

        # Check cron schedule exists
        self.assertTrue(
            len(on_config['schedule']) > 0,
            "No cron schedule defined"
        )
    
    def test_pr_checks_workflow_structure(self):
        """Test PR checks workflow structure."""
        pr_checks_path = self.github_workflows / "pr-checks.yml"

        with open(pr_checks_path, 'r') as f:
            pr_config = yaml.safe_load(f)

        # Check required fields
        self.assertIn('name', pr_config)
        # YAML parses 'on:' as True (boolean), not string 'on'
        on_config = pr_config.get(True) or pr_config.get('on')
        self.assertIsNotNone(on_config, "'on' trigger not found in PR checks workflow")
        self.assertIn('pull_request', on_config)
    
    def test_pylintrc_exists(self):
        """Test that .pylintrc exists."""
        pylintrc_path = self.repo_root / ".pylintrc"
        self.assertTrue(pylintrc_path.exists(), ".pylintrc does not exist")
    
    def test_flake8_config_exists(self):
        """Test that .flake8 exists."""
        flake8_path = self.repo_root / ".flake8"
        self.assertTrue(flake8_path.exists(), ".flake8 does not exist")
    
    def test_pyproject_toml_exists(self):
        """Test that pyproject.toml exists."""
        pyproject_path = self.repo_root / "pyproject.toml"
        self.assertTrue(pyproject_path.exists(), "pyproject.toml does not exist")
    
    def test_pyproject_toml_structure(self):
        """Test pyproject.toml structure."""
        pyproject_path = self.repo_root / "pyproject.toml"
        
        with open(pyproject_path, 'r') as f:
            content = f.read()
        
        # Check for required sections
        required_sections = [
            '[build-system]',
            '[project]',
            '[tool.black]',
            '[tool.isort]',
            '[tool.pytest.ini_options]',
            '[tool.coverage.run]'
        ]
        
        for section in required_sections:
            self.assertIn(section, content, f"Section {section} not found in pyproject.toml")
    
    def test_makefile_exists(self):
        """Test that Makefile exists."""
        makefile_path = self.repo_root / "Makefile"
        self.assertTrue(makefile_path.exists(), "Makefile does not exist")
    
    def test_makefile_targets(self):
        """Test that Makefile has required targets."""
        makefile_path = self.repo_root / "Makefile"
        
        with open(makefile_path, 'r') as f:
            content = f.read()
        
        required_targets = [
            'install',
            'test',
            'lint',
            'format',
            'security',
            'docker-build',
            'ci-all'
        ]
        
        for target in required_targets:
            self.assertIn(f"{target}:", content, f"Target {target} not found in Makefile")
    
    def test_docker_compose_exists(self):
        """Test that docker-compose files exist."""
        compose_files = [
            "docker-compose.yml",
            "docker-compose.dev.yml"
        ]
        
        for compose_file in compose_files:
            compose_path = self.repo_root / compose_file
            self.assertTrue(
                compose_path.exists(),
                f"{compose_file} does not exist"
            )
    
    def test_docker_compose_structure(self):
        """Test docker-compose.yml structure."""
        compose_path = self.repo_root / "docker-compose.yml"
        
        with open(compose_path, 'r') as f:
            compose_config = yaml.safe_load(f)
        
        # Check required fields
        self.assertIn('version', compose_config)
        self.assertIn('services', compose_config)
        
        # Check required services
        required_services = [
            'postgres',
            'redis',
            'api',
            'dashboard'
        ]
        
        for service in required_services:
            self.assertIn(service, compose_config['services'], f"Service {service} not found")
    
    def test_k8s_deployment_exists(self):
        """Test that Kubernetes deployment file exists."""
        deployment_path = self.k8s_dir / "deployment.yaml"
        self.assertTrue(deployment_path.exists(), "k8s/deployment.yaml does not exist")
    
    def test_k8s_deployment_structure(self):
        """Test Kubernetes deployment structure."""
        deployment_path = self.k8s_dir / "deployment.yaml"
        
        with open(deployment_path, 'r') as f:
            # Load all YAML documents
            docs = list(yaml.safe_load_all(f))
        
        # Check that we have multiple resources
        self.assertGreater(len(docs), 5, "Not enough Kubernetes resources defined")
        
        # Check for required resource types
        resource_kinds = [doc.get('kind') for doc in docs if doc]
        
        required_kinds = [
            'Namespace',
            'ConfigMap',
            'Secret',
            'Deployment',
            'Service',
            'PersistentVolumeClaim'
        ]
        
        for kind in required_kinds:
            self.assertIn(kind, resource_kinds, f"Resource kind {kind} not found")
    
    def test_prometheus_config_exists(self):
        """Test that Prometheus configuration exists."""
        prometheus_path = self.monitoring_dir / "prometheus.yml"
        self.assertTrue(prometheus_path.exists(), "monitoring/prometheus.yml does not exist")
    
    def test_prometheus_config_structure(self):
        """Test Prometheus configuration structure."""
        prometheus_path = self.monitoring_dir / "prometheus.yml"
        
        with open(prometheus_path, 'r') as f:
            prometheus_config = yaml.safe_load(f)
        
        # Check required fields
        self.assertIn('global', prometheus_config)
        self.assertIn('scrape_configs', prometheus_config)
        
        # Check for BountyBot scrape configs
        scrape_configs = prometheus_config['scrape_configs']
        job_names = [config['job_name'] for config in scrape_configs]
        
        self.assertIn('bountybot-api', job_names, "BountyBot API scrape config not found")
    
    def test_prometheus_alerts_exist(self):
        """Test that Prometheus alert rules exist."""
        alerts_path = self.monitoring_dir / "alerts" / "bountybot.yml"
        self.assertTrue(alerts_path.exists(), "monitoring/alerts/bountybot.yml does not exist")
    
    def test_prometheus_alerts_structure(self):
        """Test Prometheus alert rules structure."""
        alerts_path = self.monitoring_dir / "alerts" / "bountybot.yml"
        
        with open(alerts_path, 'r') as f:
            alerts_config = yaml.safe_load(f)
        
        # Check required fields
        self.assertIn('groups', alerts_config)
        
        # Check that we have alert groups
        self.assertGreater(len(alerts_config['groups']), 0, "No alert groups defined")
        
        # Check that each group has rules
        for group in alerts_config['groups']:
            self.assertIn('name', group)
            self.assertIn('rules', group)
            self.assertGreater(len(group['rules']), 0, f"No rules in group {group['name']}")
    
    def test_cicd_documentation_exists(self):
        """Test that CI/CD documentation exists."""
        docs_path = self.repo_root / "docs" / "CICD.md"
        self.assertTrue(docs_path.exists(), "docs/CICD.md does not exist")
    
    def test_cicd_documentation_content(self):
        """Test CI/CD documentation content."""
        docs_path = self.repo_root / "docs" / "CICD.md"
        
        with open(docs_path, 'r') as f:
            content = f.read()
        
        # Check for required sections
        required_sections = [
            '## Overview',
            '## Pipeline Architecture',
            '## Configuration Files',
            '## Makefile Commands',
            '## Docker Configuration',
            '## Kubernetes Deployment',
            '## Monitoring',
            '## Secrets Management',
            '## Best Practices',
            '## Troubleshooting'
        ]
        
        for section in required_sections:
            self.assertIn(section, content, f"Section {section} not found in CICD.md")


class TestCICDIntegration(unittest.TestCase):
    """Test CI/CD integration with project."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.repo_root = Path(__file__).parent.parent
    
    def test_dockerfile_exists(self):
        """Test that Dockerfile exists."""
        dockerfile_path = self.repo_root / "Dockerfile"
        self.assertTrue(dockerfile_path.exists(), "Dockerfile does not exist")
    
    def test_requirements_file_exists(self):
        """Test that requirements.txt exists."""
        requirements_path = self.repo_root / "requirements.txt"
        self.assertTrue(requirements_path.exists(), "requirements.txt does not exist")
    
    def test_github_directory_structure(self):
        """Test GitHub directory structure."""
        github_dir = self.repo_root / ".github"
        workflows_dir = github_dir / "workflows"
        
        self.assertTrue(github_dir.exists(), ".github directory does not exist")
        self.assertTrue(workflows_dir.exists(), ".github/workflows directory does not exist")
    
    def test_monitoring_directory_structure(self):
        """Test monitoring directory structure."""
        monitoring_dir = self.repo_root / "monitoring"
        alerts_dir = monitoring_dir / "alerts"
        
        self.assertTrue(monitoring_dir.exists(), "monitoring directory does not exist")
        self.assertTrue(alerts_dir.exists(), "monitoring/alerts directory does not exist")
    
    def test_k8s_directory_structure(self):
        """Test Kubernetes directory structure."""
        k8s_dir = self.repo_root / "k8s"
        
        self.assertTrue(k8s_dir.exists(), "k8s directory does not exist")


if __name__ == '__main__':
    unittest.main()


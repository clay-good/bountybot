# CI/CD Pipeline Documentation

## Overview

BountyBot uses a comprehensive CI/CD pipeline built with GitHub Actions to ensure code quality, security, and reliable deployments. The pipeline includes automated testing, code quality checks, security scanning, Docker image building, and deployment automation.

---

## Pipeline Architecture

### 1. **Continuous Integration (CI)**

Triggered on:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop`
- Manual workflow dispatch

**Workflow File:** `.github/workflows/ci.yml`

#### Jobs:

1. **Code Quality** (Ubuntu Latest)
   - Black (code formatting)
   - isort (import sorting)
   - Flake8 (linting)
   - Pylint (static analysis)
   - MyPy (type checking)
   - Bandit (security scanning)
   - Safety (dependency vulnerability checking)

2. **Unit Tests** (Matrix: Python 3.9-3.12, Ubuntu/macOS)
   - Run all unit tests
   - Generate coverage reports
   - Upload to Codecov

3. **Integration Tests** (Ubuntu Latest + PostgreSQL)
   - Run integration tests with real database
   - Test database connectivity
   - Test API endpoints

4. **Security Scanning**
   - Trivy vulnerability scanner
   - Snyk security scan
   - Upload results to GitHub Security

5. **Docker Build & Test**
   - Build Docker image
   - Test image functionality
   - Scan image with Trivy

6. **Performance Tests**
   - Run benchmark tests
   - Upload benchmark results

7. **Documentation**
   - Build Sphinx documentation
   - Upload documentation artifacts

8. **Test Summary**
   - Aggregate all test results
   - Fail if critical jobs failed

---

### 2. **Continuous Deployment (CD)**

Triggered on:
- Git tags matching `v*.*.*` (e.g., v2.9.0)
- Manual workflow dispatch with environment selection

**Workflow File:** `.github/workflows/cd.yml`

#### Jobs:

1. **Build & Test**
   - Run full test suite
   - Upload coverage to Codecov

2. **Build & Push Docker Image**
   - Build multi-platform image (amd64, arm64)
   - Push to GitHub Container Registry
   - Tag with version, SHA, and latest
   - Scan image with Trivy

3. **Create GitHub Release**
   - Generate changelog from commits
   - Create release with notes
   - Attach artifacts

4. **Deploy to Staging**
   - Deploy to staging environment
   - Run smoke tests
   - Verify deployment

5. **Deploy to Production**
   - Deploy to production environment
   - Run smoke tests
   - Send notifications

6. **Rollback** (On Failure)
   - Automatic rollback on deployment failure
   - Notify team

7. **Performance Monitoring**
   - Run performance tests against production
   - Upload results

---

### 3. **Scheduled Tasks**

Runs daily at 2 AM UTC

**Workflow File:** `.github/workflows/scheduled.yml`

#### Jobs:

1. **Dependency Updates Check**
   - Check for outdated packages
   - Scan for vulnerabilities
   - Create issues if found

2. **Code Quality Metrics**
   - Calculate code complexity
   - Calculate maintainability index
   - Upload metrics

3. **Test Coverage Report**
   - Generate coverage report
   - Upload to artifacts

4. **Performance Benchmarks**
   - Run benchmark suite
   - Store results for trending

5. **Docker Image Cleanup**
   - Delete old untagged images
   - Keep last 10 versions

6. **Database Backup**
   - Backup production database
   - Upload to S3

7. **Health Check Monitoring**
   - Check production health
   - Check staging health
   - Create issues if unhealthy

8. **License Compliance Check**
   - Generate license report
   - Check for incompatible licenses

9. **Documentation Freshness Check**
   - Check if docs need updating
   - Create reminder issues

---

### 4. **Pull Request Checks**

Triggered on PR events

**Workflow File:** `.github/workflows/pr-checks.yml`

#### Jobs:

1. **PR Validation**
   - Check PR title format (semantic)
   - Check for breaking changes
   - Check file changes
   - Comment if tests needed

2. **Automated Code Review**
   - Run linters on changed files
   - Generate review reports
   - Upload artifacts

3. **Test Coverage Check**
   - Run tests with coverage
   - Comment coverage percentage on PR
   - Fail if below threshold

4. **Performance Impact Check**
   - Compare benchmarks with base branch
   - Report performance regressions

5. **Security Impact Check**
   - Scan for new vulnerabilities
   - Compare with base branch

6. **Documentation Check**
   - Check if docs updated
   - Comment if needed

7. **Dependency Check**
   - Check if dependencies changed
   - Audit new dependencies

8. **PR Summary**
   - Aggregate all check results
   - Post summary comment

---

## Configuration Files

### Code Quality Tools

#### `.pylintrc`
- Pylint configuration
- Disabled warnings for common patterns
- Custom naming conventions
- Complexity thresholds

#### `.flake8`
- Flake8 configuration
- Line length: 127
- Max complexity: 15
- Per-file ignores

#### `pyproject.toml`
- Project metadata
- Black configuration
- isort configuration
- pytest configuration
- Coverage configuration
- MyPy configuration
- Ruff configuration

---

## Makefile Commands

The `Makefile` provides convenient commands for local development and CI/CD:

### Installation
```bash
make install          # Install production dependencies
make install-dev      # Install development dependencies
```

### Testing
```bash
make test             # Run all tests
make test-unit        # Run unit tests only
make test-integration # Run integration tests
make test-coverage    # Run tests with coverage
make test-watch       # Run tests in watch mode
```

### Code Quality
```bash
make lint             # Run all linters
make format           # Format code with Black and isort
make security         # Run security checks
```

### Build & Deploy
```bash
make build            # Build distribution packages
make docker-build     # Build Docker image
make docker-run       # Run Docker container
make docker-run-api   # Run API server in Docker
```

### CI/CD
```bash
make ci-test          # Run CI test suite
make ci-lint          # Run CI linting
make ci-security      # Run CI security checks
make ci-all           # Run all CI checks
```

### Metrics
```bash
make metrics          # Show code metrics
make complexity       # Show code complexity
make maintainability  # Show maintainability index
```

---

## Docker Configuration

### Production (`docker-compose.yml`)
- PostgreSQL database
- Redis cache
- API server (3 replicas)
- Dashboard (2 replicas)
- Prometheus monitoring
- Grafana dashboards
- Nginx reverse proxy

### Development (`docker-compose.dev.yml`)
- PostgreSQL database
- Redis cache
- API server (hot reload)
- Dashboard (hot reload)
- Mailhog (email testing)

---

## Kubernetes Deployment

### Manifests (`k8s/deployment.yaml`)

**Resources:**
- Namespace: `bountybot`
- ConfigMap: Application configuration
- Secret: API keys and credentials
- Deployment: API (3 replicas)
- Deployment: Dashboard (2 replicas)
- Service: API (ClusterIP)
- Service: Dashboard (ClusterIP)
- PVC: Validation results (10Gi)
- PVC: Logs (5Gi)
- Ingress: HTTPS with Let's Encrypt
- HPA: Auto-scaling (3-10 replicas for API, 2-5 for dashboard)

**Features:**
- Rolling updates with zero downtime
- Health checks (liveness & readiness)
- Resource limits and requests
- Pod anti-affinity for high availability
- Prometheus annotations for monitoring
- Auto-scaling based on CPU/memory

### Deployment Commands

```bash
# Create namespace and deploy
kubectl apply -f k8s/deployment.yaml

# Check deployment status
kubectl get pods -n bountybot
kubectl get services -n bountybot
kubectl get ingress -n bountybot

# View logs
kubectl logs -f deployment/bountybot-api -n bountybot
kubectl logs -f deployment/bountybot-dashboard -n bountybot

# Scale manually
kubectl scale deployment bountybot-api --replicas=5 -n bountybot

# Update image
kubectl set image deployment/bountybot-api api=ghcr.io/clay-good/bountybot:v2.9.0 -n bountybot

# Rollback
kubectl rollout undo deployment/bountybot-api -n bountybot

# Delete deployment
kubectl delete -f k8s/deployment.yaml
```

---

## Monitoring

### Prometheus Configuration (`monitoring/prometheus.yml`)

**Scrape Targets:**
- BountyBot API (15s interval)
- BountyBot Dashboard (15s interval)
- PostgreSQL (30s interval)
- Redis (30s interval)
- Node exporter (30s interval)
- Kubernetes pods (auto-discovery)

### Alert Rules (`monitoring/alerts/bountybot.yml`)

**Alert Groups:**
1. **API Alerts**
   - High error rate (>5%)
   - Critical error rate (>10%)
   - High latency (P95 >2s)
   - Service down

2. **Validation Alerts**
   - High failure rate (>20%)
   - Slow processing (P95 >60s)

3. **AI Provider Alerts**
   - High error rate (>10%)
   - Cost spike (>$50/hour)
   - High token usage (>1M/hour)

4. **System Alerts**
   - System unhealthy
   - Component unhealthy
   - High memory usage (>90%)
   - Low disk space (>90%)

5. **Database Alerts**
   - Connection failure
   - High query latency (P95 >1s)
   - High connection count (>80)

6. **Integration Alerts**
   - Integration failure (>20%)
   - Webhook delivery failure (>30%)

---

## Secrets Management

### GitHub Secrets

Required secrets for CI/CD:

```
ANTHROPIC_API_KEY       # Anthropic API key
OPENAI_API_KEY          # OpenAI API key (optional)
GEMINI_API_KEY          # Google Gemini API key (optional)
SNYK_TOKEN              # Snyk security scanning token
CODECOV_TOKEN           # Codecov upload token
GITHUB_TOKEN            # Automatically provided by GitHub
```

### Kubernetes Secrets

```bash
# Create secrets
kubectl create secret generic bountybot-secrets \
  --from-literal=ANTHROPIC_API_KEY=your-key \
  --from-literal=DATABASE_URL=postgresql://... \
  --from-literal=JWT_SECRET_KEY=your-secret \
  -n bountybot

# Update secrets
kubectl edit secret bountybot-secrets -n bountybot
```

---

## Best Practices

### 1. **Commit Messages**
Follow conventional commits:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `test:` Test changes
- `build:` Build system changes
- `ci:` CI/CD changes
- `chore:` Other changes

### 2. **Pull Requests**
- Use semantic PR titles
- Include tests for new features
- Update documentation
- Keep PRs focused and small
- Request reviews from team

### 3. **Testing**
- Write tests for all new code
- Maintain >80% coverage
- Run tests locally before pushing
- Fix failing tests immediately

### 4. **Security**
- Never commit secrets
- Use environment variables
- Scan dependencies regularly
- Update dependencies promptly
- Follow security best practices

### 5. **Deployment**
- Use semantic versioning
- Test in staging first
- Monitor after deployment
- Have rollback plan ready
- Document changes in changelog

---

## Troubleshooting

### CI Pipeline Failures

**Tests failing:**
```bash
# Run tests locally
make test-coverage

# Check specific test
pytest tests/test_specific.py -v
```

**Linting errors:**
```bash
# Format code
make format

# Check linting
make lint
```

**Docker build failing:**
```bash
# Build locally
make docker-build

# Check Dockerfile syntax
docker build --no-cache -t bountybot:test .
```

### Deployment Issues

**Kubernetes pods not starting:**
```bash
# Check pod status
kubectl describe pod <pod-name> -n bountybot

# Check logs
kubectl logs <pod-name> -n bountybot

# Check events
kubectl get events -n bountybot --sort-by='.lastTimestamp'
```

**Database connection issues:**
```bash
# Test database connectivity
kubectl run -it --rm debug --image=postgres:15 --restart=Never -- psql -h postgres -U bountybot

# Check database logs
kubectl logs deployment/postgres -n bountybot
```

---

## Support

For issues or questions:
- GitHub Issues: https://github.com/clay-good/bountybot/issues
- Documentation: https://bountybot.readthedocs.io
- Email: team@bountybot.example.com


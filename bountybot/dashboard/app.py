"""
Dashboard FastAPI Application

Web-based dashboard for BountyBot management and monitoring.
"""

import time
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .models import (
    DashboardConfig,
    DashboardStats,
    ReportSummary,
    ReportListRequest,
    ReportListResponse,
    AnalyticsRequest,
    AnalyticsSummary,
    IntegrationStatus,
    WebhookSummary,
    BatchJobSummary,
    SystemHealth,
    TimeRange,
    ReportStatus,
    IntegrationStatusEnum
)

logger = logging.getLogger(__name__)


def create_dashboard_app(config: Optional[Dict[str, Any]] = None) -> FastAPI:
    """
    Create and configure the dashboard FastAPI application.
    
    Args:
        config: Optional configuration dictionary
        
    Returns:
        Configured FastAPI application
    """
    # Initialize dashboard config
    dashboard_config = DashboardConfig()
    if config:
        for key, value in config.items():
            if hasattr(dashboard_config, key):
                setattr(dashboard_config, key, value)
    
    # Create FastAPI app
    app = FastAPI(
        title="BountyBot Dashboard",
        description="Web-based management and monitoring dashboard for BountyBot",
        version="2.5.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc"
    )
    
    # Add middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    
    # Store config in app state
    app.state.config = dashboard_config
    app.state.start_time = time.time()
    
    # Setup templates and static files
    dashboard_dir = Path(__file__).parent
    templates_dir = dashboard_dir / "templates"
    static_dir = dashboard_dir / "static"
    
    # Create directories if they don't exist
    templates_dir.mkdir(exist_ok=True)
    static_dir.mkdir(exist_ok=True)
    
    # Mount static files
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    
    # Setup Jinja2 templates
    templates = Jinja2Templates(directory=str(templates_dir))
    
    # Store templates in app state
    app.state.templates = templates
    
    # ==================== Routes ====================
    
    @app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
    async def dashboard_home(request: Request):
        """Main dashboard page."""
        return templates.TemplateResponse(
            request=request,
            name="dashboard.html",
            context={
                "title": dashboard_config.title,
                "refresh_interval": dashboard_config.refresh_interval
            }
        )

    @app.get("/reports", response_class=HTMLResponse, tags=["Dashboard"])
    async def reports_page(request: Request):
        """Reports management page."""
        return templates.TemplateResponse(
            request=request,
            name="reports.html",
            context={"title": "Reports"}
        )

    @app.get("/analytics", response_class=HTMLResponse, tags=["Dashboard"])
    async def analytics_page(request: Request):
        """Analytics and visualizations page."""
        return templates.TemplateResponse(
            request=request,
            name="analytics.html",
            context={"title": "Analytics"}
        )

    @app.get("/integrations", response_class=HTMLResponse, tags=["Dashboard"])
    async def integrations_page(request: Request):
        """Integrations management page."""
        return templates.TemplateResponse(
            request=request,
            name="integrations.html",
            context={"title": "Integrations"}
        )

    @app.get("/webhooks", response_class=HTMLResponse, tags=["Dashboard"])
    async def webhooks_page(request: Request):
        """Webhooks management page."""
        return templates.TemplateResponse(
            request=request,
            name="webhooks.html",
            context={"title": "Webhooks"}
        )

    @app.get("/batch", response_class=HTMLResponse, tags=["Dashboard"])
    async def batch_page(request: Request):
        """Batch processing page."""
        return templates.TemplateResponse(
            request=request,
            name="batch.html",
            context={"title": "Batch Processing"}
        )
    
    # ==================== API Routes ====================
    
    @app.get("/api/health", tags=["API"])
    async def health_check():
        """Health check endpoint."""
        return {"status": "healthy", "timestamp": datetime.now().isoformat()}
    
    @app.get("/api/stats", response_model=DashboardStats, tags=["API"])
    async def get_dashboard_stats():
        """Get real-time dashboard statistics."""
        try:
            from bountybot.database import ReportRepository, session_scope
            from bountybot.integrations import IntegrationManager
            from bountybot.webhooks import WebhookManager
            
            stats = DashboardStats(
                total_reports=0,
                reports_today=0,
                reports_this_week=0,
                reports_this_month=0,
                valid_count=0,
                invalid_count=0,
                uncertain_count=0,
                average_confidence=0.0,
                average_processing_time=0.0,
                total_cost=0.0,
                cost_today=0.0,
                active_integrations=0,
                healthy_integrations=0,
                active_webhooks=0,
                system_uptime=time.time() - app.state.start_time,
                api_requests_today=0
            )
            
            # Get report statistics from database
            try:
                with session_scope() as session:
                    repo = ReportRepository(session)
                    
                    # Total reports
                    stats.total_reports = repo.count_all()
                    
                    # Reports by time period
                    now = datetime.now()
                    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
                    week_start = now - timedelta(days=7)
                    month_start = now - timedelta(days=30)
                    
                    stats.reports_today = repo.count_by_date_range(today_start, now)
                    stats.reports_this_week = repo.count_by_date_range(week_start, now)
                    stats.reports_this_month = repo.count_by_date_range(month_start, now)
                    
                    # Verdict counts
                    verdict_counts = repo.get_verdict_counts()
                    stats.valid_count = verdict_counts.get('VALID', 0)
                    stats.invalid_count = verdict_counts.get('INVALID', 0)
                    stats.uncertain_count = verdict_counts.get('UNCERTAIN', 0)
                    
                    # Average metrics
                    metrics = repo.get_average_metrics()
                    stats.average_confidence = metrics.get('confidence', 0.0)
                    stats.average_processing_time = metrics.get('processing_time', 0.0)
                    stats.total_cost = metrics.get('total_cost', 0.0)
                    stats.cost_today = repo.get_cost_by_date_range(today_start, now)
                    
            except Exception as e:
                logger.warning(f"Could not fetch database stats: {e}")
            
            # Get integration statistics
            try:
                # This would be implemented with actual integration manager
                stats.active_integrations = 5  # Placeholder
                stats.healthy_integrations = 4  # Placeholder
            except Exception as e:
                logger.warning(f"Could not fetch integration stats: {e}")
            
            # Get webhook statistics
            try:
                webhook_manager = WebhookManager()
                webhooks = webhook_manager.list_webhooks(status='active')
                stats.active_webhooks = len(webhooks)
            except Exception as e:
                logger.warning(f"Could not fetch webhook stats: {e}")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error fetching dashboard stats: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/reports/list", response_model=ReportListResponse, tags=["API"])
    async def list_reports(request: ReportListRequest):
        """List reports with filtering and pagination."""
        try:
            from bountybot.database import ReportRepository, session_scope
            
            with session_scope() as session:
                repo = ReportRepository(session)
                
                # Build filters
                filters = {}
                if request.verdict:
                    filters['verdict'] = request.verdict
                if request.severity:
                    filters['severity'] = request.severity
                if request.vulnerability_type:
                    filters['vulnerability_type'] = request.vulnerability_type
                if request.researcher:
                    filters['researcher'] = request.researcher
                if request.start_date:
                    filters['start_date'] = request.start_date
                if request.end_date:
                    filters['end_date'] = request.end_date
                
                # Get reports
                reports, total = repo.list_reports(
                    page=request.page,
                    page_size=request.page_size,
                    filters=filters,
                    sort_by=request.sort_by,
                    sort_order=request.sort_order
                )
                
                # Convert to ReportSummary objects
                report_summaries = [
                    ReportSummary(
                        report_id=str(r.id),
                        title=r.title,
                        vulnerability_type=r.vulnerability_type,
                        verdict=r.verdict,
                        confidence=r.confidence,
                        severity=r.severity,
                        cvss_score=r.cvss_score,
                        priority_level=r.priority_level,
                        researcher=r.researcher_name,
                        submitted_at=r.submitted_at,
                        processed_at=r.processed_at,
                        processing_time=r.processing_time,
                        status=ReportStatus.COMPLETED if r.processed_at else ReportStatus.PENDING,
                        integration_count=len(r.integration_results) if r.integration_results else 0,
                        has_poc=bool(r.proof_of_concept),
                        is_duplicate=r.is_duplicate,
                        is_false_positive=r.is_false_positive
                    )
                    for r in reports
                ]
                
                # Calculate pagination
                total_pages = (total + request.page_size - 1) // request.page_size
                
                return ReportListResponse(
                    reports=report_summaries,
                    total=total,
                    page=request.page,
                    page_size=request.page_size,
                    total_pages=total_pages,
                    has_next=request.page < total_pages,
                    has_prev=request.page > 1
                )
                
        except Exception as e:
            logger.error(f"Error listing reports: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/api/analytics", response_model=AnalyticsSummary, tags=["API"])
    async def get_analytics(request: AnalyticsRequest):
        """Get analytics data for specified time range."""
        try:
            from bountybot.database import ReportRepository, session_scope
            from bountybot.analytics import TrendAnalyzer

            with session_scope() as session:
                repo = ReportRepository(session)

                # Calculate time range
                now = datetime.now()
                if request.time_range == TimeRange.HOUR:
                    start_date = now - timedelta(hours=1)
                elif request.time_range == TimeRange.DAY:
                    start_date = now - timedelta(days=1)
                elif request.time_range == TimeRange.WEEK:
                    start_date = now - timedelta(days=7)
                elif request.time_range == TimeRange.MONTH:
                    start_date = now - timedelta(days=30)
                elif request.time_range == TimeRange.QUARTER:
                    start_date = now - timedelta(days=90)
                elif request.time_range == TimeRange.YEAR:
                    start_date = now - timedelta(days=365)
                else:
                    start_date = None

                # Get reports in time range
                reports = repo.get_reports_by_date_range(start_date, now) if start_date else repo.get_all_reports()

                # Calculate statistics
                total_reports = len(reports)
                valid_reports = sum(1 for r in reports if r.verdict == 'VALID')
                invalid_reports = sum(1 for r in reports if r.verdict == 'INVALID')
                uncertain_reports = sum(1 for r in reports if r.verdict == 'UNCERTAIN')
                duplicate_reports = sum(1 for r in reports if r.is_duplicate)
                false_positive_reports = sum(1 for r in reports if r.is_false_positive)

                # Calculate averages
                confidences = [r.confidence for r in reports if r.confidence]
                processing_times = [r.processing_time for r in reports if r.processing_time]
                costs = [r.cost for r in reports if r.cost]

                avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
                avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0.0
                total_cost = sum(costs)
                avg_cost = total_cost / len(reports) if reports else 0.0

                # Severity distribution
                severity_dist = {}
                for r in reports:
                    if r.severity:
                        severity_dist[r.severity] = severity_dist.get(r.severity, 0) + 1

                # Vulnerability type distribution
                vuln_dist = {}
                for r in reports:
                    if r.vulnerability_type:
                        vuln_dist[r.vulnerability_type] = vuln_dist.get(r.vulnerability_type, 0) + 1

                # Verdict trend (time series)
                verdict_trend = []
                if request.include_trends:
                    # Group by time period
                    trend_analyzer = TrendAnalyzer()
                    verdict_trend = trend_analyzer.get_verdict_trend(reports, request.group_by or 'day')

                # Top researchers
                top_researchers = []
                if request.include_researchers:
                    researcher_stats = {}
                    for r in reports:
                        if r.researcher_name:
                            if r.researcher_name not in researcher_stats:
                                researcher_stats[r.researcher_name] = {
                                    'name': r.researcher_name,
                                    'total': 0,
                                    'valid': 0,
                                    'invalid': 0
                                }
                            researcher_stats[r.researcher_name]['total'] += 1
                            if r.verdict == 'VALID':
                                researcher_stats[r.researcher_name]['valid'] += 1
                            elif r.verdict == 'INVALID':
                                researcher_stats[r.researcher_name]['invalid'] += 1

                    # Sort by valid reports
                    top_researchers = sorted(
                        researcher_stats.values(),
                        key=lambda x: x['valid'],
                        reverse=True
                    )[:10]

                # Processing metrics
                processing_metrics = {
                    'min_time': min(processing_times) if processing_times else 0.0,
                    'max_time': max(processing_times) if processing_times else 0.0,
                    'median_time': sorted(processing_times)[len(processing_times)//2] if processing_times else 0.0,
                    'total_time': sum(processing_times)
                }

                return AnalyticsSummary(
                    time_range=request.time_range,
                    total_reports=total_reports,
                    valid_reports=valid_reports,
                    invalid_reports=invalid_reports,
                    uncertain_reports=uncertain_reports,
                    duplicate_reports=duplicate_reports,
                    false_positive_reports=false_positive_reports,
                    average_confidence=avg_confidence,
                    average_processing_time=avg_processing_time,
                    total_cost=total_cost,
                    average_cost_per_report=avg_cost,
                    severity_distribution=severity_dist,
                    vulnerability_distribution=vuln_dist,
                    verdict_trend=verdict_trend,
                    top_researchers=top_researchers,
                    processing_metrics=processing_metrics
                )

        except Exception as e:
            logger.error(f"Error fetching analytics: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/integrations/status", response_model=List[IntegrationStatus], tags=["API"])
    async def get_integration_status():
        """Get status of all integrations."""
        try:
            from bountybot.integrations import IntegrationManager
            from bountybot.config_loader import ConfigLoader

            config = ConfigLoader.load_config()
            integration_manager = IntegrationManager(config)

            statuses = []
            for name, integration in integration_manager.integrations.items():
                # Test connection
                try:
                    is_healthy = integration.test_connection()
                    status = IntegrationStatusEnum.HEALTHY if is_healthy else IntegrationStatusEnum.DOWN
                except Exception as e:
                    status = IntegrationStatusEnum.DOWN
                    logger.error(f"Integration {name} health check failed: {e}")

                # Get statistics
                stats = integration_manager.get_integration_stats(name)

                statuses.append(IntegrationStatus(
                    integration_name=name,
                    integration_type=integration.config.type.value,
                    status=status,
                    enabled=integration.config.enabled,
                    last_success=stats.get('last_success'),
                    last_failure=stats.get('last_failure'),
                    success_count=stats.get('success_count', 0),
                    failure_count=stats.get('failure_count', 0),
                    success_rate=stats.get('success_rate', 0.0),
                    average_response_time=stats.get('avg_response_time'),
                    error_message=stats.get('last_error')
                ))

            return statuses

        except Exception as e:
            logger.error(f"Error fetching integration status: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/webhooks/list", response_model=List[WebhookSummary], tags=["API"])
    async def list_webhooks(status: Optional[str] = None):
        """List all webhooks."""
        try:
            from bountybot.webhooks import WebhookManager

            webhook_manager = WebhookManager()
            webhooks = webhook_manager.list_webhooks(status=status)

            summaries = []
            for webhook in webhooks:
                summaries.append(WebhookSummary(
                    webhook_id=webhook.id,
                    url=webhook.url,
                    events=webhook.events,
                    status=webhook.status,
                    description=webhook.description,
                    created_at=webhook.created_at,
                    last_triggered=webhook.last_triggered,
                    success_count=webhook.success_count,
                    failure_count=webhook.failure_count,
                    success_rate=webhook.success_rate
                ))

            return summaries

        except Exception as e:
            logger.error(f"Error listing webhooks: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/system/health", response_model=SystemHealth, tags=["API"])
    async def get_system_health():
        """Get overall system health status."""
        try:
            from bountybot.database import DatabaseSession, health_check
            from bountybot.ai_providers import AnthropicProvider
            from bountybot import __version__

            uptime = time.time() - app.state.start_time

            # Check database
            db_health = {"status": "unknown", "message": ""}
            try:
                db_session = DatabaseSession()
                if db_session.health_check():
                    db_health = {"status": "healthy", "message": "Connected"}
                else:
                    db_health = {"status": "down", "message": "Connection failed"}
            except Exception as e:
                db_health = {"status": "down", "message": str(e)}

            # Check AI provider
            ai_health = {"status": "unknown", "message": ""}
            try:
                ai_provider = AnthropicProvider()
                ai_health = {"status": "healthy", "message": "Available"}
            except Exception as e:
                ai_health = {"status": "down", "message": str(e)}

            # Check integrations
            integrations_health = {"status": "unknown", "healthy_count": 0, "total_count": 0}
            try:
                from bountybot.integrations import IntegrationManager
                from bountybot.config_loader import ConfigLoader

                config = ConfigLoader.load_config()
                integration_manager = IntegrationManager(config)

                healthy_count = 0
                total_count = len(integration_manager.integrations)

                for name, integration in integration_manager.integrations.items():
                    try:
                        if integration.test_connection():
                            healthy_count += 1
                    except:
                        pass

                integrations_health = {
                    "status": "healthy" if healthy_count == total_count else "degraded",
                    "healthy_count": healthy_count,
                    "total_count": total_count
                }
            except Exception as e:
                integrations_health = {"status": "down", "message": str(e)}

            # Check webhooks
            webhooks_health = {"status": "unknown", "active_count": 0}
            try:
                from bountybot.webhooks import WebhookManager

                webhook_manager = WebhookManager()
                active_webhooks = webhook_manager.list_webhooks(status='active')
                webhooks_health = {
                    "status": "healthy",
                    "active_count": len(active_webhooks)
                }
            except Exception as e:
                webhooks_health = {"status": "down", "message": str(e)}

            # Determine overall status
            overall_status = "healthy"
            if db_health["status"] == "down" or ai_health["status"] == "down":
                overall_status = "down"
            elif integrations_health["status"] == "degraded":
                overall_status = "degraded"

            return SystemHealth(
                status=overall_status,
                uptime=uptime,
                version=__version__,
                database=db_health,
                ai_provider=ai_health,
                integrations=integrations_health,
                webhooks=webhooks_health,
                average_response_time=0.0,  # Placeholder
                requests_per_minute=0.0,  # Placeholder
                error_rate=0.0  # Placeholder
            )

        except Exception as e:
            logger.error(f"Error fetching system health: {e}")
            raise HTTPException(status_code=500, detail=str(e))

    return app


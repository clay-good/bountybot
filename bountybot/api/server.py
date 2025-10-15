import time
import uuid
import asyncio
import logging
from typing import Optional, List
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status, Request, BackgroundTasks
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from .models import (
    ValidationRequest,
    ValidationResponse,
    BatchValidationRequest,
    BatchValidationResponse,
    HealthResponse,
    MetricsResponse,
    ErrorResponse,
    APIKeyCreate,
    APIKeyResponse,
    QueueStatusResponse,
    ValidationResult
)
from .auth import (
    get_current_user,
    get_optional_user,
    require_admin,
    APIKey,
    api_key_manager,
    RateLimitExceeded
)
from .rate_limiter import rate_limiter
from bountybot.webhooks import WebhookManager, WebhookDispatcher

logger = logging.getLogger(__name__)

# Service start time
START_TIME = time.time()

# Metrics
METRICS = {
    'total_requests': 0,
    'successful_requests': 0,
    'failed_requests': 0,
    'total_response_time': 0.0,
    'total_reports_validated': 0,
    'valid_reports': 0,
    'invalid_reports': 0,
    'duplicate_reports': 0,
    'false_positive_reports': 0,
    'total_ai_cost': 0.0
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for startup/shutdown."""
    # Startup
    logger.info("Starting BountyBot API server...")

    # Initialize components
    try:
        # Import here to avoid circular imports
        from bountybot.database import DatabaseSession
        from bountybot.ai_providers import AnthropicProvider

        # Initialize webhook system
        app.state.webhook_manager = WebhookManager()
        app.state.webhook_dispatcher = WebhookDispatcher(app.state.webhook_manager)
        logger.info("Webhook system initialized")

        # Test database connection
        try:
            db_session = DatabaseSession()
            db_session.health_check()
            logger.info("Database connection successful")
        except Exception as e:
            logger.warning(f"Database not available: {e}")

        # Test AI provider
        try:
            ai_provider = AnthropicProvider()
            logger.info("AI provider initialized")
        except Exception as e:
            logger.warning(f"AI provider not available: {e}")

        logger.info("BountyBot API server started successfully")

    except Exception as e:
        logger.error(f"Startup error: {e}")

    yield

    # Shutdown
    logger.info("Shutting down BountyBot API server...")

    # Cleanup webhook dispatcher
    if hasattr(app.state, 'webhook_dispatcher'):
        try:
            await app.state.webhook_dispatcher.close()
        except Exception as e:
            logger.error(f"Error closing webhook dispatcher: {e}")


def create_app() -> FastAPI:
    """Create and configure FastAPI application."""

    app = FastAPI(
        title="BountyBot API",
        description="Enterprise Bug Bounty Validation API",
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan
    )

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Add GZip middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # Request ID middleware
    @app.middleware("http")
    async def add_request_id(request: Request, call_next):
        """Add request ID to all requests."""
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id

        # Add to response headers
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id

        return response

    # Metrics middleware
    @app.middleware("http")
    async def track_metrics(request: Request, call_next):
        """Track request metrics."""
        start_time = time.time()

        METRICS['total_requests'] += 1

        try:
            response = await call_next(request)

            if response.status_code < 400:
                METRICS['successful_requests'] += 1
            else:
                METRICS['failed_requests'] += 1

            return response

        except Exception as e:
            METRICS['failed_requests'] += 1
            raise

        finally:
            elapsed = time.time() - start_time
            METRICS['total_response_time'] += elapsed

    # Rate limit middleware
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        """Apply rate limiting."""
        # Skip rate limiting for health check and docs
        if request.url.path in ["/health", "/docs", "/redoc", "/openapi.json"]:
            return await call_next(request)

        # Get API key from authorization header
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
            api_key = api_key_manager.verify_key(token)

            if api_key:
                # Check rate limit
                key = f"api_key:{api_key.key_id}"

                try:
                    if not rate_limiter.allow_request(key, api_key.rate_limit):
                        wait_time = rate_limiter.get_wait_time(key, api_key.rate_limit)

                        return JSONResponse(
                            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            content={
                                "error": "RateLimitExceeded",
                                "message": f"Rate limit exceeded: {api_key.rate_limit} requests per minute",
                                "retry_after": int(wait_time) + 1
                            },
                            headers={"Retry-After": str(int(wait_time) + 1)}
                        )
                except Exception as e:
                    logger.error(f"Rate limit error: {e}")

        return await call_next(request)

    # Exception handlers
    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handle HTTP exceptions."""
        error_response = ErrorResponse(
            error=exc.__class__.__name__,
            message=exc.detail,
            request_id=getattr(request.state, 'request_id', None)
        )

        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.model_dump()
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception):
        """Handle general exceptions."""
        logger.error(f"Unhandled exception: {exc}", exc_info=True)

        error_response = ErrorResponse(
            error="InternalServerError",
            message="An internal server error occurred",
            request_id=getattr(request.state, 'request_id', None)
        )

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.model_dump()
        )

    return app


# Create app instance
app = create_app()


@app.get("/", tags=["General"])
async def root():
    """Root endpoint."""
    return {
        "service": "BountyBot API",
        "version": "2.0.0",
        "status": "operational",
        "documentation": "/docs"
    }


@app.get("/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """
    Health check endpoint.

    Returns service health status and component availability.
    """
    uptime = time.time() - START_TIME

    # Check database
    database_connected = False
    try:
        from bountybot.database import DatabaseSession
        db_session = DatabaseSession()
        db_session.health_check()
        database_connected = True
    except Exception as e:
        logger.warning(f"Database health check failed: {e}")

    # Check AI provider
    ai_provider_available = False
    try:
        from bountybot.ai_providers import AnthropicProvider
        # Simple check - just verify we can import
        ai_provider_available = True
    except Exception as e:
        logger.warning(f"AI provider check failed: {e}")

    # Determine overall status
    if database_connected and ai_provider_available:
        overall_status = "healthy"
    elif ai_provider_available:
        overall_status = "degraded"
    else:
        overall_status = "unhealthy"

    return HealthResponse(
        status=overall_status,
        version="2.0.0",
        uptime_seconds=uptime,
        database_connected=database_connected,
        ai_provider_available=ai_provider_available,
        cache_available=True  # Cache is always available (in-memory)
    )


@app.get("/metrics", response_model=MetricsResponse, tags=["General"])
async def get_metrics(api_key: APIKey = Depends(get_current_user)):
    """
    Get API metrics.

    Requires authentication.
    """
    avg_response_time = (
        METRICS['total_response_time'] / METRICS['total_requests']
        if METRICS['total_requests'] > 0
        else 0.0
    )

    cache_hit_rate = 0.0
    try:
        from bountybot.ai_providers import AnthropicProvider
        provider = AnthropicProvider()
        if hasattr(provider, 'cache') and provider.cache:
            stats = provider.cache.get_stats()
            total = stats['hits'] + stats['misses']
            cache_hit_rate = stats['hits'] / total if total > 0 else 0.0
    except Exception:
        pass

    return MetricsResponse(
        total_requests=METRICS['total_requests'],
        successful_requests=METRICS['successful_requests'],
        failed_requests=METRICS['failed_requests'],
        average_response_time=avg_response_time,
        total_reports_validated=METRICS['total_reports_validated'],
        valid_reports=METRICS['valid_reports'],
        invalid_reports=METRICS['invalid_reports'],
        duplicate_reports=METRICS['duplicate_reports'],
        false_positive_reports=METRICS['false_positive_reports'],
        total_ai_cost=METRICS['total_ai_cost'],
        cache_hit_rate=cache_hit_rate
    )


@app.post("/validate", response_model=ValidationResponse, tags=["Validation"])
async def validate_report(
    request: ValidationRequest,
    background_tasks: BackgroundTasks,
    api_key: APIKey = Depends(get_current_user),
    req: Request = None
):
    """
    Validate a single vulnerability report.

    Performs comprehensive validation including:
    - AI-powered analysis
    - CVSS scoring
    - Duplicate detection
    - False positive detection
    - Exploit complexity analysis
    - Attack chain detection
    - Priority scoring

    Returns validation result with confidence score and recommendations.
    """
    request_id = getattr(req.state, 'request_id', str(uuid.uuid4()))
    start_time = time.time()

    # Dispatch validation.started webhook
    if hasattr(req.app.state, 'webhook_dispatcher'):
        background_tasks.add_task(
            req.app.state.webhook_dispatcher.dispatch_event,
            "validation.started",
            {
                "request_id": request_id,
                "report": request.report.model_dump()
            }
        )

    try:
        # Import orchestrator
        from bountybot.orchestrator import ValidationOrchestrator
        from bountybot.models import Report

        # Convert API model to internal model
        report = Report(
            title=request.report.title,
            description=request.report.description,
            vulnerability_type=request.report.vulnerability_type,
            severity=request.report.severity,
            affected_url=request.report.affected_url,
            steps_to_reproduce=request.report.steps_to_reproduce,
            proof_of_concept=request.report.proof_of_concept,
            impact=request.report.impact,
            researcher_id=request.report.researcher_id,
            researcher_username=request.report.researcher_username,
            external_id=request.report.external_id,
            metadata=request.report.metadata or {}
        )

        # Create orchestrator
        orchestrator = ValidationOrchestrator()

        # Run validation
        result = orchestrator.validate(
            report=report,
            enable_code_analysis=request.options.enable_code_analysis if request.options else False,
            codebase_path=request.options.codebase_path if request.options else None,
            enable_dynamic_testing=request.options.enable_dynamic_testing if request.options else False,
            target_url=request.options.target_url if request.options else None
        )

        # Update metrics
        METRICS['total_reports_validated'] += 1
        if result.verdict == 'VALID':
            METRICS['valid_reports'] += 1
        elif result.verdict == 'INVALID':
            METRICS['invalid_reports'] += 1

        if hasattr(result, 'duplicate_check') and result.duplicate_check and result.duplicate_check.is_duplicate:
            METRICS['duplicate_reports'] += 1

        if hasattr(result, 'fp_detection') and result.fp_detection and result.fp_detection.is_likely_fp:
            METRICS['false_positive_reports'] += 1

        if hasattr(result, 'ai_cost'):
            METRICS['total_ai_cost'] += result.ai_cost

        # Convert result to API model
        processing_time = time.time() - start_time

        validation_result = ValidationResult(
            verdict=result.verdict,
            confidence=result.confidence,
            severity=result.severity if hasattr(result, 'severity') else None,
            cvss_score=result.cvss_score.base_score if hasattr(result, 'cvss_score') and result.cvss_score else None,
            cvss_vector=result.cvss_score.vector_string if hasattr(result, 'cvss_score') and result.cvss_score else None,
            priority_score=result.priority_score.overall_score if hasattr(result, 'priority_score') and result.priority_score else None,
            priority_level=result.priority_score.priority_level if hasattr(result, 'priority_score') and result.priority_score else None,
            is_duplicate=result.duplicate_check.is_duplicate if hasattr(result, 'duplicate_check') and result.duplicate_check else False,
            is_false_positive=result.fp_detection.is_likely_fp if hasattr(result, 'fp_detection') and result.fp_detection else False,
            fp_confidence=result.fp_detection.confidence if hasattr(result, 'fp_detection') and result.fp_detection else None,
            exploit_complexity=result.complexity_analysis.complexity_score if hasattr(result, 'complexity_analysis') and result.complexity_analysis else None,
            has_attack_chain=result.attack_chain.is_chain if hasattr(result, 'attack_chain') and result.attack_chain else False,
            findings=result.findings if hasattr(result, 'findings') else [],
            recommendations=result.recommendations if hasattr(result, 'recommendations') else [],
            reasoning=result.reasoning if hasattr(result, 'reasoning') else None,
            processing_time=processing_time,
            ai_cost=result.ai_cost if hasattr(result, 'ai_cost') else None
        )

        # Send webhook if configured
        if request.webhook_url:
            background_tasks.add_task(send_webhook, request.webhook_url, request_id, validation_result)

        # Dispatch validation.completed webhook
        if hasattr(req.app.state, 'webhook_dispatcher'):
            background_tasks.add_task(
                req.app.state.webhook_dispatcher.dispatch_event,
                "validation.completed",
                {
                    "request_id": request_id,
                    "report": request.report.model_dump(),
                    "result": validation_result.model_dump()
                }
            )

        # Dispatch critical_issue.found webhook if critical
        if validation_result.severity == "CRITICAL":
            if hasattr(req.app.state, 'webhook_dispatcher'):
                background_tasks.add_task(
                    req.app.state.webhook_dispatcher.dispatch_event,
                    "critical_issue.found",
                    {
                        "request_id": request_id,
                        "report": request.report.model_dump(),
                        "result": validation_result.model_dump()
                    }
                )

        return ValidationResponse(
            request_id=request_id,
            status="completed",
            result=validation_result
        )

    except Exception as e:
        logger.error(f"Validation error: {e}", exc_info=True)

        # Dispatch validation.failed webhook
        if hasattr(req.app.state, 'webhook_dispatcher'):
            background_tasks.add_task(
                req.app.state.webhook_dispatcher.dispatch_event,
                "validation.failed",
                {
                    "request_id": request_id,
                    "report": request.report.model_dump(),
                    "error": str(e)
                }
            )

        return ValidationResponse(
            request_id=request_id,
            status="failed",
            error=str(e)
        )


async def send_webhook(url: str, request_id: str, result: ValidationResult):
    """Send webhook notification."""
    try:
        import httpx

        payload = {
            "event_type": "validation.completed",
            "request_id": request_id,
            "result": result.dict(),
            "timestamp": datetime.utcnow().isoformat()
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(url, json=payload, timeout=10.0)
            response.raise_for_status()

        logger.info(f"Webhook sent successfully to {url}")

    except Exception as e:
        logger.error(f"Webhook error: {e}")


@app.post("/validate/batch", response_model=BatchValidationResponse, tags=["Validation"])
async def validate_batch(
    request: BatchValidationRequest,
    background_tasks: BackgroundTasks,
    api_key: APIKey = Depends(get_current_user)
):
    """
    Validate multiple vulnerability reports in batch.

    Maximum 100 reports per batch.
    Processing is done in parallel for efficiency.
    """
    batch_id = f"batch_{uuid.uuid4().hex[:16]}"

    try:
        from bountybot.batch_processor import BatchProcessor
        from bountybot.models import Report

        # Convert API models to internal models
        reports = []
        for report_input in request.reports:
            report = Report(
                title=report_input.title,
                description=report_input.description,
                vulnerability_type=report_input.vulnerability_type,
                severity=report_input.severity,
                affected_url=report_input.affected_url,
                steps_to_reproduce=report_input.steps_to_reproduce,
                proof_of_concept=report_input.proof_of_concept,
                impact=report_input.impact,
                researcher_id=report_input.researcher_id,
                researcher_username=report_input.researcher_username,
                external_id=report_input.external_id,
                metadata=report_input.metadata or {}
            )
            reports.append(report)

        # Create batch processor
        processor = BatchProcessor()

        # Process batch
        results = processor.process_batch(reports)

        # Convert results to API models
        validation_responses = []
        completed = 0
        failed = 0

        for i, result in enumerate(results):
            request_id = f"{batch_id}_{i}"

            if result:
                validation_result = ValidationResult(
                    verdict=result.verdict,
                    confidence=result.confidence,
                    severity=result.severity if hasattr(result, 'severity') else None,
                    cvss_score=result.cvss_score.base_score if hasattr(result, 'cvss_score') and result.cvss_score else None,
                    priority_score=result.priority_score.overall_score if hasattr(result, 'priority_score') and result.priority_score else None,
                    priority_level=result.priority_score.priority_level if hasattr(result, 'priority_score') and result.priority_score else None,
                    is_duplicate=result.duplicate_check.is_duplicate if hasattr(result, 'duplicate_check') and result.duplicate_check else False,
                    is_false_positive=result.fp_detection.is_likely_fp if hasattr(result, 'fp_detection') and result.fp_detection else False,
                    findings=result.findings if hasattr(result, 'findings') else [],
                    recommendations=result.recommendations if hasattr(result, 'recommendations') else []
                )

                validation_responses.append(ValidationResponse(
                    request_id=request_id,
                    status="completed",
                    result=validation_result
                ))
                completed += 1
            else:
                validation_responses.append(ValidationResponse(
                    request_id=request_id,
                    status="failed",
                    error="Validation failed"
                ))
                failed += 1

        return BatchValidationResponse(
            batch_id=batch_id,
            status="completed",
            total_reports=len(reports),
            completed=completed,
            failed=failed,
            results=validation_responses
        )

    except Exception as e:
        logger.error(f"Batch validation error: {e}", exc_info=True)

        return BatchValidationResponse(
            batch_id=batch_id,
            status="failed",
            total_reports=len(request.reports),
            completed=0,
            failed=len(request.reports),
            results=[]
        )


@app.post("/admin/keys", response_model=APIKeyResponse, tags=["Admin"])
async def create_api_key(
    request: APIKeyCreate,
    api_key: APIKey = Depends(require_admin)
):
    """
    Create a new API key.

    Requires admin privileges.
    """
    try:
        raw_key, new_key = api_key_manager.create_key(
            name=request.name,
            description=request.description,
            rate_limit=request.rate_limit or 60,
            expires_at=request.expires_at
        )

        return APIKeyResponse(
            key_id=new_key.key_id,
            name=new_key.name,
            key=raw_key,  # Only shown once
            rate_limit=new_key.rate_limit,
            created_at=new_key.created_at,
            expires_at=new_key.expires_at
        )

    except Exception as e:
        logger.error(f"API key creation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create API key"
        )


@app.delete("/admin/keys/{key_id}", tags=["Admin"])
async def revoke_api_key(
    key_id: str,
    api_key: APIKey = Depends(require_admin)
):
    """
    Revoke an API key.

    Requires admin privileges.
    """
    if api_key_manager.revoke_key(key_id):
        return {"message": f"API key {key_id} revoked successfully"}
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key {key_id} not found"
        )


@app.get("/admin/keys", tags=["Admin"])
async def list_api_keys(api_key: APIKey = Depends(require_admin)):
    """
    List all API keys.

    Requires admin privileges.
    """
    keys = api_key_manager.list_keys()

    return {
        "keys": [
            {
                "key_id": k.key_id,
                "name": k.name,
                "rate_limit": k.rate_limit,
                "is_active": k.is_active,
                "created_at": k.created_at.isoformat(),
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
                "last_used": k.last_used.isoformat() if k.last_used else None,
                "request_count": k.request_count
            }
            for k in keys
        ]
    }


    # Webhook endpoints
    @app.post("/webhooks", response_model=dict, tags=["Webhooks"])
    async def create_webhook(
        webhook_data: dict,
        request: Request,
        api_key: APIKey = Depends(require_admin)
    ):
        """Create a new webhook."""
        from bountybot.api.models import WebhookCreate, WebhookResponse

        webhook_create = WebhookCreate(**webhook_data)
        webhook_manager = request.app.state.webhook_manager

        webhook = webhook_manager.create_webhook(
            url=webhook_create.url,
            events=webhook_create.events,
            description=webhook_create.description,
            headers=webhook_create.headers
        )

        return webhook.to_dict()

    @app.get("/webhooks", response_model=List[dict], tags=["Webhooks"])
    async def list_webhooks(
        request: Request,
        status: Optional[str] = None,
        event: Optional[str] = None,
        api_key: APIKey = Depends(require_admin)
    ):
        """List all webhooks."""
        webhook_manager = request.app.state.webhook_manager
        webhooks = webhook_manager.list_webhooks(status=status, event=event)
        return [w.to_dict() for w in webhooks]

    @app.get("/webhooks/{webhook_id}", response_model=dict, tags=["Webhooks"])
    async def get_webhook(
        webhook_id: str,
        request: Request,
        api_key: APIKey = Depends(require_admin)
    ):
        """Get webhook by ID."""
        webhook_manager = request.app.state.webhook_manager
        webhook = webhook_manager.get_webhook(webhook_id)

        if not webhook:
            raise HTTPException(status_code=404, detail="Webhook not found")

        return webhook.to_dict()

    @app.patch("/webhooks/{webhook_id}", response_model=dict, tags=["Webhooks"])
    async def update_webhook(
        webhook_id: str,
        webhook_data: dict,
        request: Request,
        api_key: APIKey = Depends(require_admin)
    ):
        """Update webhook configuration."""
        from bountybot.api.models import WebhookUpdate

        webhook_update = WebhookUpdate(**webhook_data)
        webhook_manager = request.app.state.webhook_manager

        webhook = webhook_manager.update_webhook(
            webhook_id=webhook_id,
            url=webhook_update.url,
            events=webhook_update.events,
            status=webhook_update.status,
            description=webhook_update.description,
            headers=webhook_update.headers
        )

        if not webhook:
            raise HTTPException(status_code=404, detail="Webhook not found")

        return webhook.to_dict()

    @app.delete("/webhooks/{webhook_id}", tags=["Webhooks"])
    async def delete_webhook(
        webhook_id: str,
        request: Request,
        api_key: APIKey = Depends(require_admin)
    ):
        """Delete webhook."""
        webhook_manager = request.app.state.webhook_manager
        success = webhook_manager.delete_webhook(webhook_id)

        if not success:
            raise HTTPException(status_code=404, detail="Webhook not found")

        return {"message": "Webhook deleted successfully"}

    @app.get("/webhooks/{webhook_id}/deliveries", response_model=List[dict], tags=["Webhooks"])
    async def list_webhook_deliveries(
        webhook_id: str,
        request: Request,
        status: Optional[str] = None,
        limit: int = 100,
        api_key: APIKey = Depends(require_admin)
    ):
        """List webhook deliveries."""
        webhook_manager = request.app.state.webhook_manager
        deliveries = webhook_manager.list_deliveries(
            webhook_id=webhook_id,
            status=status,
            limit=limit
        )
        return [d.to_dict() for d in deliveries]

    @app.post("/webhooks/{webhook_id}/test", tags=["Webhooks"])
    async def test_webhook(
        webhook_id: str,
        request: Request,
        api_key: APIKey = Depends(require_admin)
    ):
        """Send a test event to webhook."""
        webhook_manager = request.app.state.webhook_manager
        webhook_dispatcher = request.app.state.webhook_dispatcher

        webhook = webhook_manager.get_webhook(webhook_id)
        if not webhook:
            raise HTTPException(status_code=404, detail="Webhook not found")

        # Send test event
        test_payload = {
            "test": True,
            "message": "This is a test webhook delivery",
            "timestamp": datetime.utcnow().isoformat()
        }

        await webhook_dispatcher.dispatch_event(
            event_type="test.webhook",
            payload=test_payload
        )

        return {"message": "Test webhook sent"}


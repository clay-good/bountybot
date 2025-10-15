from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, validator


class ReportInput(BaseModel):
    """Input model for a vulnerability report."""
    
    title: str = Field(..., description="Report title", min_length=5, max_length=500)
    description: str = Field(..., description="Detailed vulnerability description", min_length=20)
    vulnerability_type: Optional[str] = Field(None, description="Type of vulnerability (e.g., XSS, SQLi)")
    severity: Optional[str] = Field(None, description="Reported severity (LOW, MEDIUM, HIGH, CRITICAL)")
    affected_url: Optional[str] = Field(None, description="Affected URL or endpoint")
    steps_to_reproduce: Optional[str] = Field(None, description="Steps to reproduce the vulnerability")
    proof_of_concept: Optional[str] = Field(None, description="Proof of concept code or payload")
    impact: Optional[str] = Field(None, description="Business impact description")
    researcher_id: Optional[str] = Field(None, description="Researcher identifier")
    researcher_username: Optional[str] = Field(None, description="Researcher username")
    external_id: Optional[str] = Field(None, description="External platform report ID")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('severity')
    def validate_severity(cls, v):
        """Validate severity level."""
        if v and v.upper() not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'INFO']:
            raise ValueError('Severity must be one of: LOW, MEDIUM, HIGH, CRITICAL, INFO')
        return v.upper() if v else None


class ValidationOptions(BaseModel):
    """Options for validation."""
    
    enable_code_analysis: bool = Field(default=False, description="Enable code analysis")
    enable_dynamic_testing: bool = Field(default=False, description="Enable dynamic testing")
    target_url: Optional[str] = Field(None, description="Target URL for dynamic testing")
    codebase_path: Optional[str] = Field(None, description="Path to codebase for analysis")
    skip_duplicate_check: bool = Field(default=False, description="Skip duplicate detection")
    skip_fp_detection: bool = Field(default=False, description="Skip false positive detection")
    priority_weights: Optional[Dict[str, float]] = Field(None, description="Custom priority weights")


class ValidationRequest(BaseModel):
    """Request model for single report validation."""
    
    report: ReportInput = Field(..., description="Vulnerability report to validate")
    options: Optional[ValidationOptions] = Field(default_factory=ValidationOptions, description="Validation options")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for async notifications")
    
    class Config:
        schema_extra = {
            "example": {
                "report": {
                    "title": "SQL Injection in Login Form",
                    "description": "The login form is vulnerable to SQL injection...",
                    "vulnerability_type": "SQL Injection",
                    "severity": "HIGH",
                    "affected_url": "https://example.com/login",
                    "steps_to_reproduce": "1. Navigate to login page\n2. Enter ' OR '1'='1 in username",
                    "proof_of_concept": "username: ' OR '1'='1 --\npassword: anything",
                    "researcher_id": "researcher_123"
                },
                "options": {
                    "enable_code_analysis": False,
                    "skip_duplicate_check": False
                }
            }
        }


class ValidationResult(BaseModel):
    """Validation result model."""
    
    verdict: str = Field(..., description="Validation verdict (VALID, INVALID, UNCERTAIN)")
    confidence: float = Field(..., description="Confidence score (0-100)")
    severity: Optional[str] = Field(None, description="Assessed severity")
    cvss_score: Optional[float] = Field(None, description="CVSS base score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector string")
    priority_score: Optional[float] = Field(None, description="Priority score (0-100)")
    priority_level: Optional[str] = Field(None, description="Priority level (P0-P4)")
    is_duplicate: bool = Field(default=False, description="Whether report is a duplicate")
    is_false_positive: bool = Field(default=False, description="Whether report is likely a false positive")
    fp_confidence: Optional[float] = Field(None, description="False positive confidence (0-100)")
    exploit_complexity: Optional[float] = Field(None, description="Exploit complexity score (0-100)")
    has_attack_chain: bool = Field(default=False, description="Whether attack chain was detected")
    findings: List[str] = Field(default_factory=list, description="Key findings")
    recommendations: List[str] = Field(default_factory=list, description="Remediation recommendations")
    reasoning: Optional[str] = Field(None, description="Detailed reasoning")
    processing_time: Optional[float] = Field(None, description="Processing time in seconds")
    ai_cost: Optional[float] = Field(None, description="AI API cost in USD")


class ValidationResponse(BaseModel):
    """Response model for single report validation."""
    
    request_id: str = Field(..., description="Unique request identifier")
    status: str = Field(..., description="Request status (completed, failed, pending)")
    result: Optional[ValidationResult] = Field(None, description="Validation result")
    error: Optional[str] = Field(None, description="Error message if failed")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Response timestamp")

    class Config:
        schema_extra = {
            "example": {
                "request_id": "req_abc123",
                "status": "completed",
                "result": {
                    "verdict": "VALID",
                    "confidence": 85.5,
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "priority_score": 75.0,
                    "priority_level": "P1",
                    "is_duplicate": False,
                    "is_false_positive": False,
                    "findings": ["SQL injection confirmed", "No authentication required"],
                    "recommendations": ["Use parameterized queries", "Implement input validation"]
                },
                "timestamp": "2025-10-15T10:30:00Z"
            }
        }


class BatchValidationRequest(BaseModel):
    """Request model for batch validation."""
    
    reports: List[ReportInput] = Field(..., description="List of reports to validate", max_items=100)
    options: Optional[ValidationOptions] = Field(default_factory=ValidationOptions, description="Validation options")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for async notifications")
    
    @validator('reports')
    def validate_reports_count(cls, v):
        """Validate number of reports."""
        if len(v) > 100:
            raise ValueError('Maximum 100 reports per batch')
        if len(v) == 0:
            raise ValueError('At least one report required')
        return v


class BatchValidationResponse(BaseModel):
    """Response model for batch validation."""
    
    batch_id: str = Field(..., description="Unique batch identifier")
    status: str = Field(..., description="Batch status (completed, processing, failed)")
    total_reports: int = Field(..., description="Total number of reports")
    completed: int = Field(default=0, description="Number of completed validations")
    failed: int = Field(default=0, description="Number of failed validations")
    results: List[ValidationResponse] = Field(default_factory=list, description="Validation results")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")


class HealthResponse(BaseModel):
    """Health check response."""
    
    status: str = Field(..., description="Service status (healthy, degraded, unhealthy)")
    version: str = Field(..., description="API version")
    uptime_seconds: float = Field(..., description="Service uptime in seconds")
    database_connected: bool = Field(..., description="Database connection status")
    ai_provider_available: bool = Field(..., description="AI provider availability")
    cache_available: bool = Field(..., description="Cache availability")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")


class MetricsResponse(BaseModel):
    """Metrics response."""
    
    total_requests: int = Field(..., description="Total API requests")
    successful_requests: int = Field(..., description="Successful requests")
    failed_requests: int = Field(..., description="Failed requests")
    average_response_time: float = Field(..., description="Average response time in seconds")
    total_reports_validated: int = Field(..., description="Total reports validated")
    valid_reports: int = Field(..., description="Valid reports")
    invalid_reports: int = Field(..., description="Invalid reports")
    duplicate_reports: int = Field(..., description="Duplicate reports")
    false_positive_reports: int = Field(..., description="False positive reports")
    total_ai_cost: float = Field(..., description="Total AI cost in USD")
    cache_hit_rate: float = Field(..., description="Cache hit rate (0-1)")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Metrics timestamp")


class WebhookPayload(BaseModel):
    """Webhook notification payload."""
    
    event_type: str = Field(..., description="Event type (validation.completed, validation.failed)")
    request_id: str = Field(..., description="Request identifier")
    batch_id: Optional[str] = Field(None, description="Batch identifier if applicable")
    result: Optional[ValidationResult] = Field(None, description="Validation result")
    error: Optional[str] = Field(None, description="Error message if failed")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Event timestamp")


class ErrorResponse(BaseModel):
    """Error response model."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional error details")
    request_id: Optional[str] = Field(None, description="Request identifier")
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat(), description="Error timestamp")
    
    class Config:
        schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid report format",
                "details": {"field": "title", "issue": "Title too short"},
                "request_id": "req_abc123",
                "timestamp": "2025-10-15T10:30:00Z"
            }
        }


class APIKeyCreate(BaseModel):
    """API key creation request."""
    
    name: str = Field(..., description="API key name", min_length=3, max_length=100)
    description: Optional[str] = Field(None, description="API key description")
    rate_limit: Optional[int] = Field(60, description="Requests per minute limit")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class APIKeyResponse(BaseModel):
    """API key response."""
    
    key_id: str = Field(..., description="API key identifier")
    name: str = Field(..., description="API key name")
    key: str = Field(..., description="API key (only shown once)")
    rate_limit: int = Field(..., description="Requests per minute limit")
    created_at: datetime = Field(..., description="Creation timestamp")
    expires_at: Optional[datetime] = Field(None, description="Expiration timestamp")


class QueueStatusResponse(BaseModel):
    """Queue status response."""

    queue_length: int = Field(..., description="Number of items in queue")
    processing: int = Field(..., description="Number of items being processed")
    completed_today: int = Field(..., description="Items completed today")
    average_wait_time: float = Field(..., description="Average wait time in seconds")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")


class WebhookCreate(BaseModel):
    """Webhook creation request."""

    url: str = Field(..., description="Webhook URL", min_length=10)
    events: List[str] = Field(..., description="List of event types to subscribe to")
    description: Optional[str] = Field(None, description="Webhook description")
    headers: Optional[Dict[str, str]] = Field(None, description="Custom headers")


class WebhookResponse(BaseModel):
    """Webhook response."""

    webhook_id: str = Field(..., description="Webhook ID")
    url: str = Field(..., description="Webhook URL")
    events: List[str] = Field(..., description="Subscribed events")
    status: str = Field(..., description="Webhook status")
    description: Optional[str] = Field(None, description="Webhook description")
    secret: str = Field(..., description="Webhook secret for signature verification")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")
    delivery_count: int = Field(..., description="Total deliveries")
    failure_count: int = Field(..., description="Failed deliveries")


class WebhookUpdate(BaseModel):
    """Webhook update request."""

    url: Optional[str] = Field(None, description="New webhook URL")
    events: Optional[List[str]] = Field(None, description="New event list")
    status: Optional[str] = Field(None, description="New status")
    description: Optional[str] = Field(None, description="New description")
    headers: Optional[Dict[str, str]] = Field(None, description="New headers")


class WebhookDeliveryResponse(BaseModel):
    """Webhook delivery response."""

    delivery_id: str = Field(..., description="Delivery ID")
    webhook_id: str = Field(..., description="Webhook ID")
    event_type: str = Field(..., description="Event type")
    status: str = Field(..., description="Delivery status")
    response_code: Optional[int] = Field(None, description="HTTP response code")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    attempt_count: int = Field(..., description="Number of attempts")
    created_at: str = Field(..., description="Creation timestamp")
    delivered_at: Optional[str] = Field(None, description="Delivery timestamp")

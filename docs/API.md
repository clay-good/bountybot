# BountyBot API Reference

## Base URL
```
http://localhost:8000
```

## Authentication

All API requests require authentication using JWT tokens or API keys.

### Headers
```http
Authorization: Bearer <token>
Content-Type: application/json
```

## Endpoints

### Health Check

#### GET /health
Check service health status.

**Response:**
```json
{
  "status": "healthy",
  "version": "2.18.0",
  "database_connected": true,
  "ai_provider_available": true,
  "timestamp": "2024-01-15T10:30:00Z"
}
```

### Validation

#### POST /validate
Validate a single vulnerability report.

**Request:**
```json
{
  "title": "SQL Injection in /api/users",
  "description": "The user ID parameter is not sanitized...",
  "severity": "high",
  "vulnerability_type": "sql_injection",
  "affected_endpoint": "/api/users",
  "poc": "curl -X POST http://example.com/api/users -d \"id=' OR '1'='1\"",
  "steps_to_reproduce": [
    "Navigate to /api/users",
    "Submit malicious payload",
    "Observe SQL error"
  ],
  "impact": "Unauthorized data access",
  "cve_id": "CVE-2024-1234",
  "cvss_score": 8.5
}
```

**Response:**
```json
{
  "report_id": "rpt_abc123",
  "verdict": "VALID",
  "confidence": 0.92,
  "severity": "high",
  "cvss_score": 8.5,
  "approved": true,
  "payout_amount": 750,
  "validation_details": {
    "code_analysis": {
      "vulnerable_code_found": true,
      "file_path": "api/users.py",
      "line_number": 42,
      "confidence": 0.88
    },
    "poc_execution": {
      "vulnerability_confirmed": true,
      "confidence": 0.95,
      "evidence": ["SQL error in response", "Database query exposed"]
    },
    "security_controls": {
      "waf_blocking": false,
      "effectiveness": "INEFFECTIVE"
    },
    "duplicate_check": {
      "is_duplicate": false,
      "similarity_score": 0.0
    }
  },
  "recommendations": [
    "Use parameterized queries",
    "Implement input validation",
    "Deploy WAF rules"
  ],
  "processing_time": 12.5
}
```

#### POST /validate/batch
Validate multiple reports in batch.

**Request:**
```json
{
  "reports": [
    { "title": "...", "description": "..." },
    { "title": "...", "description": "..." }
  ],
  "options": {
    "parallel": true,
    "max_concurrent": 5
  }
}
```

**Response:**
```json
{
  "batch_id": "batch_xyz789",
  "total_reports": 10,
  "completed": 10,
  "results": [
    { "report_id": "rpt_1", "verdict": "VALID", "confidence": 0.92 },
    { "report_id": "rpt_2", "verdict": "INVALID", "confidence": 0.15 }
  ],
  "summary": {
    "valid": 7,
    "invalid": 2,
    "uncertain": 1,
    "total_payout": 5250
  }
}
```

### Reports

#### GET /reports
List all validated reports.

**Query Parameters:**
- `page` (int): Page number (default: 1)
- `limit` (int): Results per page (default: 20)
- `severity` (string): Filter by severity
- `verdict` (string): Filter by verdict
- `researcher_id` (string): Filter by researcher

**Response:**
```json
{
  "reports": [
    {
      "report_id": "rpt_abc123",
      "title": "SQL Injection in /api/users",
      "severity": "high",
      "verdict": "VALID",
      "confidence": 0.92,
      "payout_amount": 750,
      "created_at": "2024-01-15T10:30:00Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 150,
    "pages": 8
  }
}
```

#### GET /reports/{report_id}
Get detailed report information.

**Response:**
```json
{
  "report_id": "rpt_abc123",
  "title": "SQL Injection in /api/users",
  "description": "...",
  "severity": "high",
  "verdict": "VALID",
  "confidence": 0.92,
  "validation_details": { ... },
  "timeline": [
    { "event": "submitted", "timestamp": "2024-01-15T10:30:00Z" },
    { "event": "validated", "timestamp": "2024-01-15T10:30:15Z" },
    { "event": "approved", "timestamp": "2024-01-15T10:31:00Z" }
  ]
}
```

### Analytics

#### GET /analytics/metrics
Get validation metrics.

**Query Parameters:**
- `start_date` (string): Start date (ISO 8601)
- `end_date` (string): End date (ISO 8601)
- `granularity` (string): day/week/month

**Response:**
```json
{
  "period": {
    "start": "2024-01-01T00:00:00Z",
    "end": "2024-01-31T23:59:59Z"
  },
  "metrics": {
    "total_reports": 450,
    "valid_reports": 315,
    "invalid_reports": 135,
    "false_positive_rate": 0.12,
    "average_confidence": 0.84,
    "total_payout": 125000,
    "average_validation_time": 8.5
  },
  "by_severity": {
    "critical": 15,
    "high": 120,
    "medium": 180,
    "low": 135
  },
  "by_type": {
    "sql_injection": 45,
    "xss": 78,
    "csrf": 32,
    "other": 160
  }
}
```

#### GET /analytics/trends
Get trend analysis.

**Response:**
```json
{
  "trends": {
    "validation_rate": {
      "current": 0.70,
      "previous": 0.65,
      "change": 0.05,
      "trend": "increasing"
    },
    "false_positive_rate": {
      "current": 0.12,
      "previous": 0.18,
      "change": -0.06,
      "trend": "decreasing"
    }
  }
}
```

### Configuration

#### GET /config
Get current configuration.

**Response:**
```json
{
  "ai_provider": "anthropic",
  "model": "claude-3-5-sonnet-20241022",
  "poc_execution_enabled": true,
  "code_analysis_enabled": true,
  "duplicate_detection_enabled": true,
  "confidence_threshold": 0.7
}
```

#### PUT /config
Update configuration.

**Request:**
```json
{
  "confidence_threshold": 0.75,
  "poc_execution_enabled": false
}
```

## Error Responses

### 400 Bad Request
```json
{
  "error": "validation_error",
  "message": "Invalid report format",
  "details": {
    "field": "severity",
    "issue": "Must be one of: critical, high, medium, low"
  }
}
```

### 401 Unauthorized
```json
{
  "error": "unauthorized",
  "message": "Invalid or missing authentication token"
}
```

### 429 Too Many Requests
```json
{
  "error": "rate_limit_exceeded",
  "message": "Rate limit exceeded",
  "retry_after": 60
}
```

### 500 Internal Server Error
```json
{
  "error": "internal_error",
  "message": "An unexpected error occurred",
  "request_id": "req_xyz789"
}
```

## Rate Limits

- **Free tier**: 100 requests/hour
- **Pro tier**: 1000 requests/hour
- **Enterprise**: Custom limits

## Webhooks

Configure webhooks to receive real-time notifications.

### Events
- `validation.completed`
- `validation.failed`
- `payout.approved`
- `payout.rejected`

### Webhook Payload
```json
{
  "event": "validation.completed",
  "timestamp": "2024-01-15T10:30:00Z",
  "data": {
    "report_id": "rpt_abc123",
    "verdict": "VALID",
    "confidence": 0.92
  }
}
```

## SDK Examples

### Python
```python
from bountybot import BountyBotClient

client = BountyBotClient(api_key="your_api_key")

result = client.validate_report({
    "title": "SQL Injection",
    "description": "...",
    "severity": "high"
})

print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.confidence}")
```

### JavaScript
```javascript
const BountyBot = require('bountybot-sdk');

const client = new BountyBot({ apiKey: 'your_api_key' });

const result = await client.validateReport({
  title: 'SQL Injection',
  description: '...',
  severity: 'high'
});

console.log(`Verdict: ${result.verdict}`);
console.log(`Confidence: ${result.confidence}`);
```

### cURL
```bash
curl -X POST http://localhost:8000/validate \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SQL Injection",
    "description": "...",
    "severity": "high"
  }'
```


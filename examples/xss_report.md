# Cross-Site Scripting (XSS) in Comment Section

## Researcher
jane_security_expert

## Submission Date
2024-01-20

## Vulnerability Type
Cross-Site Scripting (XSS)

## Severity
Medium

## Severity Justification
Stored XSS vulnerability that affects all users viewing the comments section. Can be used to steal session cookies, perform actions on behalf of users, or deface the website.

## Affected Components
- /comments/post
- /comments/view
- CommentController.create()
- comments.html template

## Reproduction Steps
1. Log in to the application
2. Navigate to any blog post with comments enabled
3. In the comment field, enter the following payload: `<script>alert(document.cookie)</script>`
4. Submit the comment
5. Refresh the page or view it from another browser
6. Observe that the JavaScript executes and displays an alert with the session cookie

## Proof of Concept
```html
POST /comments/post HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

comment=<script>alert(document.cookie)</script>&post_id=123
```

## Impact
An attacker can inject malicious JavaScript that executes in the context of other users' browsers. This can be used to:
- Steal session cookies and hijack user accounts
- Perform actions on behalf of authenticated users
- Redirect users to phishing sites
- Deface the website for all visitors
- Install keyloggers or other malicious scripts

## Additional Notes
The application does not sanitize user input before storing it in the database, and does not encode output when rendering comments. Both input validation and output encoding should be implemented.


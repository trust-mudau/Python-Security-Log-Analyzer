# Detection Rules

## Rule 1 — Repeated Failed Login
Trigger when one source IP generates 5 or more failed logins.

### Security Rationale
Repeated authentication failures may indicate mistyped credentials, a stale service account, or an automated password attack.

### False Positives
- User forgot password
- Misconfigured application
- Shared NAT address

### Improvements
- Add time windows
- Add user baselining
- Enrich IPs
- Track device identity

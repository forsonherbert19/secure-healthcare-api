# Secure Healthcare Records API — Threat Model

## System Purpose

This project models a healthcare records API containing synthetic patient information. The security objective is to prevent unauthorized access, maintain accountability, and detect suspicious behavior.

## Assets

Protected assets include:

- Patient records
- User identities
- Authentication credentials
- JWT signing secrets
- Authorization relationships
- Security audit events
- Security alerts

No real protected health information is used.

## Trust Boundaries

Major trust boundaries include:

1. Internet client to AWS load balancer
2. Load balancer to ECS/Fargate container
3. API authentication layer
4. Authorization layer to patient records
5. Application to AWS Secrets Manager
6. Application events to audit and detection systems
7. GitHub repository to CI pipeline
8. Amazon ECR to ECS deployment

## Threats and Controls

| Threat | Security Control |
|---|---|
| Stolen or forged authentication token | Signed JWT with issuer, audience, expiration, `nbf`, `iat`, and `jti` validation |
| Password disclosure | Argon2 password hashing |
| Username timing attacks | Dummy password verification for unknown users |
| Patient accesses another patient's record | Object-level authorization |
| Excessive privileges | Role-based access control |
| BOLA / IDOR | Patient ID authorization checks |
| Repeated unauthorized access | SEC-001 behavioral detection |
| Password guessing | SEC-002 repeated-login detection |
| Log injection | Log-value sanitization |
| Secret exposure in Git | `.env` excluded by `.gitignore` and `.dockerignore` |
| Secret embedded in container image | AWS Secrets Manager injection |
| Container compromise | Application runs as non-root user |
| Vulnerable container packages | Amazon ECR image scanning |
| Code regression | Automated pytest security tests and GitHub Actions CI |
| Unencrypted internet traffic | AWS-managed HTTPS/TLS endpoint |

## Detection Rules

### SEC-001 — RepeatedUnauthorizedRecordAccess

Triggers when a user generates three denied patient-record access attempts within a five-minute window.

Severity: **HIGH**

### SEC-002 — RepeatedFailedLogins

Triggers when the same username generates three failed login attempts within a five-minute window.

Severity: **HIGH**

## Security Logging Principles

The application records security metadata such as:

- Timestamp
- Event type
- Username
- Role
- Outcome
- Patient ID where relevant
- Failure reason

The application intentionally avoids writing passwords, JWTs, diagnoses, medications, or complete patient records into security audit logs.

## Assumptions

- Patient records are synthetic.
- Demo users are intentionally included for portfolio testing.
- The API demonstrates security architecture rather than full hospital functionality.
- AWS IAM permissions should follow least privilege.
- Secrets are supplied at runtime rather than embedded into source code or container images.

## Limitations

This project is not represented as a production healthcare system or as HIPAA compliant.

Production improvements would include:

- Persistent encrypted database storage
- Fine-grained administrative privileges
- MFA
- Token revocation
- API rate limiting
- WAF protections
- Centralized immutable audit storage
- SIEM integration
- KMS-managed encryption
- Automated secret rotation
- More comprehensive integration and penetration testing

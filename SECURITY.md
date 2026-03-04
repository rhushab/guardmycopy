# Security Policy

## Reporting a Vulnerability

Please report vulnerabilities privately by opening a security advisory in the repository (preferred) or contacting maintainers directly.

When reporting:
- Include reproduction steps and impact.
- Include affected version/tag.
- Share minimal proof-of-concept data.

Do **not** include real secrets, private keys, tokens, credentials, or raw sensitive clipboard content in reports.
Use synthetic examples.

## Security Posture Notes

- clipguard is macOS-only.
- clipguard is local-only and should not perform network calls.
- Optional audit logs must remain hash+metadata only (no raw clipboard text).

## Scope Limitations

clipguard helps reduce accidental clipboard leaks but is not a complete endpoint security product.
Compromise of the host system or user account can bypass clipboard safeguards.

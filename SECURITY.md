# Security policy

## Supported versions

Security fixes are applied to the latest maintained Sentinel release. The published release page identifies supported versions.

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability reporting for `sablectl/sentinel`. Do not include real security logs, access tokens, database files or other sensitive material in a public issue.

Please provide the affected version, a concise description, impact and safe reproduction details. Sentinel is a defensive local tool; reports must not involve testing against systems without permission.

## Security boundaries

Sentinel treats imported records as untrusted input. The dashboard is authenticated, uses strict Host/Origin checks, binds to loopback by default and stores state locally. Remote binding is an explicit operator choice and requires a token; plain HTTP should not be exposed to untrusted networks.

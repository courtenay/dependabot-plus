# Security Policy

## Supported Versions

Only the latest release is supported with security updates.

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

Please report vulnerabilities through [GitHub's private vulnerability reporting](https://github.com/courtenay/dependabot-plus/security/advisories/new).

You should receive an acknowledgement within 48 hours. We will work with you to understand the issue and coordinate a fix before any public disclosure.

## Scope

This tool runs untrusted code inside Docker containers with `--network=none`. If you find a sandbox escape, container breakout, or a way to exfiltrate real secrets (not canary tokens), that is in scope.

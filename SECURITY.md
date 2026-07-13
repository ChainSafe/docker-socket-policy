# Security Policy

## Reporting a Vulnerability

This project enforces Docker API security via policy-based access control.
If you discover a security vulnerability that could bypass these controls,
please report it responsibly.

**Do not open a public GitHub issue.** Instead, email the ChainSafe security
team at **security@chainsafe.io** with details about the vulnerability.

Please include:
- A description of the issue
- Steps to reproduce
- Affected versions
- Potential impact

You should receive a response within 48 hours. If you do not, please follow up.

## Scope

The following areas are in scope:
- Policy bypass vulnerabilities (exec, privileged, image, volume, env, flag)
- Default-deny router bypass
- Audit log tampering or bypass
- Transport layer vulnerabilities

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| Latest  | :white_check_mark: |

## Disclosure Policy

We follow a coordinated disclosure process:
1. Receive and acknowledge report
2. Investigate and develop a fix
3. Release a patched version
4. Public disclosure after patch release

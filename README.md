# External Security Assessment - Case Study (Passive OSINT, Anonymized)

![type](https://img.shields.io/badge/type-case%20study-blue)
![method](https://img.shields.io/badge/method-passive%20OSINT-green)
![exploitation](https://img.shields.io/badge/exploitation-none-brightgreen)
![disclosure](https://img.shields.io/badge/disclosure-responsible-purple)

An **anonymized write-up of a real, good-faith external assessment** of a distributed multi-campus university's public web presence, performed using **only passive techniques**: public DNS, certificate transparency, and HTTP banner inspection.

> **No active scanning, no exploitation, no authentication, no system access.** Institution names, campuses, hostnames, and IPs are replaced with generic placeholders so the organization cannot be identified. Findings were **responsibly disclosed** (via the national CERT and, where possible, the operator) before this anonymized version was published.

## What it demonstrates
- A disciplined **passive** external methodology (DNS -> banners -> CVE correlation -> scoring).
- **Honest caveats:** banner-inferred versions are potential (backporting), not confirmed; CVE matches are hypotheses, not proof.
- Responsible disclosure through the correct channel (national CERT / operator), identifying oneself, sharing only public data.
- Clear, CVSS-justified findings and a prioritized remediation roadmap.

## Contents
```
README.md                 - this overview
SECURITY_AUDIT_REPORT.md  - the full anonymized report
LICENSE                   - MIT
```

## Findings (anonymized)
| # | Finding | Severity |
|---|---------|:--------:|
| C1 | EOL IIS 6.0 / Win Server 2003 R2 (public RCE CVE match) | Critical (9.8) |
| C2 | EOL Apache 2.2.22 (Optionsbleed match) | High (7.5) |
| H1 | Outdated Apache 2.4.29 | Medium (5.0) |
| H2 | Outdated nginx 1.14.2 | Medium (5.0) |
| M1-M4 | wp-admin exposure, DMARC p=none, expiring certs, WAF (positive) | Low / Info |

## Skills demonstrated
| Domain | Techniques |
|--------|------------|
| OSINT | Certificate transparency (crt.sh), DNS reconnaissance, subdomain discovery |
| Web security | HTTP banner fingerprinting, TLS handshake analysis, CVSS 3.1 scoring |
| Vulnerability research | CVE-to-version matching, EOL-software risk assessment, public-exploit correlation |
| Email security | SPF/DMARC/DKIM audit, domain-spoofing risk analysis |
| Legacy assessment | Windows Server 2003 R2 / IIS 6.0 / Apache 2.2.x risk evaluation |
| Technical writing | CVSS-justified findings, backport-aware caveats, prioritized remediation |

## Standards referenced
OWASP Testing Guide v4 - NIST SP 800-115

## Author
**Axel Feduzka** · GitHub [@dopaminauta](https://github.com/dopaminauta) · dominguezfya@gmail.com

---
*Anonymized portfolio case study. Passive only; no exploitation, no system access, no real identifiers. Responsibly disclosed before publication.*

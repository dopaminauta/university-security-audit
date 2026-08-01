# External Security Assessment - Case Study
## Distributed Multi-Campus University Network (Passive OSINT)

**Report ID:** EXT-AUDIT-CS-002
**Type:** External passive assessment (OSINT + non-intrusive banner/DNS inspection)
**Author:** Axel Feduzka (github.com/dopaminauta)
**Classification:** Public - Anonymized Case Study

> **About this document:** This is an anonymized write-up of a real, good-faith external assessment performed using **only passive techniques** - public DNS queries, certificate-transparency lookups, and inspection of HTTP response banners. **No active scanning, no exploitation, no authentication attempts, and no access to any system occurred.** Institution names, campus locations, hostnames, IP addresses, and other identifiers have been replaced with generic placeholders so the assessed organization cannot be identified. Findings were disclosed responsibly before publication (see Disclosure).

---

## Executive Summary

An external, passive assessment of a distributed multi-campus university's public web presence identified end-of-life server software reachable from the internet. Everything below derives from **publicly observable banners and DNS records** - the assessment never sent an exploit, never authenticated, and never accessed a system.

Summary: **1 critical-severity item** (EOL server matching a public RCE CVE), **1 high**, **2 medium** (outdated-but-supported versions), and **4 lower-severity hardening items** across regional campuses.

> **Methodological honesty - version strings vs. reality:** Findings are based on HTTP banner strings. On Debian/Ubuntu systems, security fixes are frequently backported without changing the banner version. A server advertising `Apache/2.2.22 (Ubuntu)` *may* be patched. These findings therefore flag **potential** exposure warranting the operator's authorized verification - they are not confirmed exploitable vulnerabilities.

---

## 1. Scope & Infrastructure

| Item | Detail |
|------|--------|
| **Domain** | `national-university.example` |
| **Scope** | Central domain + 6 regional campus subdomains |
| **Web Servers** | Apache (various), nginx, IIS |
| **SSL** | Wildcard certificate |
| **Method** | Passive only (dig, crt.sh, curl -sI, openssl s_client) |

---

## 2. Campuses Observed

| Campus | Subdomain | Banner |
|--------|-----------|--------|
| Central | `www.national-university.example` | nginx behind cloud WAF |
| North | `www.north.national-university.example` | IIS/6.0 |
| East | `www.east.national-university.example` | Apache/2.2.22 (Ubuntu) |
| West | `www.west.national-university.example` | Apache/2.4.29 (Ubuntu) |
| South | `www.south.national-university.example` | nginx/1.14.2 |
| Central-West | `www.centralwest.national-university.example` | Drupal 10 (modern) |
| South-East | `www.southeast.national-university.example` | HSTS preloaded, strict CSP |

---

## 3. Findings

### C1 - End-of-Life IIS 6.0 / Windows Server 2003 R2 (public RCE CVE)

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL (CVSS 9.8) |
| **CWE** | CWE-1104 / CWE-120 |
| **Location** | `www.north.national-university.example` |
| **Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

The North campus banner advertises **IIS/6.0 on Windows Server 2003 R2** - an OS unsupported since 2015. This platform matches **CVE-2017-7269** (unauthenticated WebDAV RCE, public PoC exists). The SSL certificate was also near expiry (~5 days) at observation time.

**Observed via (passive):**
```bash
curl -sI "https://www.north.national-university.example/" | grep -i "^server:"
# Server: Microsoft-IIS/6.0
```
No exploitation was performed - the CVE match is inferred from the banner only.

**Remediation:** migrate off Server 2003/IIS 6.0 to a supported stack; if immediate migration is impossible, remove the host from direct internet exposure; renew the certificate.

---

### C2 - End-of-Life Apache 2.2.22 (branch EOL 2018)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH (CVSS 7.5) |
| **CWE** | CWE-1104 |
| **Location** | `www.east.national-university.example` |

Banner shows **Apache/2.2.22 (Ubuntu)** - a branch EOL since 2018, associated with **CVE-2017-9798 (Optionsbleed)** and **CVE-2017-7679**. *Ubuntu backport caveat applies:* the package may carry backported fixes; the operator should verify via `apt changelog apache2`.

**Remediation:** move to Apache 2.4.x on a supported LTS; verify actual patch level before assuming exposure.

---

### H1 - Outdated Apache 2.4.29

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM (CVSS 5.0) |
| **Location** | `www.west.national-university.example` |

`Apache/2.4.29` (2017) on a still-supported branch, well behind current 2.4.6x. **Remediation:** update to the latest LTS-packaged version.

---

### H2 - Outdated nginx 1.14.2

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM (CVSS 5.0) |
| **Location** | `www.south.national-university.example` |

`nginx/1.14.2`, no longer actively supported; certificate ~63 days from expiry. **Remediation:** upgrade to current stable.

---

### M1 - WordPress Admin Panels Publicly Reachable

| Field | Detail |
|-------|--------|
| **Severity** | LOW (CVSS 3.1) |
| **CWE** | CWE-200 |

Several campus sites expose `/wp-admin/` directly. **Remediation:** restrict by IP/VPN, rate-limit logins, enforce 2FA.

---

### M2 - DMARC Monitor-Only (spoofing risk)

| Field | Detail |
|-------|--------|
| **Severity** | LOW (CVSS 2.0) |

`p=none` allows domain spoofing; no default DKIM selector found. **Remediation:** progress `p=none -> quarantine -> reject`; add DKIM; monitor rua reports.

---

### M3 - Certificates Approaching Expiry

| Campus | Days Remaining |
|--------|:--------------:|
| North | ~5 |
| East | 30 |
| West | 30 |
| South | 60 |

**Remediation:** renew; automate via ACME/certbot.

---

### M4 - Central Behind Cloud WAF (positive)

The central domain sits behind a cloud WAF - a **good** pattern recommended for the other campuses.

---

## 4. Positive Findings

| Campus | Practice |
|--------|----------|
| Central-West | Drupal 10, modern & supported |
| South-East | HSTS preloaded, strict CSP |
| Central | Behind cloud WAF; SPF present |

---

## 5. Methodology

| Phase | Activity | Tools |
|-------|----------|-------|
| OSINT | Subdomain / cert discovery | dig, crt.sh |
| Fingerprinting | Banner + TLS inspection | curl -sI, openssl s_client |
| CVE correlation | Version-to-CVE matching | NVD, MITRE |
| Email posture | SPF/DMARC/DKIM lookup | dig |

**Passive only. No active scanning, no exploits, no automated crawling, no authentication.** Frameworks referenced: OWASP Testing Guide v4, NIST SP 800-115.

> **Why passive-only matters:** without written authorization or an in-scope VDP/bug-bounty program, active scanning of third-party infrastructure is not defensible. This assessment stayed strictly within publicly observable data.

---

## 6. CVE Summary (banner-inferred)

| CVE | Component | CVSS | Status |
|-----|-----------|------|--------|
| CVE-2017-7269 | IIS 6.0 WebDAV RCE | 9.8 | Banner match; public exploit exists; not tested |
| CVE-2017-9798 | Apache 2.2.x Optionsbleed | 7.5 | Banner match; not tested |
| CVE-2017-7679 | Apache 2.2.x (mod_mime) | 7.5 | Banner match; not tested |

> Applicability inferred from banners only. No exploit was run against any host.

---

## 7. Disclosure

Handled as responsible disclosure, good-faith and passive:

- Findings were reported to the **national CERT / CSIRT** as an intermediary and, where a contact was identifiable, **directly to the operator's technical staff**.
- Only publicly observable information was shared; no exploitation was performed.
- This anonymized case study omits all identifying details.

> The reporter identified themselves and offered the full technical detail to the operator. No sensitive data was collected or published.

---

## 8. Limitations

- **Passive, external only** - no internal testing, no active scanning.
- **Banner-based** - real patch levels may differ (backporting).
- **Snapshot** - reflects state at observation time.
- **No exploitation** - CVE applicability inferred, not confirmed.

---

## 9. References

- CVE-2017-7269 - https://nvd.nist.gov/vuln/detail/CVE-2017-7269
- CVE-2017-9798 - https://nvd.nist.gov/vuln/detail/CVE-2017-9798
- OWASP Testing Guide v4 - https://owasp.org/www-project-web-security-testing-guide/
- DMARC - https://dmarc.org/

---

*Anonymized portfolio case study. Passive methodology only; no exploitation, no system access, no real identifiers or sensitive data disclosed. Findings were responsibly disclosed before publication.*

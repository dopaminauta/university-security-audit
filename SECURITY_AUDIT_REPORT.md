# External Security Assessment Report
## National University Network — Case Study

**Date:** July 2026  
**Report ID:** EXT-AUDIT-CS-002  
**Assessment Type:** External Passive Security Audit (OSINT + Non-Intrusive Reconnaissance)  
**Auditor:** Independent Security Researcher  
**Classification:** Public Portfolio — Case Study (fictionalized for confidentiality)

> ⚠️ **Disclaimer:** This report is a fictionalized case study based on an unsolicited good-faith external security assessment. All domain names, IP addresses, institutional names, campus locations, server hostnames, and technical identifiers have been replaced with synthetic placeholders to protect the confidentiality of the assessed organization. This document follows Coordinated Vulnerability Disclosure (CVD) principles as described in *Gray Hat Hacking, 6th Edition*. No real infrastructure details, exploit paths, or sensitive data are disclosed.

---

## Executive Summary

An external security assessment was conducted on the web infrastructure of a national university network using passive OSINT techniques and non-intrusive reconnaissance. **No exploits were executed. No systems were accessed. No data was modified.**

The assessment identified **1 critical finding** (end-of-life server with public RCE exploit — CVE-2017-7269, CVSS 9.8), **1 high-severity finding** (end-of-life Apache 2.2.22 with memory disclosure — CVE-2017-9798, CVSS 7.5), **2 medium-severity findings** (outdated but still-supported server versions), and **4 lower-severity hardening items** across multiple regional campuses.

⚠️ **Important methodological note:** Server version strings were detected via HTTP banners and TLS handshakes. On Debian/Ubuntu-based systems, it is common practice to backport security patches without updating the banner version string. Therefore, a server reporting `Apache/2.2.22 (Ubuntu)` *may* have security patches applied. The findings below reflect banner-detected versions; active authorized verification is required to confirm actual patch levels.

---

## 1. Infrastructure Overview

| Item | Detail |
|------|--------|
| **Domain** | `national-university.example` |
| **Scope** | Central domain + 6 regional campus subdomains |
| **Web Servers** | Apache (various versions), nginx, IIS |
| **SSL** | Wildcard certificate (GeoTrust CA) |

---

## 2. Campuses Assessed (6 regional + central)

| Campus | Subdomain | Server |
|--------|-----------|--------|
| Central | `www.national-university.example` | nginx behind cloud WAF |
| North Campus | `www.north.national-university.example` | IIS/6.0 |
| East Campus | `www.east.national-university.example` | Apache/2.2.22 (Ubuntu) |
| West Campus | `www.west.national-university.example` | Apache/2.4.29 (Ubuntu) |
| South Campus | `www.south.national-university.example` | nginx/1.14.2 |
| Central-West Campus | `www.centralwest.national-university.example` | Drupal 10 — modern, actively supported |
| South-East Campus | `www.southeast.national-university.example` | HSTS preloaded, restrictive CSP |

---

## 3. Security Findings

### FINDING C1 — End-of-Life IIS 6.0 on Windows Server 2003 R2 — Public RCE Exploit Available

| Field | Detail |
|-------|--------|
| **Severity** | CRITICAL (CVSS 9.8) |
| **CWE** | CWE-120: Buffer Copy without Checking Size of Input |
| **Location** | `www.north.national-university.example` |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

**Description:**

The North Campus web server runs **IIS/6.0 on Windows Server 2003 R2**, an operating system whose extended support ended in 2015 — over a decade without security patches. This version is vulnerable to:

- **CVE-2017-7269**: Unauthenticated Remote Code Execution via WebDAV PROPATCH. Public proof-of-concept exploit code is available. Allows full server compromise without credentials.
- Multiple additional post-EOL CVEs affecting the underlying OS.

⚠️ **SSL certificate expires in approximately 5 days from assessment date**, adding urgency to the remediation window.

**Impact:** An attacker can gain unauthenticated remote code execution on the server, potentially pivoting to internal university networks, exfiltrating research data, or deploying ransomware.

**Verification (Synthetic PoC):**
```bash
# Banner fingerprinting confirms IIS/6.0
curl -sI "https://www.north.national-university.example/" | grep -i "server:"
# Expected: Server: Microsoft-IIS/6.0
```

**Remediation:**
1. **IMMEDIATE:** Migrate to a supported Windows Server version (2019/2022) or Linux-based stack
2. If immediate migration is not possible, isolate the server from the public internet behind a VPN
3. Renew the SSL certificate before expiration (5 days)
4. Conduct a full security audit of any legacy servers remaining in the network

---

### FINDING C2 — End-of-Life Apache 2.2.22 (14 years old, branch EOL 2018)

| Field | Detail |
|-------|--------|
| **Severity** | HIGH (CVSS 7.5) |
| **CWE** | CWE-1104: Use of Unmaintained Third-Party Components |
| **Location** | `www.east.national-university.example` |
| **CVSS Vector** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` |

**Description:**

The East Campus web server runs **Apache/2.2.22 (Ubuntu)**, belonging to the Apache 2.2.x branch whose end-of-life was January 2018. Known vulnerabilities include:

- **CVE-2017-9798** (Optionsbleed): Memory disclosure via malformed .htaccess `Limit` directives — CVSS 7.5
- Multiple additional post-EOL CVEs affecting the 2.2.x branch

**⚠️ Ubuntu backport caveat:** Ubuntu may have backported security patches to their Apache 2.2.22 package. The actual patch level cannot be confirmed from the banner string alone — active authorized verification is required.

**Impact:** If unpatched, an attacker can read arbitrary memory from the server process, potentially leaking credentials, session tokens, or configuration secrets.

**Remediation:**
1. Upgrade to Apache 2.4.x (latest stable) on a supported Ubuntu LTS release
2. If migration is blocked, verify the actual patch level via package changelog (`apt changelog apache2`)
3. Renew SSL certificate (32 days remaining)

---

### FINDING H1 — Outdated Apache 2.4.29 (9 years behind current)

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM (CVSS 5.0) |
| **CWE** | CWE-1104: Use of Unmaintained Third-Party Components |
| **Location** | `www.west.national-university.example` |

**Description:**

The West Campus server runs **Apache/2.4.29 (Ubuntu)** with a CodeIgniter application stack. While the Apache 2.4.x branch remains actively supported, version 2.4.29 was released in 2017 — significantly behind the current 2.4.6x releases, which include numerous security fixes.

**Remediation:** Update Apache to the latest version available in the Ubuntu LTS repositories.

---

### FINDING H2 — Outdated nginx 1.14.2

| Field | Detail |
|-------|--------|
| **Severity** | MEDIUM (CVSS 5.0) |
| **CWE** | CWE-1104: Use of Unmaintained Third-Party Components |
| **Location** | `www.south.national-university.example` |

**Description:**

The South Campus runs **nginx/1.14.2**, a version that no longer receives active security support. SSL certificate expires in approximately 63 days.

**Remediation:** Upgrade nginx to latest stable (1.24.x or newer).

---

### FINDING M1 — WordPress Admin Panels Publicly Accessible

| Field | Detail |
|-------|--------|
| **Severity** | LOW (CVSS 3.1) |
| **CWE** | CWE-200: Exposure of Sensitive Information |
| **Affected Campuses** | 3 regional campuses |

**Description:**

Multiple campus websites expose `/wp-admin/` login panels directly to the internet without additional access controls. While some redirect to login pages, brute-force attacks against WordPress admin panels are a well-known attack vector.

**Remediation:**
1. Restrict `/wp-admin/` access by IP (VPN or campus IP ranges only)
2. Implement rate-limiting on login attempts
3. Enable two-factor authentication for all admin accounts

---

### FINDING M2 — DMARC Policy Set to Monitor-Only (Phishing Risk)

| Field | Detail |
|-------|--------|
| **Severity** | LOW (CVSS 2.0) |
| **Location** | `national-university.example` |

**Description:**

Email authentication records:
- **SPF:** ✅ Configured (`v=spf1 mx include:spf.protection.outlook.com ~all`)
- **DMARC:** ⚠️ `p=none` — monitor-only mode, does not prevent domain spoofing
- **DKIM:** ❌ No default selector found

With `p=none`, anyone can send emails appearing to come from `@national-university.example` without them being rejected or quarantined.

**Remediation:**
1. Progressively tighten DMARC: `p=none` → `p=quarantine` → `p=reject`
2. Implement DKIM signing for all outbound email
3. Monitor DMARC aggregate reports (rua) during transition

---

### FINDING M3 — SSL Certificates Approaching Expiration

| Campus | Expiration | Days Remaining |
|--------|------------|:--------------:|
| North Campus | Imminent | **⚠️ ~5 days** |
| East Campus | 30 days | 30 |
| West Campus | 30 days | 30 |
| South Campus | 60 days | 60 |

**Remediation:** Renew certificates before expiration. Implement automated certificate renewal (e.g., certbot with Let's Encrypt) to prevent future lapses.

---

### FINDING M4 — Central Server Behind Cloud WAF

| Field | Detail |
|-------|--------|
| **Severity** | INFO |
| **Location** | `www.national-university.example` (central) |

**Observation:** The central domain sits behind a cloud Web Application Firewall (Azure App Gateway equivalent), which mitigates direct exposure of the nginx backend. This is a **positive finding** — recommended as a pattern for other campuses.

---

## 4. Positive Findings

These campuses demonstrate good security practices worth replicating across the network:

| Campus | Practice |
|--------|----------|
| Central-West Campus | Drupal 10 — modern CMS with active security support |
| South-East Campus | HSTS preloaded, restrictive Content-Security-Policy |
| Central | SPF + DMARC configured (needs DKIM + policy tightening) |

---

## 5. Tools & Methodology

| Phase | Activity | Tools & Techniques |
|-------|----------|-------------------|
| **F0 — OSINT** | Domain intelligence, subdomain discovery | dig, crt.sh |
| **F1 — Fingerprinting** | Server version detection, SSL analysis | curl (HTTP headers), openssl s_client |
| **F2 — CVE Correlation** | Version-to-CVE matching | NIST NVD, MITRE CVE database |
| **F3 — DNS Security** | Email authentication audit | dig (SPF/DMARC/DKIM) |

**Methodology Compliance:** OWASP Testing Guide v4, NIST SP 800-115. **No active scanning, no exploits, no automated crawling.**

**⚠️ Ubuntu/Debian Backport Limitation:** Servers running Apache/nginx packaged by Debian/Ubuntu may have security patches backported without changing the banner version string. Reported versions reflect HTTP banners, not necessarily the actual patch level. Active authorized verification is required to confirm.

---

## 6. CVE Analysis

| CVE | Component | CVSS | Status |
|-----|-----------|------|--------|
| CVE-2017-7269 | IIS 6.0 WebDAV RCE | 9.8 | Confirmed version match — public exploit exists |
| CVE-2017-9798 | Apache 2.2.x Optionsbleed | 7.5 | Confirmed version match |
| CVE-2017-7679 | Apache 2.2.x Buffer Overread (mod_mime) | 9.8 | Confirmed version match |

> **Note:** CVE applicability was assessed via version fingerprinting only. **No exploits were attempted or executed.** The IIS 6.0 finding includes a CVE with publicly available exploit code (CVE-2017-7269), but no exploitation was performed.

---

## 7. Disclosure Timeline

This assessment followed **Coordinated Vulnerability Disclosure (CVD)** best practices:

| Date | Event |
|------|-------|
| Day 0 | Passive reconnaissance and vulnerability assessment completed |
| Day 1 | Confidential report prepared with full technical details and remediation guidance |
| Pending | Delivery to system owner; standard 90-day CVD remediation window begins upon acknowledgment |
| Post-remediation | Public case study published with all identifiers replaced by synthetic data |

> **Note:** Timeline dates are generalized. This public version was prepared in accordance with CVD principles; the original confidential report contains complete technical details and affected endpoints.

---

## 8. Limitations

- **External Assessment Only:** No internal network testing was performed
- **Banner-Based Version Detection:** Actual patch levels may differ from reported versions on Debian/Ubuntu systems due to backporting practices
- **Passive Methodology:** No active exploitation or intrusive scanning was performed
- **Snapshot in Time:** Findings represent infrastructure state as of the assessment date
- **No Exploitation:** CVE applicability assessed via version matching; no exploits were executed

---

## 9. Prioritized Remediation Roadmap

### IMMEDIATE (0–7 days)
1. 🔴 **North Campus:** Renew expiring SSL certificate (5 days)
2. 🔴 **North Campus:** Begin migration off IIS 6.0 / Windows Server 2003 R2

### SHORT-TERM (1–4 weeks)
3. 🟠 **East Campus:** Verify Apache 2.2.22 patch level; upgrade to 2.4.x
4. 🟡 **West Campus:** Update Apache 2.4.29 to latest
5. 🟡 **South Campus:** Update nginx 1.14.2 to latest stable
6. 🔒 **All campuses:** Restrict `/wp-admin/` access by IP

### MEDIUM-TERM (1–3 months)
7. 📧 Tighten DMARC policy: `p=none` → `p=quarantine` → `p=reject`
8. 🔑 Implement DKIM signing
9. 🔒 Automate SSL certificate renewal (certbot / ACME)

### ONGOING
10. Establish a centralized patch management policy across all campuses
11. Implement a Vulnerability Disclosure Program (VDP)
12. Replicate security best practices from high-performing campuses (HSTS, CSP, modern CMS)

---

## 10. References

- CVE-2017-7269: https://nvd.nist.gov/vuln/detail/CVE-2017-7269
- CVE-2017-9798: https://nvd.nist.gov/vuln/detail/CVE-2017-9798
- OWASP Testing Guide v4: https://owasp.org/www-project-web-security-testing-guide/
- Apache 2.2.x End of Life: https://httpd.apache.org/
- DMARC Implementation Guide: https://dmarc.org/

---

*This is a fictionalized portfolio case study. No real infrastructure data, exploitation paths, or sensitive information is disclosed. Original responsible disclosure report delivered to the system owner. For questions, contact the repository maintainer.*

# 🔐 External Security Assessment — National University Network (Case Study)

[![Assessment Type](https://img.shields.io/badge/assessment-passive%20OSINT-blue)](https://github.com/dopaminauta/university-security-audit)
[![Methodology](https://img.shields.io/badge/disclosure-coordinated%20CVD-green)](https://github.com/dopaminauta/university-security-audit)
[![Exploitation](https://img.shields.io/badge/exploitation-none-brightgreen)](https://github.com/dopaminauta/university-security-audit)
[![Review](https://img.shields.io/badge/review-ethical%20QA%20gate-purple)](https://github.com/dopaminauta/university-security-audit)
[![Status](https://img.shields.io/badge/status-case%20study-orange)](https://github.com/dopaminauta/university-security-audit)

**Security assessment case study** — demonstrating multi-campus infrastructure audit, legacy system vulnerability research, and responsible disclosure practices.

>  **Important:** This repository contains a **fictionalized case study** based on an unsolicited good-faith external security assessment, prepared for professional portfolio purposes. All technical information, domain names, IP addresses, institutional names, campus locations, and server hostnames have been **replaced with synthetic or simulated data** to protect the confidentiality of the assessed organization, in accordance with Coordinated Vulnerability Disclosure (CVD) principles.

---

##  Overview

This case study demonstrates a multi-campus external security assessment: discovering and fingerprinting web servers across a distributed university network, identifying end-of-life systems with publicly available exploits, analyzing email security posture, and delivering a prioritized remediation roadmap.

**All work was performed passively — no exploits were executed, no systems were accessed, no data was modified or extracted.**

---

##  Key Findings

| Severity | Count | Category |
|----------|:-----:|----------|
|  CRITICAL (CVSS 9.8) | 1 | IIS 6.0 on Windows Server 2003 R2 — EOL 2015, public RCE exploit (CVE-2017-7269) |
| 🟠 HIGH (CVSS 7.5) | 1 | Apache 2.2.22 — branch EOL 2018, memory disclosure via mod_mime (CVE-2017-9798, CVE-2017-7679) |
| 🟡 MEDIUM (CVSS 5.0) | 2 | Apache 2.4.29 and nginx 1.14.2 — significantly outdated within supported branches |
|  LOW / INFO | 4 | WordPress admin exposure, DMARC monitor-only, expiring SSL certificates, WAF detection |

**Most Significant:** A campus web server running **IIS 6.0 on Windows Server 2003 R2** — an operating system without security patches since 2015 — with a publicly available unauthenticated RCE exploit (CVE-2017-7269, CVSS 9.8). SSL certificate expiring within 5 days.

---

## 🛠️ Skills Demonstrated

| Domain | Techniques |
|--------|------------|
| **OSINT** | Certificate transparency enumeration (crt.sh), DNS reconnaissance, subdomain discovery |
| **Web Security** | HTTP banner fingerprinting, TLS handshake analysis, CVSS 3.1 scoring |
| **Vulnerability Research** | CVE-to-version matching, EOL software risk assessment, public exploit correlation |
| **Email Security** | SPF/DMARC/DKIM audit, domain spoofing risk analysis |
| **Legacy System Assessment** | Windows Server 2003 R2, IIS 6.0, Apache 2.2.x risk evaluation |
| **Multi-Campus Audit** | Distributed infrastructure assessment, comparative security posture analysis |
| **Technical Writing** | CVSS-justified findings, backport-aware caveats, prioritized multi-campus remediation |

---

##  Repository Structure

```
university-security-audit/
├── README.md                      <- Portfolio overview & methodology
├── SECURITY_AUDIT_REPORT.md       <- Full case study report (fictionalized)
└── LICENSE                        <- MIT License
```

---

## 🧰 Methodology & Tools

| Phase | Tools Used |
|-------|------------|
| **OSINT** | dig, crt.sh |
| **Fingerprinting** | curl (HTTP headers), openssl s_client (TLS) |
| **Email Security** | dig (SPF/DMARC/DKIM) |
| **CVE Analysis** | NIST NVD, MITRE CVE database |
| **Quality Review** | Independent multi-stage validation |

**Standards:** OWASP Testing Guide v4 · NIST SP 800-115

** Ubuntu/Debian Backport Caveat:** Servers on Debian-based distributions may backport security patches without updating the banner version string. Reported versions reflect HTTP banners; actual patch levels require authorized active verification.

---

##  Ethics & Coordinated Disclosure

1. **100% Passive:** No active exploitation, no intrusion, no denial of service
2. **OSINT-Only:** All intelligence from public sources and non-intrusive banner inspection
3. **Confidential First:** A complete confidential report was prepared for the system owner
4. **Structural Sanitization:** All identifying information replaced with synthetic data for this public version
5. **No Exploit Code:** This repository contains no working exploits or bypass techniques

---

##  Assessment Metrics (Fictionalized)

| Metric | Value |
|--------|:-----:|
| Campuses Assessed | 7 (6 regional + central) |
| Technologies Fingerprinted | IIS, Apache, nginx, Drupal, WordPress, CodeIgniter |
| End-of-Life Systems Found | 2 (IIS 6.0, Apache 2.2.22) |
| CVEs Evaluated | 3 confirmed matches |
| SSL Certificates Audited | 5 |
| Findings Documented | 8 |

---

## 📄 Full Case Study

-> **[SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)**

---

*Professional security portfolio. For inquiries, contact the repository maintainer. Unauthorized use of the techniques described against systems you do not own or have written permission to test is illegal.*

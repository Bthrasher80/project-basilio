[README.md](https://github.com/user-attachments/files/29809405/README.md)
# DISA Windows 11 STIG Remediation — Project Basilio

**Author:** Basilio Thrasher
**Context:** LOGN Pacific Cyber Range Vulnerability Management Internship
**Benchmark:** DISA Microsoft Windows 11 STIG v2r7
**Tools:** Tenable Vulnerability Management (authenticated compliance scanning), PowerShell, Microsoft Azure
**Date:** June–July 2026

---

## Overview
This project documents the end-to-end remediation of ten DISA STIG findings on a Windows 11 asset, from authenticated compliance scanning through PowerShell remediation to re-validation. Each control was identified via an authenticated Tenable scan against the DISA Windows 11 STIG v2r7 audit policy, remediated with PowerShell, and re-scanned to confirm compliance.

The baseline authenticated scan returned **97 Passed**; after remediation the asset returned **107 Passed** — a verifiable movement of ten controls, corroborated by the timestamped Tenable scan History.

## Environment
- **Target:** Windows 11 Pro VM (`VirtualTest15`), private IP 10.0.0.10, Microsoft Azure (LOGN Pacific Cyber Range subscription)
- **Scanner:** Tenable `LOCAL-SCAN-ENGINE-01`, authenticated credentialed compliance scan
- **Audit policy:** DISA Microsoft Windows 11 STIG v2r7 — Windows Compliance Checks
- **Scan template:** `BT_Win11_STIG_Template_FAST_SCAN` (compliance-only, scoped for rapid rescans)

## Methodology
1. **Authenticated scan setup.** Resolved an initial credentialed-scan authentication failure (single Warning instead of Pass/Fail) by setting `LocalAccountTokenFilterPolicy = 1`, enabling Remote Registry / admin shares / Server service in the scan template, and disabling the host firewall. This produced full ~263-control Pass/Fail results.
2. **Baseline scan.** Captured the failing state of each target control.
3. **Remediation.** Applied each fix with PowerShell, using `New-Item -Force` to create absent policy keys followed by `New-ItemProperty -Force` to set values reliably.
4. **Verification.** Confirmed each value at the source with `Get-ItemProperty` before rescanning — never trusting command exit status alone.
5. **Re-scan validation.** Re-ran the compliance scan to confirm each control moved to Passed.
6. **Methodology proof.** Demonstrated a full fix → revert → re-apply cycle on a representative control (WN11-CC-000315) to prove remediation effectiveness; remaining controls documented as remediation-confirmed.

## Remediated Controls

| # | STIG-ID | Title | CAT | Writeup |
|---|---|---|---|---|
| 1 | WN11-CC-000315 | Always install with elevated privileges disabled | II | [WN11-CC-000315.md](WN11-CC-000315.md) |
| 2 | WN11-CC-000110 | Printing over HTTP prevented | II | [WN11-CC-000110.md](WN11-CC-000110.md) |
| 3 | WN11-CC-000100 | Print driver download over HTTP prevented | II | [WN11-CC-000100.md](WN11-CC-000100.md) |
| 4 | WN11-CC-000197 | Microsoft consumer experiences off | III | [WN11-CC-000197.md](WN11-CC-000197.md) |
| 5 | WN11-CC-000305 | Indexing of encrypted files off | II | [WN11-CC-000305.md](WN11-CC-000305.md) |
| 6 | WN11-CC-000170 | Microsoft accounts optional | III | [WN11-CC-000170.md](WN11-CC-000170.md) |
| 7 | WN11-CC-000185 | Autorun commands prevented | **I** | [WN11-CC-000185.md](WN11-CC-000185.md) |
| 8 | WN11-CC-000175 | App Compatibility Inventory prevented | III | [WN11-CC-000175.md](WN11-CC-000175.md) |
| 9 | WN11-CC-000326 | PowerShell script block logging enabled | II | [WN11-CC-000326.md](WN11-CC-000326.md) |
| 10 | WN11-CC-000327 | PowerShell transcription enabled | II | [WN11-CC-000327.md](WN11-CC-000327.md) |

**Documented not-applicable:** [WN11-CC-000391](WN11-CC-000391-NOT-APPLICABLE.md) — Internet Explorer disable; not applicable on Windows 11 25H2 (IE already retired). Substituted with WN11-CC-000185.

## Key Skills Demonstrated
- Authenticated (credentialed) compliance scanning with Tenable against a DISA STIG benchmark
- Diagnosing and resolving credentialed-scan authentication failures (UAC token filtering, Remote Registry, firewall)
- PowerShell registry remediation with reliable create-and-set patterns
- Remediation verification discipline (source-of-truth checks, not exit-status trust)
- Full fix → revert → re-validate proof of remediation effectiveness
- Vulnerability-management judgment on environment-limited controls (documented N/A + substitution)
- Mapping compliance controls to detection value (PowerShell logging → EID 4104 → T1059.001 hunting)

## Evidence
All scan-state screenshots (baseline Failed, post-fix Passed, revert Failed, re-apply Passed) and the Tenable History timeline are stored in `/screenshots`. The History tab captures 19 timestamped scan runs across the project, serving as the tamper-evident audit trail.

## Notes on Reproduction
All PowerShell remediation commands are included as text in each control's writeup. Azure resource identifiers (subscription ID, resource group) have been redacted from methodology screenshots prior to publication.

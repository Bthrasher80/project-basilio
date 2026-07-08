# WN11-CC-000391 — Internet Explorer Must Be Disabled — NOT APPLICABLE (Environment-Limited)

**Project:** Project Basilio — DISA STIG Remediation (LOGN Pacific Cyber Range Internship)
**Date:** June–July 2026
**Benchmark:** DISA Microsoft Windows 11 STIG v2r7
**STIG-ID:** WN11-CC-000391
**Status:** NOT APPLICABLE — documented and substituted with WN11-CC-000185

---

## Summary
This control requires Internet Explorer to be disabled. During remediation I determined it could not be satisfied on the target build (Windows 11 25H2) and made a documented decision to mark it not-applicable and substitute an alternate control (WN11-CC-000185, a CAT I autorun control) to complete a full set of ten remediated STIGs.

## What I Tried
1. **Registry approach.** Set `NotifyDisableIEOptions = 1` under `HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Main`. The value wrote and persisted, but the Tenable audit still returned **Failed** — the control's check requires Internet Explorer to be absent/disabled as a feature, not merely flagged via this registry value.

2. **DISA-documented feature removal fallback.** Ran:
   ```powershell
   Disable-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -NoRestart
   ```
   This failed with: `Feature name Internet-Explorer-Optional-amd64 is unknown.`

## Root Cause
Internet Explorer 11 has been **retired and removed** from Windows 11 25H2. The optional-feature name the STIG's fix targets does not exist on this build, so the feature-removal command has nothing to act on, and the registry-only approach does not satisfy the audit's check logic. The control is effectively **not applicable** to this OS version in the way the v2r7 STIG expects — the underlying component the control governs is already gone.

## Decision
Rather than spend disproportionate time forcing an invalid remediation on an environment-limited control, I:
- Documented WN11-CC-000391 as not-applicable with the evidence and rationale above, and
- Substituted **WN11-CC-000185** (Default autorun behavior — a **CAT I** control) to complete a defensible set of ten fully remediated and validated STIGs.

The substitution strengthened the overall set by adding a highest-severity (CAT I) finding.

## Evidence Captured
Screenshots stored in `/screenshots`:
- `WN11-CC-000391_registry-set-still-fails_1of2.png` — registry value confirmed set (NotifyDisableIEOptions = 1)
- `WN11-CC-000391_registry-set-still-fails_2of2.png` — Tenable audit still Failed after registry value set
- `WN11-CC-000391_feature-removal-error.png` — "feature name unknown" error confirming IE is not present on this build

## Why This Matters (Analyst Judgment)
Recognizing that an OS build has already removed the component a STIG targets — and documenting it as not-applicable rather than reporting a false remediation — is a core vulnerability-management skill. Real VM programs constantly encounter controls that don't map cleanly to a given environment; the professional response is documented justification and, where appropriate, a compensating or substitute control, not a forced or fabricated pass.

## Interview Formula
> I demonstrated vulnerability-management judgment when I identified a STIG control as environment-limited — Internet Explorer was already retired in Windows 11 25H2, making the prescribed fix invalid — documented it as not-applicable with evidence, and substituted a CAT I control to complete the set. Documented at github.com/Bthrasher80/project-basilio.

## Status: NOT APPLICABLE — DOCUMENTED AND SUBSTITUTED

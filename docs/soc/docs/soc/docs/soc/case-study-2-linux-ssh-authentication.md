# Case Study #2 — Linux SSH Authentication Events

Project: Project Basilio  
Sprint: Sprint 2 — Telemetry & SOC Foundations  
Endpoint: Linux Endpoint (SSH)

---

## 1. Scenario Overview

This case study examines SSH authentication events on a Linux endpoint to validate visibility, analyst reasoning, and triage discipline using native system logs.

The objective is to demonstrate how a SOC analyst detects, investigates, and classifies SSH authentication activity without relying on centralized tooling.

---

## 2. Trigger / Initial Signal

Description of the initial SSH authentication signal observed.

Examples:
- Failed SSH login attempts
- Successful SSH login after failures
- Unexpected authentication attempt

---

## 3. Evidence Collected

Log source(s):
- /var/log/auth.log or /var/log/secure

Evidence attributes:
- Timestamp
- Username
- Source IP
- Authentication result

---

## 4. Analyst Reasoning

Analysis considerations:
- Was the login expected?
- Did the activity originate locally or remotely?
- Was the username valid?
- Was the timing consistent with normal usage?

---

## 5. Classification

Final classification:
- ☐ True Positive (TP)
- ☐ False Positive (FP)
- ☐ Benign True Positive (BTP)

Rationale for classification.

---

## 6. Lessons Learned

Key takeaways regarding Linux authentication telemetry, visibility gaps, and detection considerations.

---

## 7. SOC Relevance

This case study demonstrates foundational Linux authentication analysis skills applicable to SOC and vulnerability management roles.

# Case Study #1 — Windows Authentication Events

Project: Project Basilio  
Sprint: Sprint 2 — Telemetry & SOC Foundations  
Endpoint: Dell Latitude 7480 (Windows)

---

## 1. Scenario Overview

This case study examines Windows authentication events generated on a monitored endpoint to validate visibility, analyst reasoning, and triage discipline using native OS logs.

The objective is to demonstrate how a SOC analyst detects, validates, and classifies authentication-related activity without relying on advanced SIEM tooling.

---

## 2. Trigger / Initial Signal

Description of the initial signal observed.

Examples:
- Repeated failed login attempts
- Failed login followed by a successful login
- Unexpected authentication event outside normal usage

---

## 3. Evidence Collected

Evidence sources:
- Windows Security Event Logs
- Authentication-related event IDs

Evidence captured:
- Timestamp
- Hostname
- Username
- Event ID
- Event description

*(Screenshots and log excerpts to be added after execution.)*

---

## 4. Analyst Reasoning

Key questions considered:
- Is this expected behavior for this system?
- Does the activity suggest user error, misconfiguration, or malicious intent?
- Is there evidence of credential misuse or brute-force behavior?

Reasoning steps:
- Correlated failed and successful attempts
- Evaluated frequency and timing
- Considered endpoint role and user context

---

## 5. Classification

Final classification:
- ☐ True Positive (TP)
- ☐ False Positive (FP)
- ☐ Benign True Positive (BTP)

Rationale for classification decision.

---

## 6. Lessons Learned

- What this event demonstrated about visibility
- Gaps or improvements identified
- Relevance to future detection engineering or alerting

---

## 7. SOC Relevance

This case study demonstrates:
- Analyst triage discipline
- Proper use of native telemetry
- Clear documentation of investigative reasoning

This foundational workflow will later scale into SIEM-driven detections in Sprint 3.

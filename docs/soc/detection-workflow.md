# Project Basilio — SOC Detection & Triage Workflow

## Purpose

This document defines the standard workflow for detecting, validating, triaging,
and investigating security events in Project Basilio. It is written to mirror
enterprise SOC operations and to support repeatable, portfolio-quality case studies.

---

## Operating Principles

- Prefer high-signal alerts over noisy rules
- Verify before escalating
- Document decisions (why an alert was true/false/benign)
- Preserve evidence needed for investigation and reporting

---

## Workflow Overview (End-to-End)

1. Alert triggers (detection fires)
2. Alert validation (is it real?)
3. Triage and classification (what is it?)
4. Scoping (how big is it?)
5. Containment / response (if needed)
6. Documentation and lessons learned

---

## 1) Alert Trigger

**Inputs**
- Endpoint telemetry (auth, process, file, network)
- Firewall logs
- (Future) network sensor data

**Outputs**
- Alert record with timestamp, host, user, rule name, and event context

**Minimum data captured**
- Host identifier (sanitized)
- Username (sanitized when needed)
- Time window
- Triggering event(s)
- Source log type

---

## 2) Alert Validation (First 5 Minutes)

**Goal:** Determine whether the alert is legitimate and actionable.

**Checklist**
- Confirm the event actually occurred (not parser noise)
- Confirm the host is expected to generate this type of event
- Check for obvious benign explanations (maintenance, updates, admin work)
- Identify whether this is a recurring pattern

**Decision**
- True Positive (TP)
- False Positive (FP)
- Benign True Positive (BTP) — real activity but expected/approved

**Notes**
Validation is not full investigation. It is a quick reality check.

---

## 3) Triage & Classification

**Goal:** Assign priority and category.

**Example categories**
- Authentication anomalies (brute force, impossible travel, new admin user)
- Execution anomalies (suspicious process trees, LOLBins)
- Persistence (new services, startup entries)
- Discovery/lateral movement indicators
- Malware indicators

**Priority guidance**
- P1: Active compromise suspected / high confidence malicious
- P2: Likely malicious but needs scoping
- P3: Suspicious activity; monitor and enrich
- P4: Informational; record and tune detections

---

## 4) Scoping (Blast Radius)

**Goal:** Determine how far the activity extends.

**Scope questions**
- Is it isolated to one host or multiple?
- Is the same user involved elsewhere?
- Are there related events in the same timeframe?
- Any evidence of privilege escalation or persistence?

**Artifacts gathered**
- Related event IDs/log lines
- Time-bounded searches around the trigger (+/- 30–60 minutes)
- List of impacted hosts/users (sanitized)

---

## 5) Response Actions (Lab-Appropriate)

**Goal:** Contain and confirm.

**Possible actions**
- Isolate endpoint (logical isolation / VLAN change / firewall rule)
- Disable suspected account (lab account only)
- Kill process / stop service (if safe)
- Collect basic forensic evidence (process list, network connections, logs)

**Rule**
In Project Basilio, response steps are documented even if containment is simulated.

---

## 6) Documentation (Case Study Format)

Every alert that becomes a case study should produce:

**Case Header**
- Title
- Date/time (local)
- Systems involved (sanitized)
- Alert summary

**Evidence**
- Key log excerpts (sanitized)
- Screenshots of dashboards/searches (sanitized)
- Timeline of events

**Analysis**
- Why it was malicious/benign
- What detection logic caught it
- What data sources were most valuable

**Outcome**
- Actions taken
- Final classification (TP/FP/BTP)
- Lessons learned and tuning ideas

---

## Detection Tuning Loop

After closing an alert, decide:

- Keep rule as-is
- Increase threshold / add suppression
- Add allowlist logic for known-good behavior
- Improve enrichment (hostname/user context, process lineage, etc.)

Tuning is treated as a first-class deliverable because it demonstrates SOC maturity.

---

## Portfolio Note

This workflow is intentionally written to support repeatable artifacts:
alerts → validation → investigation → write-up.
Each completed case becomes a standalone portfolio entry.

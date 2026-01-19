Case Study #1 — Windows Authentication Events

Project: Project Basilio
Sprint: Sprint 2 — Telemetry & SOC Foundations
Endpoint: Dell Latitude 7480 (Windows)

1. Scenario Overview

This case study examines Windows authentication events generated on a monitored endpoint to validate visibility, analyst reasoning, and triage discipline using native operating system logs.

The objective is to demonstrate how a SOC analyst detects, investigates, and classifies authentication-related activity without relying on SIEM dashboards or advanced tooling, focusing instead on signal interpretation and context.

2. Trigger / Initial Signal

During normal endpoint usage, multiple authentication events were observed in the Windows Security log, including failed logon attempts followed by a successful logon.

The sequence warranted review to determine whether the activity represented benign user behavior or potential credential abuse.

3. Evidence Collected

Log Source: Windows Security Event Log

Relevant Events Identified:

Event ID 4625 — Failed logon attempt (two occurrences)

Event ID 4648 — Logon attempt using explicit credentials

Event ID 4624 — Successful logon

Key Evidence Attributes:

Same endpoint (Dell Latitude 7480)

Same user account

Interactive logon type

Events occurred within a short time window

Activity originated locally from the endpoint

Screenshots were captured to document failed and successful authentication events and to preserve timeline context.

4. Analyst Reasoning

The analyst evaluated the activity using the following considerations:

The failed logon attempts involved a valid local user account.

The activity occurred while the user was physically present at the endpoint.

Event ID 4648 appeared between failed and successful logons, consistent with normal Windows credential handling during interactive authentication retries.

The authentication sequence concluded with a successful logon shortly after the failures.

No evidence of multiple usernames, remote source IPs, or repeated attempts across systems was observed.

Based on timing, context, and endpoint role, the activity aligned with normal user behavior rather than malicious intent.

5. Classification

Final Classification: Benign True Positive (BTP)

Rationale:
While failed authentication events were legitimately detected, the surrounding context indicates the activity resulted from user input errors during an interactive logon session. The presence of Event ID 4648 reflects standard credential validation behavior rather than misuse.

6. Lessons Learned

Windows authentication workflows may generate intermediate events (e.g., Event ID 4648) that appear suspicious without contextual analysis.

Timeline correlation is essential to distinguish benign behavior from credential-based attacks.

Not all failed logons represent malicious activity; analyst judgment is required to prevent false escalation.

Native OS logs provide sufficient signal for effective triage when properly interpreted.

7. SOC Relevance

This case study demonstrates foundational SOC analyst capabilities, including:

Interpreting native endpoint telemetry

Correlating authentication events over time

Applying contextual reasoning to avoid false positives

Producing clear, structured investigative documentation

The workflow established here will scale into SIEM-driven detection and alerting in future sprints.

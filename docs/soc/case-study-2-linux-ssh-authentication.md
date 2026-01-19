Case Study #2 — Linux SSH Authentication Events

Project: Project Basilio
Sprint: Sprint 2 — Telemetry & SOC Foundations
Endpoint: HP Linux Victim (Ubuntu Server 22.04)

1. Scenario Overview

This case study examines SSH authentication activity on a Linux endpoint to validate host-level visibility into credential access events. The objective was to observe failed and successful SSH authentication attempts using native Linux logging mechanisms, without reliance on centralized SIEM tooling.

2. Trigger / Initial Activity

The analyst initiated multiple SSH connection attempts to the Linux host, intentionally generating:

an initial failed authentication attempt

a subsequent successful authentication using valid credentials

All activity was performed locally to simulate realistic user behavior and authentication retries.

3. Evidence Collection

Log Source:
/var/log/auth.log

Relevant Artifacts Identified:

Failed SSH authentication (Failed password)

Successful SSH authentication (Accepted password)

PAM session creation (session opened for user)

4. Observed Events

The system recorded a failed SSH login attempt due to invalid credentials.

A subsequent authentication attempt using correct credentials was accepted.

A user session was successfully established following authentication.

These events confirm that the Linux host provides clear, timestamped visibility into SSH authentication activity.

5. Analysis & Interpretation

The observed log sequence demonstrates a complete SSH authentication lifecycle:

credential failure

retry behavior

successful access

session establishment

Such patterns are commonly analyzed during investigations involving credential misuse, brute-force attempts, or unauthorized access attempts in enterprise Linux environments.

6. Outcome

This case study confirms that Linux host-based telemetry provides sufficient detail to:

detect failed authentication attempts

confirm successful access

reconstruct authentication timelines

The endpoint is now validated as a reliable telemetry source for SOC investigations involving SSH access.

7. Screenshots

Supporting screenshots are available in:

docs/soc/screenshots/case-study-2/

# Project Basilio — Security Telemetry Flow

## Purpose

This document explains how security telemetry is generated, transported,
ingested, and used within Project Basilio.

The intent is to make telemetry flow traceable and defensible.

---

## Telemetry Philosophy

Project Basilio prioritizes:

- Host-based visibility before network-scale visibility
- High-signal data sources
- End-to-end traceability from event to investigation

Every telemetry source must support detection or investigation use cases.

---

## Telemetry Sources

**Endpoint Systems**
- Linux authentication logs
- System logs
- Process and file activity
- Network connections

**Network Devices**
- Firewall logs
- (Future) Network sensor telemetry

---

## Transport Layer

Telemetry is securely transmitted from endpoints to centralized platforms
using agent-based and protocol-appropriate methods.

Transport choices emphasize reliability and auditability.

---

## Ingestion & Processing

Centralized platforms perform:

- Log normalization
- Correlation
- Alerting
- Retention for investigation

Raw telemetry is preserved where possible to support forensic review.

---

## Analyst Consumption

Analysts interact with telemetry through:

- Dashboards
- Searches
- Alerts
- Case notes

Telemetry supports both reactive incident response
and proactive threat hunting workflows.

---

## Future Expansion

Network-based telemetry (e.g., packet inspection)
will be added only after endpoint visibility is mature
to avoid overwhelming analysis workflows.

---

## Summary

Telemetry flow in Project Basilio is intentional, explainable,
and aligned with real-world SOC operations.

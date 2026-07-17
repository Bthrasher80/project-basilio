# project-basilio

Project Basilio is an enterprise-style cybersecurity home lab designed to demonstrate
SOC operations, vulnerability management, detection engineering, and Linux administration
skills through intentional architecture and documented decision-making.

## Architecture

- [Lab Architecture Overview](https://github.com/Bthrasher80/project-basilio/blob/main/docs/architecture/lab-architecture-overview.md)
- [Telemetry Flow](https://github.com/Bthrasher80/project-basilio/blob/main/docs/architecture/telemetry-flow.md)

## Documentation

- [Hardware Justification & Design Decisions](https://github.com/Bthrasher80/project-basilio/blob/main/docs/hardware/hardware-justification.md)
- [SOC Detection & Triage Workflow](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/detection-workflow.md)
- [DISA STIG Remediation](https://github.com/Bthrasher80/project-basilio/tree/main/docs/stigs) — Windows 11 STIG (v2r7) remediation using Tenable and PowerShell, 97→107 passing controls
- [TOR Browser Threat Hunt](https://github.com/Bthrasher80/project-basilio-tor-threat-hunt)

## Lab Artifacts

- [Active Directory](https://github.com/Bthrasher80/project-basilio-active-directory)
- [Network Segmentation](https://github.com/Bthrasher80/project-basilio-network-segmentation)
- [Centralized Logging](https://github.com/Bthrasher80/project-basilio-centralized-logging)
- [Wazuh SIEM Deployment](https://github.com/Bthrasher80/project-basilio-wazuh-siem)


## SOC Foundations

This section documents SOC analyst workflows, access controls, and investigation practices developed as part of Project Basilio.

Included artifacts:

- [Detection & Triage Workflow](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/detection-workflow.md)
- [Credential & Access Practices](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/credential-access-practices.md)
- [Case Study #1 — Windows Authentication Events (Sprint 2)](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/case-study-1-windows-authentication.md)
- [Case Study #2 — Linux SSH Authentication](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/case-study-2-linux-ssh-authentication.md)
- [Hunt 07: Rocky Clinic OpenEMR Breach](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/hunt07-rocky-clinic-openemr-breach.md)
- [Hunt 07: KQL Query Library](https://github.com/Bthrasher80/project-basilio/blob/main/docs/soc/hunt07_rocky_clinic_kql_library.md)

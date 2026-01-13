# Project Basilio — Hardware Justification & Design Decisions

## Purpose

This document explains the rationale behind each physical system used in Project Basilio.
The goal is to demonstrate intentional design, separation of duties, and alignment between
hardware choices and cybersecurity skill development.

This lab is designed to reflect an enterprise SOC and vulnerability management environment,
not a hobbyist setup.

---

## Core Infrastructure

### Dell Latitude 5400 — Proxmox Host
**Role:** Centralized infrastructure and network backbone

**Justification:**
This system hosts all core services including virtualization, firewalling, identity,
and centralized logging. Consolidating infrastructure reflects real-world enterprise
design while maintaining clear logical separation via virtualization.

**Primary Skills Demonstrated:**
- Virtualization (Proxmox)
- Network segmentation (pfSense)
- SOC platform administration (Wazuh, Splunk)
- Identity services (Active Directory)

---

## Analyst & Operator Workstations

### Lenovo IdeaPad — SOC Analyst Workstation
**Role:** Blue-team operations and investigation

**Justification:**
Separating analyst workflows from infrastructure mirrors real SOC environments and
prevents accidental disruption of core services.

**Primary Skills Demonstrated:**
- SIEM alert triage
- Log analysis
- Case documentation
- Vulnerability management workflows

---

### Dell Latitude 5411 — Purple Team / Detection Testing
**Role:** Controlled adversary simulation and detection validation

**Justification:**
This system is used to generate attack telemetry and validate detections without
contaminating analyst systems or infrastructure hosts.

**Primary Skills Demonstrated:**
- Detection engineering
- Attack simulation
- Validation of SOC controls

---

## Endpoint Systems (Telemetry Sources)

### Linux Endpoints (HP Laptop, Minisforum, Dell 7480)
**Role:** Realistic endpoint telemetry generation

**Justification:**
Endpoints are intentionally low-to-moderate resource systems to reflect real-world
environments. These systems generate authentication, process, file, and network logs
used for detection and incident response exercises.

**Primary Skills Demonstrated:**
- Endpoint logging
- Lateral movement detection
- Incident response investigation

---

## Network Visibility

### Dell OptiPlex 7040 — Network Sensor
**Role:** Dedicated network traffic inspection

**Justification:**
A dedicated system is reserved for network-based visibility tools to avoid resource
contention and to reflect enterprise separation of host-based and network-based telemetry.

**Primary Skills Demonstrated:**
- Network traffic analysis
- Zeek and Suricata monitoring
- East-west and north-south visibility

---

## Linux Learning Platform

### Lenovo ThinkPad T490 — LFCS Preparation System
**Role:** Linux learning and certification preparation

**Justification:**
This system provides a safe, non-production environment for Linux administration practice.
It allows break/fix learning without risking SOC operations and may be integrated into
the lab later if a clear operational role is identified.

**Primary Skills Demonstrated:**
- Linux system administration
- Service configuration
- Storage and networking management
- Automation fundamentals

---

## Design Principles Demonstrated

- Separation of duties
- Learning environments isolated from production
- Hardware choices aligned to skill outcomes
- Controlled expansion to prevent lab sprawl

This hardware design reflects intentional engineering decisions rather than ad-hoc
experimentation.

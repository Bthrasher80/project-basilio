# Project Basilio — Lab Architecture Overview

## Purpose

This document describes the high-level architecture of Project Basilio.
The goal is to explain system roles, trust boundaries, and design intent
without exposing sensitive configuration details.

---

## Architectural Goals

Project Basilio is designed to:

- Mirror enterprise SOC and vulnerability management environments
- Enforce separation of duties between infrastructure, analysts, and endpoints
- Prioritize signal over tool sprawl
- Support portfolio-quality documentation and repeatable workflows

---

## High-Level Structure

The lab is divided into four logical layers:

1. Infrastructure & Network Control
2. SOC & Management Platforms
3. Analyst & Operator Workstations
4. Endpoint Systems (Telemetry Sources)

Each layer has a defined responsibility and limited scope.

---

## Infrastructure & Network Control

**Core Components**
- Proxmox virtualization host
- pfSense firewall

**Responsibilities**
- Network segmentation
- Traffic control and routing
- Hosting core security services via virtual machines

This layer is intentionally isolated from analyst workflows to reduce risk
and reflect enterprise infrastructure practices.

---

## SOC & Management Platforms

**Core Platforms**
- Centralized logging (SIEM)
- Endpoint security monitoring
- Vulnerability management services

**Responsibilities**
- Log ingestion and correlation
- Alert generation
- Vulnerability assessment and tracking

These platforms consume telemetry but do not generate it.

---

## Analyst & Operator Workstations

**Responsibilities**
- Alert triage
- Investigation
- Documentation
- Detection validation

Analyst systems are deliberately separated from infrastructure hosts
to prevent accidental disruption and to reflect real SOC workflows.

---

## Endpoint Systems

**Responsibilities**
- Generate authentication, process, file, and network telemetry
- Simulate realistic user and server behavior
- Serve as investigation targets during IR exercises

Endpoints are intentionally modest in resources to reflect real-world environments.

---

## Design Principles

- Separation of duties
- Least privilege
- Intentional growth
- Documentation-first engineering

This architecture favors clarity and explainability over complexity.

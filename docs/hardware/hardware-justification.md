# Project Basilio — Hardware Justification & Design Decisions

## Purpose

This document explains the rationale behind each physical system used in Project Basilio. The goal is to demonstrate intentional design, separation of duties, and alignment between hardware choices and cybersecurity skill development.

This lab is designed to reflect an enterprise SOC and vulnerability management environment, not a hobbyist setup.

---

## Core Infrastructure

### Dell Latitude 5400 — Proxmox Virtualization Host

**Specs:** Intel i5-8365U @ 1.60GHz | 32GB RAM

**Role:** Core compute and virtualization infrastructure

**Justification:** This system hosts all lab VMs including Active Directory, Wazuh SIEM, and Windows and Linux victim machines. 32GB RAM supports realistic multi-VM workloads that mirror enterprise environments. Proxmox was selected for its enterprise-grade hypervisor capabilities and support for snapshots, cloning, and resource isolation. The i5-8365U is an 8th gen U-series processor — efficient for always-on virtualization workloads where sustained single-core performance matters less than stable multi-VM hosting.

**Primary Skills Demonstrated:**
- Virtualization (Proxmox VE)
- VM provisioning and resource management
- Active Directory administration
- Wazuh SIEM deployment and agent management

---

### Dell OptiPlex 5050 Micro — Network Edge / Firewall Appliance

**Specs:** Intel i5-6500T | 16GB RAM

**Role:** Dedicated pfSense router and firewall

**Justification:** Deploying pfSense on dedicated hardware rather than as a virtualized instance mirrors enterprise network architecture where the firewall is a physically separate appliance. This system serves as the network choke point, enforcing segmentation between lab zones, handling NAT and routing, and controlling traffic between attacker systems, victim endpoints, and core services. Physical separation from the hypervisor eliminates the risk of a compromised VM affecting firewall enforcement. The i5-6500T desktop-class processor provides stable, efficient performance for routing and firewall tasks.

**Primary Skills Demonstrated:**
- Network segmentation and zone enforcement
- Firewall rule design and management
- NAT and routing configuration
- Enterprise-style trust boundary implementation

---

### ThinkPad T490 — SIEM / Splunk Node

**Specs:** Intel i7-8665U | 24GB RAM | 512GB SSD | Gigabit Ethernet (RJ-45)

**Role:** Dedicated Splunk deployment and log ingestion

**Justification:** Running Splunk on dedicated hardware with a quad-core processor and 24GB RAM ensures consistent performance during log-heavy detection exercises and threat hunting sessions. The i7-8665U (8th gen, 4-core) provides meaningful headroom for sustained Splunk search workloads. The built-in gigabit ethernet port ensures reliable high-throughput log ingestion from lab endpoints without adapter dependency. Separating the SIEM from the virtualization host mirrors production SOC architecture where log aggregation infrastructure is isolated from endpoint systems.

**Primary Skills Demonstrated:**
- Splunk deployment and Universal Forwarder configuration
- SPL query development and dashboard creation
- Log ingestion and correlation across multiple sources
- Detection engineering and alert tuning

---

## Analyst & Operator Workstations

### Lenovo IdeaPad 1 15ALC7 — Primary SOC Analyst Workstation

**Specs:** AMD Ryzen 7 5700U @ 1.80GHz | 40GB RAM | 477GB Storage

**Role:** Primary analysis console and investigation platform

**Justification:** The Ryzen 7 5700U (Zen 3 architecture) combined with 40GB RAM makes this the highest-performing user-facing machine in the lab. Separating analyst workflows from infrastructure mirrors real SOC environments and prevents accidental disruption of core services during investigations. This system is used for Wazuh and Splunk log analysis, threat hunting queries, and event investigation using Sysmon and Windows event logs.

**Primary Skills Demonstrated:**
- SIEM alert triage and investigation
- Log analysis and event correlation
- Threat hunting workflows
- Case documentation

---

### Dell Latitude 5411 — Purple Team / Attack Simulation

**Specs:** Intel i7-10850H @ 2.70GHz | 32GB RAM

**Role:** Offensive operations and detection validation

**Justification:** The i7-10850H is a 10th gen H-series processor — the highest sustained CPU performance in the lab. Controlled attack simulation requires a dedicated system isolated from analyst and infrastructure machines. Using a separate physical node for adversary emulation ensures attack telemetry does not contaminate analyst systems or core services, and allows realistic end-to-end detection validation across the full stack. The H-series processor handles tool-heavy offensive workloads including Metasploit, BloodHound, and Impacket without performance constraints.

**Primary Skills Demonstrated:**
- Attack simulation and adversary emulation
- Endpoint telemetry generation
- Detection rule validation across SIEM and EDR stack
- Purple team operations

---

### Dell Latitude 7480 — Kali Linux / Offensive Tooling

**Specs:** Intel i7-6600U @ 2.60GHz | 16GB RAM

**Role:** Dedicated Kali Linux platform and secondary offensive tooling

**Justification:** A dedicated Kali Linux machine provides a stable, persistent offensive tooling environment separate from the primary purple team system. The 7480 handles lightweight attack tooling, scanning, and exploitation exercises without competing for resources on the 5411. Maintaining two offensive platforms mirrors enterprise red team environments where multiple operators work simultaneously.

**Primary Skills Demonstrated:**
- Kali Linux administration
- Offensive security tooling
- Scanning and enumeration
- Exploitation frameworks

---

## Sensor & Utility Nodes

### Dell OptiPlex 7040 Micro — Security Onion Sensor (Planned)

**Specs:** Intel i5-6500T @ 2.50GHz | 16GB RAM

**Role:** Network detection and packet visibility layer

**Justification:** Network-based detection requires a dedicated sensor positioned to capture traffic between lab zones without impacting endpoint or server performance. The OptiPlex 7040 Micro is earmarked for Security Onion, running Zeek for traffic metadata and Suricata for intrusion detection. This completes the three-layer detection architecture: endpoint (Wazuh agents), log aggregation (Splunk on T490), and network (Security Onion). The i5-6500T desktop-class processor provides stable sustained performance suitable for continuous packet analysis.

**Primary Skills Demonstrated (Planned):**
- Network traffic analysis (Zeek)
- Intrusion detection (Suricata)
- Security Onion deployment and tuning
- Multi-layer detection architecture

---

### Raspberry Pi 500 — Lightweight Utility Node

**Specs:** ARM SoC | 8GB RAM

**Role:** Lightweight services, automation, and experimentation

**Justification:** Low-power utility systems are common in enterprise environments for DNS, scripting, and lightweight sensor tasks. The Pi 500 handles small services, automation scripts, and Linux experimentation without consuming resources on primary lab machines.

**Primary Skills Demonstrated:**
- Linux administration
- Lightweight service deployment
- Scripting and automation

---

## Architecture Flow

```
Attacker (Dell Latitude 5411 — Purple Team / i7-10850H)
Kali Tools (Dell Latitude 7480 — Offensive Tooling / i7-6600U)
         ↓
  Victim Endpoints (Proxmox VMs on Dell Latitude 5400)
         ↓
pfSense Firewall (Dell OptiPlex 5050 — Network Edge)
         ↓
  Core Services (AD + Wazuh on Dell Latitude 5400 Proxmox)
         ↓
  Log Aggregation (Splunk on ThinkPad T490)
         ↓
Analysis Layer (Lenovo IdeaPad — Primary SOC Workstation)
```

**Future addition:** Dell OptiPlex 7040 Micro (Security Onion) will sit inline on the network to capture traffic between zones, completing the network visibility layer.

---

## Hardware Performance Tiers

| Tier | Machine | CPU | RAM | Role |
|---|---|---|---|---|
| 1 — Heavy Compute | Lenovo IdeaPad | Ryzen 7 5700U | 40GB | SOC Analyst Workstation |
| 1 — Heavy Compute | Dell Latitude 5411 | i7-10850H | 32GB | Purple Team |
| 2 — Core Infrastructure | Dell Latitude 5400 | i5-8365U | 32GB | Proxmox Host |
| 2 — Core Infrastructure | ThinkPad T490 | i7-8665U | 24GB | Splunk SIEM |
| 3 — Specialized Services | Dell OptiPlex 5050 | i5-6500T | 16GB | pfSense Firewall |
| 3 — Specialized Services | Dell Latitude 7480 | i7-6600U | 16GB | Kali Linux |
| 4 — Sensors / Lightweight | Dell OptiPlex 7040 | i5-6500T | 16GB | Security Onion (Planned) |
| 4 — Sensors / Lightweight | Raspberry Pi 500 | ARM | 8GB | Utility Node |

---

## Key Design Principles

- **Separation of duties** — Each machine has a defined role. No system serves multiple conflicting functions.
- **Physical firewall appliance** — pfSense on dedicated hardware mirrors enterprise network architecture and eliminates hypervisor dependency for security enforcement.
- **Dedicated SIEM node** — Splunk on isolated hardware with a quad-core processor ensures consistent log ingestion performance independent of VM load.
- **Analyst isolation** — Workstations are physically separate from infrastructure and attack simulation systems.
- **Dual offensive platforms** — Separate machines for purple team operations and Kali tooling mirrors real red team environments.
- **Scalable design** — The architecture supports adding Security Onion, additional victim VMs, and future tooling without restructuring the core layout.

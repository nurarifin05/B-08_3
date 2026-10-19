# AV-03 Malware Infection & Remediation (EDR-centric)

**OS:** Windows 11 / PowerShell 5.1. **EDR:** SentinelOne during development; ESET planned for final deployment. **No other VM required** for development evidence. **Duration:** 45–60 min.

## Safety and operational prerequisites

Use an isolated training VM, instructor approval, a hypervisor snapshot, and only the standard EICAR anti-malware test string. The test sample is not real malware. Do not disable Windows Defender/SentinelOne/ESET to make detections appear. A single EDR should be configured as intended. Scanning and quarantine results depend on deployed product, license, and policy.

The installer has no additional software dependency: Windows 11 includes PowerShell 5.1, .NET file hashing, CSV and JSON support. The SentinelOne or ESET agent and its management console must be installed and licensed separately. Sysmon is optional for supplemental endpoint process evidence, not required for the CTF.

## Deploy

1. Copy folder to `C:\CTF\AV03`; open Windows PowerShell **as Administrator** and `cd C:\CTF\AV03`.
2. `Set-ExecutionPolicy -Scope Process Bypass -Force`
3. `.\setup.ps1 -Action Install -EDRVendor SentinelOne`
4. `.\setup.ps1 -Action Status -EDRVendor SentinelOne`
5. Take a hypervisor snapshot. Install/connect the SentinelOne agent. Confirm endpoint online, scan/on-access policy, quarantine capabilities and console access. Do not assume all three write attempts result in detections.
6. `.\setup.ps1 -Action Preflight -EDRVendor SentinelOne`
7. Instructor only: `.\setup.ps1 -Action Trigger -EDRVendor SentinelOne` (creates THREE EICAR test-file write attempts at different paths).
8. On the EDR console, filter by hostname/time/run. Identify **actual** count of detected threats, response action, and any remaining active threats. If possible run an approved on-demand scan; record before/after.
9. `.\setup.ps1 -Action Verify -EDRVendor SentinelOne` compares NORMAL documents to baseline; does not fake an EDR scan.
10. `.\setup.ps1 -Action Reset -EDRVendor SentinelOne` removes only known lab test paths. Restore hypervisor snapshot between student sessions to ensure clean telemetry. Keep instructor evidence outside participant-accessible paths for formal assessment.

## Files

- `C:\CTF-Lab-AV03\Case\incident_ticket.txt`: incident narrative.
- `C:\CTF-Lab-AV03\Documents\`: normal documents, never delete.
- `C:\CTF-Lab-AV03\Intake\Finance`, `\Mail`, `\Archive`: EICAR sample destinations.
- `C:\CTF-Lab-AV03\Evidence\baseline_hashes.csv`: expected SHA-256 for NORMAL documents.
- `C:\CTF-Instructor\AV03-Evidence\AV03-...\expected_metadata.json`: instructor run context and sample metadata created BEFORE writes.
- `trigger_attempts.json`: OS write observations, **not** proof of EDR detection/remediation.

## Grading model

15 practice exercises with 100 practice points plus four independent final checkpoints with weights 20/25/25/30 (alternative assessment scheme; do not sum to 200). Final answers use actual EDR evidence: threat folder(s), number of detections (unique events/files per stated scope), actual action, and active threats remaining after remediation.

**Vendor-neutral caveat:** menu names vary by SentinelOne console version and ESET PROTECT version; use the closest endpoint/threat/detection/action views. EDR may not expose SHA-256 for every event; use authorized export and instructor metadata for correlation. No automatic vendor API integration is included.

## Trouble-shooting

- No EDR alert: check online status, policy, exclusions, notifications and on-access detection; do not declare the sample infected merely from metadata.
- File absent: the file may have been blocked on write, quarantined, deleted or otherwise removed; inspect real action log.
- Repeated Trigger: each run is uniquely identified; only compare events from the chosen time window and host.
- Zero detections on follow-up scan: possible even after successful on-access protection; distinguish cumulative detection count from active threats remaining.
- Normal document hash mismatch: investigate accidental modification and restore snapshot, never treat as successful remediation.

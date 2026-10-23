# AV03 - Finance Department Security Incident

**Windows 11 VM / Proxmox / ESET HOME Essential + OBS Studio**

1. `Set-ExecutionPolicy -Scope Process Bypass -Force`
2. `.\setup.ps1 -Action Install` (baseline only; EICAR not created)
3. Install/activate/update ESET Internet Security and install OBS Studio. In OBS, add Color Source and Start Virtual Camera.
4. `.\setup.ps1 -Action Preflight`
5. `.\setup.ps1 -Action RunScenario -ConfirmTest`
6. Investigate five modules, run `.\setup.ps1 -Action Verify`, complete 15 MC and submit five flags to LMS.

For webcam-only testing: `.\setup.ps1 -Action Trigger -Module Webcam -ConfirmTest`. CSV/log at `C:\CTF-Lab-AV03\Webcam`. Source `SYNTHETIC_CTF` means *not ESET data*.

**Safety and acceptance:** EICAR is an antivirus test file. HIPS synthetic events, webcam synthetic logs and web test plans are not vendor detections. OBS must be accessed by a client and blocked by ESET for actual webcam SOW evidence. Keep instructor package off student VM.

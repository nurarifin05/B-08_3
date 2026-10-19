# AV-03 Malware Infection & Remediation — benign EICAR test lab only
# Windows PowerShell 5.1; run elevated. No EDR bypass, no disabling protections.
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Preflight','Trigger','Verify','Reset')][string]$Action='Status',
 [ValidateSet('SentinelOne','ESET','Other')][string]$EDRVendor='SentinelOne',
 [string]$EvidenceExportPath='C:\CTF-Instructor\AV03-Evidence'
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$Root='C:\CTF-Lab-AV03'
$Normal=Join-Path $Root 'Documents'
$Threat=Join-Path $Root 'Intake'
$Evidence=Join-Path $Root 'Evidence'
$Ticket=Join-Path $Root 'Case\incident_ticket.txt'
$Marker=Join-Path $Evidence 'baseline_hashes.csv'
$Trials=@(
 @{Name='invoice_2026.com';Rel='Intake\Finance'},
 @{Name='shipping_notice.com';Rel='Intake\Mail'},
 @{Name='archive_review.com';Rel='Intake\Archive'}
)
function Say([string]$msg){Write-Host "[AV03] $msg"}
function Assert-Admin {
 $id=[Security.Principal.WindowsIdentity]::GetCurrent()
 $p=New-Object Security.Principal.WindowsPrincipal($id)
 if(-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Run PowerShell as Administrator.'}
}
function Save-Json($obj,[string]$path) {
 $obj | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
}
function Get-Digest([string]$p){(Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash}
function Get-EicarBytes {
 # Build only at trigger time to avoid creating a detector artefact during Install.
 $parts=@('X5O!P%@AP[4\PZX54(P^)7CC)7}$','EICAR-STANDARD-ANTIVIRUS-TEST-FILE!','$H+H*')
 $text=($parts -join '')
 $b=[Text.Encoding]::ASCII.GetBytes($text)
 if($b.Length -ne 68){throw "Unexpected EICAR sample length: $($b.Length)"}
 return ,$b
}
function Get-HashFromBytes([byte[]]$bytes){
 $sha=[Security.Cryptography.SHA256]::Create()
 try { return (([BitConverter]::ToString($sha.ComputeHash($bytes))) -replace '-','') } finally {$sha.Dispose()}
}
function Install-Lab {
 Assert-Admin
 foreach($p in @($Normal,$Threat,$Evidence,(Split-Path $Ticket),$EvidenceExportPath)) {New-Item -ItemType Directory -Force -Path $p | Out-Null}
 $docs=@{
   'academic_schedule.txt'="Jadwal kegiatan taruna - data latihan AV03.`r`n";
   'student_contacts.csv'="student_id,contact`r`nT001,dummy@example.invalid`r`n";
   'faculty_notes.txt'="Catatan staf yang harus dipertahankan saat remediation.`r`n"
 }
 foreach($name in $docs.Keys){$p=Join-Path $Normal $name;if(-not(Test-Path $p)){[IO.File]::WriteAllText($p,$docs[$name],[Text.Encoding]::UTF8)}}
 $baseline=Get-ChildItem -LiteralPath $Normal -File | ForEach-Object {[pscustomobject]@{Name=$_.Name;Path=$_.FullName;SHA256=(Get-Digest $_.FullName);Length=$_.Length}}
 if(-not(Test-Path $Marker)){$baseline | Export-Csv -LiteralPath $Marker -NoTypeInformation -Encoding UTF8}
 @"
Incident AV03 — Malware Infection & Remediation
Host: $env:COMPUTERNAME
Scope: C:\CTF-Lab-AV03\Intake (training files only)
Normal user documents: C:\CTF-Lab-AV03\Documents (DO NOT DELETE)
EDR used in development: $EDRVendor (ESET planned later)
Task: correlate actual EDR detections, remediation action, and baseline hashes.
Alert count is NEVER assumed from the number of test-file write attempts.
"@ | Set-Content -LiteralPath $Ticket -Encoding UTF8
 Say 'Baseline installed. No EICAR test file has been created.'
 Say "Protected document baseline: $Marker"
 Say 'Take hypervisor snapshot now before Trigger.'
}
function Test-Preflight {
 Say "EDR vendor label: $EDRVendor (not an agent installer)."
 $hits=Get-Service | Where-Object {$_.Name -match 'Sentinel|ESET|ERA|ekrn|EraAgent|s1' -or $_.DisplayName -match 'SentinelOne|ESET'} | Select-Object Name,DisplayName,Status
 if($hits){$hits | Format-Table -AutoSize} else {Say 'No recognized EDR Windows service found; inspect EDR console manually.'}
 Say 'Instructor must confirm agent ONLINE and policy allows EICAR testing.'
}
function Trigger-Lab {
 Assert-Admin
 if(-not(Test-Path $Marker)){throw 'Run -Action Install first.'}
 New-Item -ItemType Directory -Force -Path $EvidenceExportPath | Out-Null
 $runId='AV03-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+([guid]::NewGuid().ToString('N').Substring(0,6))
 $dest=Join-Path $EvidenceExportPath $runId
 New-Item -Path $dest -ItemType Directory -Force | Out-Null
 $bytes=Get-EicarBytes
 $sha=Get-HashFromBytes $bytes
 $plan=@($Trials | ForEach-Object {
  [pscustomobject]@{Name=$_.Name;Path=(Join-Path $Root ($_.Rel+'\'+$_.Name));SHA256=$sha;Type='EICAR training test';ExpectedBytes=68}
 })
 # Write metadata outside Intake BEFORE any test sample; local instructor storage is not tamper-proof.
 Save-Json ([pscustomobject]@{RunId=$runId;UTC=(Get-Date).ToUniversalTime().ToString('o');Host=$env:COMPUTERNAME;Vendor=$EDRVendor;Expected=$plan;Note='Write attempts are NOT EDR detection or quarantine evidence.'}) (Join-Path $dest 'expected_metadata.json')
 Copy-Item -LiteralPath $Marker -Destination (Join-Path $dest 'baseline_hashes.csv') -Force
 $attempts=New-Object System.Collections.ArrayList
 foreach($i in $plan){
  New-Item -ItemType Directory -Path (Split-Path $i.Path) -Force | Out-Null
  $status='UNKNOWN';$err=''
  try {
   [IO.File]::WriteAllBytes($i.Path,$bytes)
   if(Test-Path -LiteralPath $i.Path){$status='WRITE_SUCCEEDED_AT_CHECK'}else{$status='NOT_PRESENT_AFTER_WRITE'}
  } catch {$status='WRITE_FAILED_OR_BLOCKED';$err=$_.Exception.Message}
  [void]$attempts.Add([pscustomobject]@{File=$i.Name;Path=$i.Path;SHA256=$sha;UTC=(Get-Date).ToUniversalTime().ToString('o');WriteObservation=$status;Error=$err})
  Say "$($i.Name): $status"
 }
 Save-Json ([pscustomobject]@{RunId=$runId;Attempts=@($attempts);Important='Use actual console EDR events to determine detection count and remediation status.'}) (Join-Path $dest 'trigger_attempts.json')
 Set-Content -LiteralPath (Join-Path $Evidence 'latest_run_id.txt') -Value $runId -Encoding ASCII
 Say "RunId: $runId"
 Say "Instructor metadata: $dest"
 Say 'Check real detections/actions in SentinelOne or ESET console. NEVER disable AV to force sample creation.'
}
function Verify-Lab {
 if(-not(Test-Path $Marker)){throw 'Baseline missing. Run Install.'}
 $base=@(Import-Csv -LiteralPath $Marker)
 $result=@(foreach($row in $base){
   $exists=Test-Path -LiteralPath $row.Path -PathType Leaf
   $actual=if($exists){Get-Digest $row.Path}else{''}
   [pscustomobject]@{Name=$row.Name;Exists=$exists;HashMatches=($exists -and $actual -eq $row.SHA256);Path=$row.Path}
 })
 $result | Format-Table -AutoSize
 if(@($result|Where-Object {-not $_.HashMatches}).Count -gt 0){Say 'FAIL: A normal document is missing or changed.'}else{Say 'PASS: All normal documents match baseline.'}
 Say 'EDR active-threat count and response action must be assessed separately in the vendor console.'
}
function Status-Lab {
 Say "Vendor selected: $EDRVendor"
 foreach($p in @($Root,$Ticket,$Marker,$EvidenceExportPath)){Say ("{0}: {1}" -f $p,(Test-Path $p))}
 if(Test-Path $Marker){Verify-Lab}
}
function Reset-Lab {
 Assert-Admin
 Say 'Reset removes ONLY specific lab test artefacts in Intake and preserves normal documents.'
 foreach($entry in $Trials){$p=Join-Path $Root ($entry.Rel+'\'+$entry.Name);if(Test-Path $p){Remove-Item -LiteralPath $p -Force -ErrorAction Stop}}
 Say 'EDR history and quarantined items are not erased. Restore snapshot for a clean rerun.'
}
switch($Action){
 'Install'{Install-Lab}
 'Status'{Status-Lab}
 'Preflight'{Test-Preflight}
 'Trigger'{Trigger-Lab}
 'Verify'{Verify-Lab}
 'Reset'{Reset-Lab}
}

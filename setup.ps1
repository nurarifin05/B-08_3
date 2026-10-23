#requires -Version 5.1
<# AV03 ESET HOME Essential - OBS hybrid LMS edition.
   Only EICAR (safe standardized antivirus test pattern) is used. No ESET settings are modified.
   No LMS flags, answers or instructor secrets are stored here.
#>
[CmdletBinding()]
param(
 [ValidateSet('Install','Status','Preflight','Trigger','RunScenario','Verify','Reset')][string]$Action='Status',
 [ValidateSet('All','Malware','HIPS','Scan','Webcam','Web')][string]$Module='All',
 [switch]$ConfirmTest,
 [switch]$LaunchInteractiveTests
)
$ErrorActionPreference='Stop'
$Lab='C:\CTF-Lab-AV03'
$Ev=Join-Path $Lab 'Evidence'
$Incident='INC-FIN-083'
function Info([string]$x){Write-Host "[AV03] $x"}
function Dir([string]$p){if(!(Test-Path -LiteralPath $p)){New-Item -ItemType Directory -Path $p -Force | Out-Null}}
function J([string]$name,$data){Dir $Ev; $data|ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $Ev $name) -Encoding UTF8}
function Event([string]$module,[string]$kind,[string]$message){
 Dir $Ev
 [pscustomobject]@{timestamp_utc=(Get-Date).ToUniversalTime().ToString('o');incident=$Incident;module=$module;event=$kind;details=$message} |
 ConvertTo-Json -Compress | Add-Content -LiteralPath (Join-Path $Ev 'lab_activity.jsonl') -Encoding UTF8
}
function EicarBytes {
 $chunks=@('X5O!P%@AP[4\PZX54(P^)7CC)7}', '$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!', '$H+H*')
 [Text.Encoding]::ASCII.GetBytes(($chunks -join ''))
}
function Metadata([string]$module,[string]$path){
 $bytes=EicarBytes; $sha=[Security.Cryptography.SHA256]::Create()
 try{$hash=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
 $v=[pscustomobject]@{incident=$Incident;module=$module;filename=[IO.Path]::GetFileName($path);path=$path;size_bytes=$bytes.Length;sha256=$hash;timestamp_utc=(Get-Date).ToUniversalTime().ToString('o');description='Metadata reference, not proof of ESET detection'}
 J "reference_$($module.ToLowerInvariant()).json" $v
 return $bytes
}
function InstallLab {
 foreach($d in @('Case','SharedFiles','Documents','Intake','Evidence','Training','Webcam')){Dir (Join-Path $Lab $d)}
 $ticket=Join-Path $Lab 'Case\incident_ticket.txt'
 if(!(Test-Path $ticket)){
 @"
Ticket: $Incident
Case: Finance Department Security Incident
Akun dummy; hanya mesin laboratorium.
Petugas keuangan menerima lampiran invoice mencurigakan, lalu mencatat perubahan perilaku workstation.
Tugas: audit real-time detection, HIPS, on-demand scanning, webcam control dan web protection.
File uji EICAR dibuat oleh Trigger SETELAH ESET siap.
"@ | Set-Content -LiteralPath $ticket -Encoding UTF8
 }
 foreach($item in @('payment_register.csv','budget_review.txt')){
  $p=Join-Path $Lab "Documents\$item"
  if(!(Test-Path $p)){"Dokumen latihan AV03: $item"|Set-Content -LiteralPath $p -Encoding UTF8}
 }
 $baseline=Join-Path $Ev 'baseline_hashes.csv'
 if(!(Test-Path $baseline)){
  Get-ChildItem (Join-Path $Lab 'Documents') -File | ForEach-Object {
   [pscustomobject]@{Name=$_.Name;Path=$_.FullName;SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
  } | Export-Csv -LiteralPath $baseline -NoTypeInformation -Encoding UTF8
 }
 Info "Installed lab baseline in $Lab; EICAR not created."
}
function GetCameraCandidates {
 # Get-PnpDevice can return a camera under Camera, Image or Media class.
 try {
  return @(Get-PnpDevice -ErrorAction Stop | Where-Object {
   $_.FriendlyName -match '(?i)OBS Virtual Camera|webcam|camera' -or
   ($_.Class -in @('Camera','Image') -and $_.Status -eq 'OK')
  })
 } catch {
  Info 'PnP inventory unavailable; inspect Windows Device Manager manually.'
  return @()
 }
}
function Preflight {
 Info "Host: $env:COMPUTERNAME | Windows: $([Environment]::OSVersion.VersionString)"
 $svc=@(Get-Service -ErrorAction SilentlyContinue | Where-Object {$_.DisplayName -match 'ESET' -or $_.Name -match '^ekrn$'})
 if($svc.Count){$svc|Select-Object Name,Status,DisplayName|Format-Table -AutoSize|Out-Host}else{Info 'ESET service not identified; confirm ESET installation in GUI.'}
 $cameras=@(GetCameraCandidates)
 if($cameras.Count){$cameras|Select-Object FriendlyName,Class,Status|Format-Table -AutoSize|Out-Host}else{Info 'No camera in PnP inventory. OBS Virtual Camera might not be installed or registered.'}
 $obs=@($cameras|Where-Object {$_.FriendlyName -match '(?i)OBS Virtual Camera'})
 if($obs.Count){Info 'OBS Virtual Camera device is listed. This does NOT prove streaming, access attempts or ESET blocking.'}
 else{Info 'OBS Virtual Camera not found. Install OBS Studio, start Virtual Camera, and verify in an approved client.'}
 Info 'Check ESET GUI: licensed/up-to-date, Real-time, HIPS, Webcam Protection, Web Protection.'
}
function NewWebcamTrainingEvidence {
 $dir=Join-Path $Lab 'Webcam'
 Dir $dir
 $time=(Get-Date).ToUniversalTime()
 $start=$time.AddMinutes(-4)
 $rows=@(
  [pscustomobject]@{TimestampUtc=$start.ToString('o');Application='MeetingCamera.exe';ProcessId=4120;Device='OBS Virtual Camera';Event='ACCESS_REQUESTED';Decision='';Rule='ApprovedAV03Camera';Source='SYNTHETIC_CTF'}
  [pscustomobject]@{TimestampUtc=$start.AddSeconds(1).ToString('o');Application='MeetingCamera.exe';ProcessId=4120;Device='OBS Virtual Camera';Event='ACCESS_DECISION';Decision='ALLOW';Rule='ApprovedAV03Camera';Source='SYNTHETIC_CTF'}
  [pscustomobject]@{TimestampUtc=$start.AddMinutes(2).ToString('o');Application='InvoiceAuditHelper.exe';ProcessId=6648;Device='OBS Virtual Camera';Event='ACCESS_REQUESTED';Decision='';Rule='BlockFinanceCameraAccess';Source='SYNTHETIC_CTF'}
  [pscustomobject]@{TimestampUtc=$start.AddMinutes(2).AddSeconds(1).ToString('o');Application='InvoiceAuditHelper.exe';ProcessId=6648;Device='OBS Virtual Camera';Event='ACCESS_DECISION';Decision='DENY';Rule='BlockFinanceCameraAccess';Source='SYNTHETIC_CTF'}
  [pscustomobject]@{TimestampUtc=$start.AddMinutes(3).ToString('o');Application='MeetingCamera.exe';ProcessId=4120;Device='OBS Virtual Camera';Event='ACCESS_DECISION';Decision='ALLOW';Rule='ApprovedAV03Camera';Source='SYNTHETIC_CTF'}
 )
 $csv=Join-Path $dir 'webcam_access_training.csv'
 $rows|Export-Csv -LiteralPath $csv -NoTypeInformation -Encoding UTF8
 $lines=@('SIMULATED LAB LOG - NOT AN ESET LOG - NO CAMERA ACCESS WAS ATTEMPTED BY THIS SCRIPT')
 $lines+=@($rows|ForEach-Object{"$($_.TimestampUtc) | $($_.Application) | $($_.Event) | $($_.Decision) | $($_.Rule) | $($_.Source)"})
 $lines|Set-Content -LiteralPath (Join-Path $dir 'webcam_access_training.log') -Encoding UTF8
 @'
AV03 WEBCAM FORENSIC PRACTICE - SYNTHETIC EVENTS
Analyze webcam_access_training.csv, sort by TimestampUtc, then determine:
- Which application is unapproved?
- Which event records the attempted access?
- Which decision follows for that application?
These records are created by setup.ps1; they are not produced by ESET.
For a real acceptance test, run OBS Virtual Camera, open an approved camera client,
set ESET Webcam Protection to ask/block for that client, and verify blocked streaming.
A missing ESET alert does not mean that blocking occurred.
'@ | Set-Content -LiteralPath (Join-Path $dir 'README_SIMULATION_ONLY.txt') -Encoding UTF8
 J 'webcam_test_plan.json' ([pscustomobject]@{
  scenario='AV03';camera='OBS Virtual Camera';training_log=$csv;
  training_log_source='SYNTHETIC_CTF';eset_real_block_verified=$false;
  evidence_needed='ESET Webcam Protection notification/rule AND client stream denied in a controlled test';
  user_note='SYNTHETIC access deny is not proof of ESET Webcam Protection.'
 })
 Event 'Webcam' 'SYNTHETIC_LOG_CREATED' 'Training-only camera access events generated. No camera API invoked by script.'
 Info "Webcam: SYNTHETIC training log ready: $csv"
 Info 'To prove ESET webcam blocking: OBS Start Virtual Camera -> camera client requests it -> ESET Block rule -> retry client.'
 if($LaunchInteractiveTests){
  try{Start-Process 'ms-camera:'; Info 'Windows Camera app launched if supported; select OBS camera when available.'}
  catch{Info 'Windows Camera app unavailable. Use an approved browser/app camera test.'}
 }
}

function MakeEicar([string]$module,[string]$path){
 $bytes=Metadata $module $path # evidence before write
 try {
  [IO.File]::WriteAllBytes($path,$bytes)
  Event $module 'WRITE_RETURNED' "Path=$path; verify ESET Detection Log"
  Info "$module: file write returned; inspect ESET logs and current file state."
 } catch {
  Event $module 'WRITE_FAILED_OR_BLOCKED' $_.Exception.Message
  Info "$module: file write did not complete ($($_.Exception.Message)); check ESET event for cause."
 }
}
function TriggerOne([string]$m){
 if(!$ConfirmTest){throw 'Add -ConfirmTest only after ESET installed and instructor-approved test.'}
 if(!(Test-Path $Lab)){throw 'Run -Action Install first.'}
 switch($m){
  'Malware' {MakeEicar 'Malware' (Join-Path $Lab 'SharedFiles\invoice_payment_notice.com')}
  'Scan' {MakeEicar 'Scan' (Join-Path $Lab 'Intake\archive_receipt_review.com');Info 'Run ESET custom scan on C:\CTF-Lab-AV03\Intake; file may already be blocked by real-time.'}
  'HIPS' {
   $key='HKCU:\Software\CTF-Lab-AV03';Dir $Ev
   if(!(Test-Path $key)){New-Item -Path $key -Force|Out-Null}
   New-ItemProperty -Path $key -Name 'InvoiceAuditHelper' -Value 'BENIGN_TRAINING_MARKER' -PropertyType String -Force | Out-Null
   & "$env:windir\System32\cmd.exe" /c whoami | Out-Null
   Event 'HIPS' 'BENIGN_REGISTRY_AND_PROCESS' "Registry $key\InvoiceAuditHelper; cmd.exe whoami"
   Info 'HIPS: benign registry marker + cmd.exe launched. No ESET block claimed. Review actual HIPS rule/log.'
  }
  'Webcam' {NewWebcamTrainingEvidence}
  'Web' {
   J 'web_test_plan.json' ([pscustomobject]@{official_url='https://www.amtso.org/security-features-check/';simulation_only=$true;observed_block=$null})
   Event 'Web' 'PLAN_ONLY' 'No automatic anti-phishing alert asserted.'
   Info 'Web: official AMTSO test instructions prepared; browser and ESET log required.'
   if($LaunchInteractiveTests){Start-Process 'https://www.amtso.org/security-features-check/'}
  }
 }
}
function Verify {
 $ref=Join-Path $Ev 'baseline_hashes.csv'; if(!(Test-Path $ref)){throw 'Baseline missing.'}
 $errors=@()
 foreach($row in @(Import-Csv -LiteralPath $ref)){
  if(!(Test-Path -LiteralPath $row.Path)){$errors+="Missing $($row.Name)";continue}
  if((Get-FileHash -LiteralPath $row.Path -Algorithm SHA256).Hash -ne $row.SHA256){$errors+="Changed $($row.Name)"}
 }
 if($errors.Count){$errors|ForEach-Object{Info "FAIL $_"};throw 'Normal document integrity failed.'}
 Info 'PASS: normal documents match baseline.'
 Info 'ESET verdicts must be independently inspected in application Logs, Quarantine, HIPS/Webcam/Web pages.'
}
function Reset {
 $key='HKCU:\Software\CTF-Lab-AV03'
 if(Test-Path $key){Remove-Item -Path $key -Recurse -Force}
 Info 'HIPS training marker removed. ESET logs/quarantine NOT cleared. Restore VM snapshot to repeat cleanly.'
}
switch($Action){
 'Install'{InstallLab}
 'Status'{Info "Case $Incident | Baseline: $(Test-Path $Lab)";Preflight}
 'Preflight'{Preflight}
 'Trigger'{if($Module -eq 'All'){@('Malware','HIPS','Scan','Webcam','Web')|ForEach-Object{TriggerOne $_}}else{TriggerOne $Module}}
 'RunScenario'{@('Malware','HIPS','Scan','Webcam','Web')|ForEach-Object{TriggerOne $_}}
 'Verify'{Verify}
 'Reset'{Reset}
}

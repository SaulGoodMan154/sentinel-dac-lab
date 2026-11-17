<#
.SYNOPSIS
    Automated Safe Adversary Simulation Runner for Sentinel Detection-as-Code Lab.

.DESCRIPTION
    Safely executes endpoint attack emulation techniques mapped to Microsoft Sentinel analytics rules:
    - T1110.001 (Failed Logons / Brute Force)
    - T1110.003 (Password Spraying)
    - T1059.001 / T1027 (Encoded PowerShell)
    - T1098 (Local Privileged Group Addition)
    - T1053.005 (Scheduled Task Creation)
    - T1543.003 (Suspicious Service Creation)
    - T1485 (Mass File Deletion in isolated sandbox)
    - T1105 / T1218 (LOLBins: certutil & mshta)

    Includes automatic safety checks, isolated sandbox paths, and cleanup routines.

.EXAMPLE
    .\run_all_safe.ps1 -LabConfirm
#>

[CmdletBinding()]
param(
    [switch]$LabConfirm
)

$ErrorActionPreference = "Continue"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host " Sentinel Detection-as-Code Safe Emulation Runner" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan

if (-not $LabConfirm) {
    Write-Warning "This script executes simulated adversary behaviors to trigger SIEM detections."
    Write-Warning "Ensure you are running this ONLY on a dedicated lab machine / VM."
    $response = Read-Host "Are you sure you want to proceed? (Type 'YES' to continue)"
    if ($response -ne "YES") {
        Write-Host "Simulation aborted by user." -ForegroundColor Yellow
        exit 0
    }
}

$startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "[+] Simulation sequence started at: $startTime (UTC: $((Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')))" -ForegroundColor Green

# ---------------------------------------------------------------------
# Test 1: T1110.001 - Brute Force (Event 4625)
# ---------------------------------------------------------------------
Write-Host "`n[1/7] Emulating Windows Brute Force (T1110.001)..." -ForegroundColor Yellow
1..7 | ForEach-Object {
    net use \\127.0.0.1\IPC$ /user:LabTargetUser WrongPassword123! 2>$null
    Start-Sleep -Milliseconds 200
}
net use \\127.0.0.1\IPC$ /delete /y 2>$null
Write-Host "  -> Generated 7 failed logons on target account 'LabTargetUser'." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 2: T1110.003 - Password Spraying (Event 4625)
# ---------------------------------------------------------------------
Write-Host "`n[2/7] Emulating Password Spray (T1110.003)..." -ForegroundColor Yellow
$sprayUsers = @("SprayUser1", "SprayUser2", "SprayUser3", "SprayUser4", "SprayUser5", "SprayUser6")
foreach ($user in $sprayUsers) {
    net use \\127.0.0.1\IPC$ /user:$user Season2026Password! 2>$null
    Start-Sleep -Milliseconds 200
}
net use \\127.0.0.1\IPC$ /delete /y 2>$null
Write-Host "  -> Sprayed 6 distinct usernames with common password." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 3: T1059.001 / T1027 - Encoded PowerShell Execution (Event 4688)
# ---------------------------------------------------------------------
Write-Host "`n[3/7] Emulating Encoded PowerShell Command (T1059.001 / T1027)..." -ForegroundColor Yellow
$encodedCommand = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host "Sentinel Lab Test"'))
powershell.exe -NoProfile -NonInteractive -EncodedCommand $encodedCommand
Write-Host "  -> Executed base64 encoded PowerShell payload." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 4: T1098 - Privileged Local Group Member Add (Event 4732)
# ---------------------------------------------------------------------
Write-Host "`n[4/7] Emulating Local Privileged Group Member Add (T1098)..." -ForegroundColor Yellow
net user LabSimUser Pass@123456789! /add 2>$null
net localgroup Administrators LabSimUser /add 2>$null
Start-Sleep -Seconds 2
# Clean up
net localgroup Administrators LabSimUser /delete 2>$null
net user LabSimUser /delete 2>$null
Write-Host "  -> Created temporary user, added to Administrators, and cleaned up." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 5: T1053.005 - Suspicious Scheduled Task (Event 4698)
# ---------------------------------------------------------------------
Write-Host "`n[5/7] Emulating Suspicious Scheduled Task Creation (T1053.005)..." -ForegroundColor Yellow
schtasks.exe /create /tn "SecurityLabSimTask" /tr "powershell.exe -WindowStyle Hidden -Command Write-Host 'sim'" /sc daily /st 09:00 /f 2>$null
Start-Sleep -Seconds 2
schtasks.exe /delete /tn "SecurityLabSimTask" /f 2>$null
Write-Host "  -> Registered scheduled task invoking PowerShell and removed it." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 6: T1543.003 - Suspicious Windows Service Creation (System 7045)
# ---------------------------------------------------------------------
Write-Host "`n[6/7] Emulating Suspicious Service Installation (T1543.003)..." -ForegroundColor Yellow
sc.exe create "LabSimService" binpath= "C:\Windows\Temp\mock_service.exe" start= auto 2>$null
Start-Sleep -Seconds 2
sc.exe delete "LabSimService" 2>$null
Write-Host "  -> Created temporary service referencing Temp path and deleted." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Test 7: T1485 - Mass File Deletion in Sandbox (Sysmon 23/26)
# ---------------------------------------------------------------------
Write-Host "`n[7/7] Emulating Mass File Deletion / Wiper Behavior (T1485)..." -ForegroundColor Yellow
$sandboxDir = "$env:TEMP\SentinelLabRansomwareSandbox"
New-Item -ItemType Directory -Force -Path $sandboxDir | Out-Null
1..35 | ForEach-Object {
    "Lab canary data for file $_" | Out-File "$sandboxDir\canary_$_.txt" -Encoding utf8
}
Start-Sleep -Seconds 1
Get-ChildItem -Path $sandboxDir -Filter *.txt | Remove-Item -Force
Remove-Item -Recurse -Force $sandboxDir -ErrorAction SilentlyContinue
Write-Host "  -> Created and deleted 35 canary files in isolated sandbox." -ForegroundColor Gray

# ---------------------------------------------------------------------
# Bonus: T1105 / T1218 - LOLBins (Certutil & Mshta)
# ---------------------------------------------------------------------
Write-Host "`n[Bonus] Emulating LOLBins Activity (T1105 / T1218)..." -ForegroundColor Yellow
certutil.exe -urlcache -split -f "http://127.0.0.1/canary.txt" "$env:TEMP\canary.txt" 2>$null
Remove-Item "$env:TEMP\canary.txt" -Force -ErrorAction SilentlyContinue
mshta.exe javascript:close()
Write-Host "  -> Triggered certutil urlcache and mshta inline javascript." -ForegroundColor Gray

$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host " Simulation sequence completed at: $endTime" -ForegroundColor Green
Write-Host " Note: Allow 3 to 10 minutes for log ingestion in Microsoft Sentinel." -ForegroundColor Cyan
Write-Host " Query SecurityEvent, Event, and Sysmon tables to verify hits!" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan


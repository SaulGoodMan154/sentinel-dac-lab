# Atomic Red Team Simulation Mapping

This document maps each of the **15 Microsoft Sentinel Scheduled Analytics Rules** in this repository to adversary emulation commands and Atomic Red Team procedures.

> [!WARNING]
> Only execute these simulations inside an isolated lab virtual machine (e.g., Azure Arc connected VM or dedicated Hyper-V/VirtualBox instance). Never run attack emulation commands on production systems or personal workstations.

---

## Simulation Matrix

| # | Detection File | Technique ID | Technique Name | Emulation Method | Generated Event |
|---|---|---|---|---|---|
| 1 | `windows_bruteforce_4625.yaml` | T1110.001 | Password Guessing | Repeated failed net use logins | SecurityEvent 4625 |
| 2 | `password_spray_4625.yaml` | T1110.003 | Password Spraying | Multi-user credential probe | SecurityEvent 4625 |
| 3 | `entra_anomalous_signin.yaml` | T1078.004 | Cloud Accounts | Multi-region or proxy signin | SigninLogs |
| 4 | `encoded_powershell.yaml` | T1059.001 | PowerShell | Base64 encoded payload | SecurityEvent 4688 |
| 5 | `privileged_group_add.yaml` | T1098 | Account Manipulation | Local admin group member add | SecurityEvent 4728 / 4732 |
| 6 | `lsass_access_sysmon10.yaml` | T1003.001 | LSASS Memory Dumping | Process memory handle access | Sysmon Event ID 10 |
| 7 | `scheduled_task_4698.yaml` | T1053.005 | Scheduled Task | Schtasks creation with script | SecurityEvent 4698 |
| 8 | `suspicious_service_7045.yaml` | T1543.003 | Windows Service | Sc.exe creation from Temp | System Event ID 7045 |
| 9 | `mass_file_deletion_ransomware.yaml` | T1485 | Data Destruction | Rapid deletion of dummy test files | Sysmon Event ID 23 / 26 |
| 10 | `kerberoasting_4769.yaml` | T1558.003 | Kerberoasting | Requesting RC4 SPN ticket | SecurityEvent 4769 |
| 11 | `dcsync_4662.yaml` | T1003.006 | DCSync | Directory replication request | SecurityEvent 4662 |
| 12 | `lolbins_certutil_mshta_rundll32.yaml` | T1105 / T1218.005 / T1218.011 | Ingress Tool Transfer & LOLBins | Certutil urlcache & Mshta dummy | SecurityEvent 4688 |
| 13 | `azure_role_assignment_or_deletion.yaml` | T1098.003 / T1485 | Cloud Infrastructure | Azure RBAC role assignment | AzureActivity |
| 14 | `mfa_disabled_auditlogs.yaml` | T1556.006 | Modify Auth Process: MFA | Deleting auth method in Entra | AuditLogs |
| 15 | `defender_alert_correlation.yaml` | None (Correlation) | Multi-Alert Incident Aggregation | Correlating multiple alerts | SecurityAlert |

---

## Detailed Technique Procedures

### 1. Windows Brute Force (T1110.001)
* **Goal**: Trigger Event 4625 by generating > 5 failed logons on a single user.
* **PowerShell Command**:
  ```powershell
  1..8 | ForEach-Object {
      net use \\127.0.0.1\IPC$ /user:LabTargetUser WrongPassword123! 2>$null
  }
  ```
* **Cleanup**:
  ```powershell
  net use \\127.0.0.1\IPC$ /delete /y 2>$null
  ```

---

### 2. Password Spray (T1110.003)
* **Goal**: Horizontal spray targeting >= 5 distinct usernames with 1 attempt each.
* **PowerShell Command**:
  ```powershell
  $users = @("AlphaUser", "BravoUser", "CharlieUser", "DeltaUser", "EchoUser", "FoxtrotUser")
  foreach ($u in $users) {
      net use \\127.0.0.1\IPC$ /user:$u Summer2026! 2>$null
  }
  ```
* **Cleanup**:
  ```powershell
  net use \\127.0.0.1\IPC$ /delete /y 2>$null
  ```

---

### 3. Entra ID Anomalous Sign-in (T1078.004)
* **Goal**: Trigger an unfamiliar location or impossible travel signal in Entra ID SigninLogs.
* **Procedure**:
  1. Authenticate to `portal.azure.com` with a test cloud user account.
  2. Connect to an external VPN or Tor proxy node and immediately attempt sign-in to Microsoft 365 / Azure Portal.
  3. Alternatively, use PowerShell to trigger an interactive OAuth token request from an unusual IP.

---

### 4. Encoded PowerShell (T1059.001 / T1027)
* **Goal**: Execute a harmless PowerShell payload passed via `-EncodedCommand`.
* **PowerShell Command**:
  ```powershell
  $script = 'Write-Host "Sentinel Lab Emulation Safe Payload"'
  $bytes  = [System.Text.Encoding]::Unicode.GetBytes($script)
  $b64    = [System.Convert]::ToBase64String($bytes)
  powershell.exe -NoProfile -NonInteractive -EncodedCommand $b64
  ```

---

### 5. Privileged Group Membership Add (T1098 / T1078.002)
* **Goal**: Add a user account to the local Administrators group.
* **PowerShell Command**:
  ```powershell
  net user LabTestAccount TempPass#2026! /add
  net localgroup Administrators LabTestAccount /add
  ```
* **Cleanup**:
  ```powershell
  net localgroup Administrators LabTestAccount /delete
  net user LabTestAccount /delete
  ```

---

### 6. LSASS Memory Access (T1003.001)
* **Goal**: Trigger Sysmon Event ID 10 with read access to `lsass.exe`.
* **Atomic Red Team Test**: `T1003.001` - Test #2 (Dump LSASS with rundll32 / comsvcs.dll)
* **PowerShell Command**:
  ```powershell
  # Safe emulation query targeting process handle without corrupting memory
  $lsass = Get-Process lsass
  rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump $lsass.Id C:\TestLab\lsass_dummy.dmp full
  ```
* **Cleanup**:
  ```powershell
  Remove-Item -Force C:\TestLab\lsass_dummy.dmp -ErrorAction SilentlyContinue
  ```

---

### 7. Suspicious Scheduled Task (T1053.005)
* **Goal**: Register a scheduled task launching a scripting engine from AppData or Temp.
* **Command**:
  ```cmd
  schtasks /create /tn "SecurityLabUpdater" /tr "powershell.exe -WindowStyle Hidden -Command Write-Host" /sc daily /st 09:00 /f
  ```
* **Cleanup**:
  ```cmd
  schtasks /delete /tn "SecurityLabUpdater" /f
  ```

---

### 8. Suspicious Windows Service (T1543.003)
* **Goal**: Install a service pointing to a binary in `C:\Windows\Temp`.
* **Command**:
  ```cmd
  sc create "LabVulnSvc" binpath= "C:\Windows\Temp\updater.exe" start= auto
  ```
* **Cleanup**:
  ```cmd
  sc delete "LabVulnSvc"
  ```

---

### 9. Mass File Deletion / Ransomware Simulation (T1486 / T1485)
* **Goal**: Trigger Sysmon 23/26 by rapidly creating and deleting > 35 dummy files in an isolated folder.
* **PowerShell Command**:
  ```powershell
  $testDir = "C:\TestLab\RansomwareSandbox"
  New-Item -ItemType Directory -Force -Path $testDir | Out-Null
  1..40 | ForEach-Object { "Canary Content $_" | Out-File "$testDir\file_$_.txt" }
  Start-Sleep -Seconds 2
  Get-ChildItem -Path $testDir -Filter *.txt | Remove-Item -Force
  ```
* **Cleanup**:
  ```powershell
  Remove-Item -Recurse -Force $testDir -ErrorAction SilentlyContinue
  ```

---

### 10. Kerberoasting (T1558.003)
* **Goal**: Request an RC4 ticket for an SPN in an Active Directory environment.
* **PowerShell Command**:
  ```powershell
  Add-Type -AssemblyName System.IdentityModel
  New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/lab-sql.domain.local:1433"
  ```

---

### 11. DCSync Emulation (T1003.006)
* **Goal**: Trigger Directory Replication rights query (Event 4662).
* **Command** (using DSInternals or Mimikatz inside test domain):
  ```powershell
  Get-ADReplAccount -DistinguishedName "CN=krbtgt,CN=Users,DC=lab,DC=local" -Server "DC01.lab.local"
  ```

---

### 12. LOLBins Execution (T1105 / T1218)
* **Goal**: Emulate certutil download and mshta inline protocol calls.
* **PowerShell Command**:
  ```powershell
  # Certutil safe download simulation (hits loopback or local file)
  certutil.exe -urlcache -split -f "http://127.0.0.1/test.txt" "$env:TEMP\certutil_test.txt" 2>$null

  # Mshta execution simulation
  mshta.exe javascript:close()
  ```
* **Cleanup**:
  ```powershell
  Remove-Item "$env:TEMP\certutil_test.txt" -Force -ErrorAction SilentlyContinue
  ```

---

### 13. Azure RBAC Role Assignment / Resource Deletion Spike (T1098.003 / T1485)
* **Goal**: Create role assignment or delete multiple test resource groups in Azure.
* **Azure CLI**:
  ```bash
  # Assign Reader role to a test identity
  az role assignment create --assignee "<test-sp-or-user-id>" --role "Reader" --scope "/subscriptions/<sub-id>"
  ```

---

### 14. MFA Disabled in Entra ID (T1556 / T1562)
* **Goal**: Trigger `AuditLogs` entry for authentication method modification.
* **Procedure**: In Microsoft Entra Admin Center, navigate to **Users** -> Test User -> **Authentication methods**, and delete an enrolled phone method or temporary access pass.

---

### 15. Defender Alert Correlation (T1071 / T1059)
* **Goal**: Trigger multiple Defender alerts on the same host to test incident aggregation.
* **Procedure**: Execute Defender test ground scripts (e.g., EICAR test string, simulated discovery scripts) or trigger Microsoft Defender for Endpoint automated test alerts.


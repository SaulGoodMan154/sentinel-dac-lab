# Microsoft Sentinel Detection-as-Code Lab Setup Guide

This guide walks you through building an industry-standard SOC lab for Microsoft Sentinel at **zero (or near-zero) cost**, configuring data ingestion with the modern **Azure Monitor Agent (AMA)**, installing Sysmon, and deploying the 15 Detection-as-Code analytics rules.

---

## 1. Cost Guards & Budget Setup ($0 Protection)

Before deploying any infrastructure:

1. **Set an Azure Budget:**
   * Go to **Cost Management + Billing** -> **Cost Management** -> **Budgets**.
   * Create a budget of **\$5.00** (or \$0.01 if using a trial).
   * Set alert notifications at 50%, 80%, and 100% sent to your email.
2. **Microsoft Sentinel Free Trial:**
   * When enabling Microsoft Sentinel on a newly created Log Analytics Workspace, the first **31 days are free** (up to 10 GB of data ingestion per day).

---

## 2. Choosing Your Target Endpoint (Cloud VM vs. Local VM)

Choose one of two options:

### Option A: 100% Free Local VM via Azure Arc (Recommended for $0 spend)
* Run a free Windows 10/11 or Windows Server evaluation VM on your physical computer using **Hyper-V** or **VirtualBox**.
* In the Azure Portal, search for **Azure Arc** -> **Machines** -> **Add machine**.
* Generate the installation script and run it inside your local VM.
* **Cost:** \$0 for Azure compute and \$0 for disks.

### Option B: Azure Cloud Virtual Machine
* Deploy a `Standard_B2s` (2 vCPU, 4 GiB RAM) running **Windows Server 2022 Datacenter: Azure Edition**.
* **CRITICAL:** In the VM configuration under **Management**, turn on **Auto-shutdown** (e.g., daily at 19:00 UTC).

---

## 3. Host Hardening & Sysmon Installation

Log in as Administrator on your target Windows VM (local or cloud) and perform these steps:

### A. Enable Process Creation Command-Line Auditing (Event 4688)
By default, Windows logs process creation (4688) but omits the full command line arguments!
1. Open PowerShell as Administrator and run:
   ```powershell
   # Enable Detailed Process Tracking
   auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable

   # Enable Process Command Line logging in Security Event 4688
   reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
   ```

### B. Install Sysmon with Filtered Config
1. Download **Sysmon** from Microsoft Sysinternals:
   ```powershell
   Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$env:TEMP\Sysmon.zip"
   Expand-Archive -Path "$env:TEMP\Sysmon.zip" -DestinationPath "C:\Tools\Sysmon" -Force
   ```
2. Download the battle-tested **SwiftOnSecurity Sysmon Config** (to avoid noisy log flooding):
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Tools\Sysmon\sysmonconfig.xml"
   ```
3. Install and start Sysmon:
   ```powershell
   cd C:\Tools\Sysmon
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
4. Verify Sysmon is running:
   ```powershell
   Get-Service Sysmon64
   ```

---

## 4. Azure Monitor Agent (AMA) & Data Collection Rules (DCR)

Microsoft Sentinel relies on **Azure Monitor Agent (AMA)** and **Data Collection Rules (DCR)** to stream logs into your Log Analytics Workspace.

### A. Create the Workspace & Enable Sentinel
1. In Azure Portal, search for **Log Analytics Workspaces** -> Click **Create**.
   * Name: `law-sentinel-dac-lab`
   * Region: Select your closest region (e.g., `East US`).
2. Search for **Microsoft Sentinel** -> Click **Add** -> Select `law-sentinel-dac-lab`.
   * Confirm the 31-day free trial banner is active.

### B. Configure Data Collection Rules (DCR) for Windows Events
1. In Sentinel, navigate to **Data Connectors** -> **Windows Security Events via AMA**.
2. Click **Open connector page** -> **+ Create data collection rule**:
   * **Rule Name:** `dcr-windows-security-events`
   * **Resources:** Select your VM (or Azure Arc machine).
   * **Collect:** Select **Common** or **Minimal**.
3. Under **Custom XPath** or filtered stream, ensure the following essential Event IDs are collected:
   ```xml
   Security!*[System[(EventID=4625 or EventID=4688 or EventID=4698 or EventID=4728 or EventID=4732 or EventID=4756 or EventID=4769 or EventID=4662)]]
   ```

### C. Ingest Sysmon Logs via DCR
1. Add a custom stream in the Data Collection Rule to collect the Sysmon channel:
   ```xml
   Microsoft-Windows-Sysmon/Operational!*
   ```
2. Ingest these records into the standard `Event` table.

---

## 5. Cloud Connectors (Entra ID & Azure Activity)

1. **Azure Activity Connector:**
   * In Sentinel -> **Data Connectors** -> **Azure Activity**.
   * Click **Open connector page** -> **Configure Azure Activity logs** -> Click your subscription -> Click **Connect**.
2. **Microsoft Entra ID (formerly Azure AD):**
   * In Sentinel -> **Data Connectors** -> **Microsoft Entra ID**.
   * Connect `SigninLogs` and `AuditLogs`.

---

## 6. Deploying Detection Rules as Code

You can deploy all 15 detection rules using the compiled ARM template:

### Method 1: Azure CLI (Fastest)
```bash
az deployment group create \
  --name "Deploy-Sentinel-Detections" \
  --resource-group "<your-resource-group>" \
  --template-file "./deploy/alertRules.arm.json" \
  --parameters workspace="law-sentinel-dac-lab"
```

### Method 2: Azure Portal Custom Template
1. In the Azure Portal search bar, type **Deploy a custom template**.
2. Click **Build your own template in the editor**.
3. Copy and paste the contents of [alertRules.arm.json](deploy/alertRules.arm.json).
4. Click **Save** -> select your Resource Group and Workspace Name -> Click **Review + create**.

---

## 7. Running Emulations & Verification

1. Inside your target VM, launch PowerShell as Administrator and run the safe simulation harness:
   ```powershell
   .\simulations\run_all_safe.ps1 -LabConfirm
   ```
2. Wait 5 to 10 minutes for log ingestion.
3. In Sentinel, open **Logs** and run verification queries:
   ```kql
   // Check brute force failures
   SecurityEvent
   | where EventID == 4625
   | summarize count() by TargetUserName

   // Check Sysmon activity
   Event
   | where Source == "Microsoft-Windows-Sysmon"
   | take 20
   ```
4. Navigate to **Microsoft Sentinel** -> **Incidents** to see your scheduled analytics rules generating incidents and entity mappings!


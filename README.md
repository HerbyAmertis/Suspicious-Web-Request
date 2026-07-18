# 🚨 **Incident Response Create Alert Rule (PowerShell Suspicious Web Request)** 🚨

![image (8)](https://github.com/user-attachments/assets/fc69fb91-2057-4728-9c16-7dcb20c01054)

## 🛡️ **Create Alert Rule (PowerShell Suspicious Web Request)**

### 🔍 **Explanation**
Sometimes, malicious actors gain access to systems and attempt to download payloads or tools directly from the internet. This is often done using legitimate tools like PowerShell to blend in with normal activity. By using commands like `Invoke-WebRequest`, attackers can:

- 📥 Download files or scripts from external servers
- 🚀 Execute them immediately, bypassing traditional defenses
- 📡 Establish communication with Command-and-Control (C2) servers
<img width="978" height="661" alt="invoke" src="https://github.com/user-attachments/assets/ff39fc22-f31b-4bf4-8bff-570aad0660d0" />

Detecting such behavior is critical to identifying and disrupting an ongoing attack! 🕵️‍♀️

### **Detection Pipeline Overview**
1. 🖥️ Processes are logged via **Microsoft Defender for Endpoint** under the `DeviceProcessEvents` table.
2. 📊 Logs are forwarded to **Log Analytics Workspace** and integrated into **Microsoft Sentinel (SIEM)**.
3. 🛑 An alert rule is created in **Sentinel** to trigger when PowerShell downloads remote files.

---

### 🔧 **Steps to Create the Alert Rule**

#### 1️⃣ **Query Logs in Microsoft Defender**
1. Open **Microsoft EDR**.
2. Go to the KQL section and enter:
```kql
DeviceFileEvents
| top 20 by Timestamp desc
```
```kql
DeviceNetworkEvents
| top 20 by Timestamp desc
```
```kql
DeviceProcessEvents
| top 20 by Timestamp desc
```
3. Locate suspicious activity, e.g., `powershell.exe` executing `Invoke-WebRequest`.
4. Refine query for target device:
   ```kql
   let TargetDevice = "windows-target-";
   DeviceProcessEvents
   | where DeviceName == TargetDevice
   | where FileName == "powershell.exe"
   | where ProcessCommandLine contains "Invoke-WebRequest"
   ```
<img width="1184" height="516" alt="powershell" src="https://github.com/user-attachments/assets/1884115d-2bd1-4b72-afa8-39759e507e09" />


5. Verify payload detection. ✅
```kql
   let TargetHostname = "windows-target-"; // Replace with the name of your VM as it shows up in the logs
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]); // Add the name of the scripts that were downloaded
DeviceProcessEvents
| where DeviceName == TargetHostname // Comment this line out for MORE results
| where FileName == "powershell.exe"
| where ProcessCommandLine contains "-File" and ProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, ProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, ProcessCommandLine
```

<img width="1200" height="336" alt="powershell5" src="https://github.com/user-attachments/assets/79a64ce0-df2d-4835-85aa-dc563d35574d" />



#### 2️⃣ **Create Alert Rule in Microsoft Sentinel**
1. Open **Sentinel** and navigate to:
   `Analytics → Scheduled Query Rule → Create Alert Rule`
2. Fill in the following details:
   - **Rule Name**: PowerShell Suspicious Web Request 🚩
   - **Description**: Detects PowerShell downloading remote files 📥.
   - **KQL Query**:
     ```kql
     let TargetDevice = "windows-target-";
     DeviceProcessEvents
     | where DeviceName == TargetDevice
     | where FileName == "powershell.exe"
     | where ProcessCommandLine contains "Invoke-WebRequest"
     ```
   - **Run Frequency**: Every 4 hours 🕒
   - **Lookup Period**: Last 24 hours 📅
   - **Incident Behavior**: Automatically create incidents and group alerts into a single incident per 24 hours.
3. Configure **Entity Mappings**:
   - **Account**: `AccountName`
   - **Host**: `DeviceName`
   - **Process**: `ProcessCommandLine`
4. Enable **Mitre ATT&CK Framework Categories** (Use ChatGPT to assist! 🤖).
5. Save and activate the rule. 🎉

<img width="888" height="738" alt="powershell1" src="https://github.com/user-attachments/assets/48e04e56-5b51-43dd-889e-5bd5f9c77a56" />



---

## 🛠️ **Work the Incident**
Follow the **NIST 800-161: Incident Response Lifecycle**:

### 1️⃣ **Preparation** 📂
- Define roles, responsibilities, and procedures 🗂️.
- Ensure tools, systems, and training are in place 🛠️.

### 2️⃣ **Detection and Analysis** 🕵️‍♀️
1. **Validate Incident**:
   - Assign it to yourself and set the status to **Active** ✅.

<img width="1144" height="719" alt="powershell2" src="https://github.com/user-attachments/assets/663ba89c-53db-41ab-b71e-1f2ede0d55bb" />


2. **Investigate**:
   - Review logs and entity mappings 🗒️.
   - Check PowerShell commands:
     ```plaintext
     powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri <URL> -OutFile <Path>
     ```
   - Identify downloaded scripts:
     - `portscan.ps1`
     - `pwncrypt.ps1`
     - `eicar.ps1`
   
3. Gather evidence:
   - Scripts downloaded and executed 🧪.
   - User admitted to downloading free software during the events.

### 3️⃣ **Containment, Eradication, and Recovery** 🛡️
1. Isolate affected systems:
   - Use **Defender for Endpoint** to isolate the machine 🔒.
   - Run anti-malware scans.
2. Analyze downloaded scripts:

3. Remove threats and restore systems:
   - Confirm scripts executed.
   - Clean up affected files and verify machine integrity 🧹.

### 4️⃣ **Post-Incident Activities** 📝
1. Document findings and lessons learned 🖊️.
   - Scripts executed: `pwncrypt.ps1` , `portscan.ps1` , `eicar.ps1` .
   - Account involved: `system-user`.
2. Update policies:
   - Restrict PowerShell usage 🚫.
   - Enhance cybersecurity training programs 📚.
3. Finalize reporting and close the case:
   - Mark incident as **True Positive** ✅. 
<img width="670" height="623" alt="powershell3" src="https://github.com/user-attachments/assets/c9774630-ca54-449f-9dab-93716eb66798" />
<img width="594" height="613" alt="powershell4" src="https://github.com/user-attachments/assets/1ee5cd40-7038-4a9f-946a-439d6c56426a" />


---

## 🎯 **Incident Summary**
| **Metric**                     | **Value**                        |
|---------------------------------|-----------------------------------|
| **Affected Device**            | `windows-target-`               |
| **Suspicious Commands**        | 3                                |
| **Scripts Downloaded**         | `portscan.ps1`, `pwncrypt.ps1`, `eicar.ps1`   |
| **Incident Status**            | Resolved                         |

---

🎉 **Great Job Securing Your Environment!** 🔒

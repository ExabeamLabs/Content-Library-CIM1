Vendor: Cisco
=============
Product: Firepower
------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  288  |  119   |         37         |     13      |   13    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  authentication-successful<br> ↳[meraki-firepower-active-dir](Ps/pC_merakifirepoweractivedir.md)<br> ↳[cisco-ftd-722041](Ps/pC_ciscoftd722041.md)<br><br> nac-logon<br> ↳[cisco-ftd-113004](Ps/pC_ciscoftd113004.md)<br><br> vpn-login<br> ↳[cisco-ftd-firewall-7](Ps/pC_ciscoftdfirewall7.md)<br><br> vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br> | T1021 - Remote Services<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>38 Rules</li></ul><ul><li>16 Models</li></ul>](RM/r_m_cisco_firepower_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1484 - Group Policy Modification<br>    | [<ul><li>7 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_cisco_firepower_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cisco_firepower_Brute_Force_Attack.md)    |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cisco_firepower_Cryptomining.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cisco_firepower_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  netflow-connection<br> ↳[cisco-netflow-connection-1](Ps/pC_cisconetflowconnection1.md)<br><br> vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1041 - Exfiltration Over C2 Channel<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1071.002 - Application Layer Protocol: File Transfer Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0010 - TA0010<br> | [<ul><li>13 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_cisco_firepower_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1041 - Exfiltration Over C2 Channel<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>TA0010 - TA0010<br>    | [<ul><li>17 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_cisco_firepower_Data_Leak.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566 - Phishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_firepower_Phishing.md)    |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  vpn-login<br> ↳[cisco-ftd-firewall-7](Ps/pC_ciscoftdfirewall7.md)<br>    | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cisco_firepower_Physical_Security.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  vpn-login<br> ↳[cisco-ftd-firewall-7](Ps/pC_ciscoftdfirewall7.md)<br><br> vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1133 - External Remote Services<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_firepower_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  vpn-logout<br> ↳[cisco-ftd-firewall-8](Ps/pC_ciscoftdfirewall8.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_cisco_firepower_Privilege_Escalation.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  authentication-successful<br> ↳[meraki-firepower-active-dir](Ps/pC_merakifirepoweractivedir.md)<br> ↳[cisco-ftd-722041](Ps/pC_ciscoftd722041.md)<br><br> vpn-login<br> ↳[cisco-ftd-firewall-7](Ps/pC_ciscoftdfirewall7.md)<br><br> web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br><br> web-activity-denied<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cisco_firepower_Ransomware.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  web-activity-allowed<br> ↳[sourcefire-proxy](Ps/pC_sourcefireproxy.md)<br> ↳[sourcefire-proxy-1](Ps/pC_sourcefireproxy1.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_firepower_Workforce_Protection.md)    |
[Next Page -->>](2_ds_cisco_firepower.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Execution                                                           | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                                                                                                                                                                                        | Defense Evasion                                                                                                                                                                                                                                                                                                                                             | Credential Access                                                                                                                                                                                                                                                                                                                                | Discovery                                                                                                                                                 | Lateral Movement                                                                                                                                                                                                                                                                                                                     | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Exfiltration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Impact                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> | [Network Service Scanning](https://attack.mitre.org/techniques/T1046)<br><br>[Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br><br> | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)<br><br>[Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)<br><br>[Internal Spearphishing](https://attack.mitre.org/techniques/T1534)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: File Transfer Protocols](https://attack.mitre.org/techniques/T1071/002)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br>[Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br>[Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |
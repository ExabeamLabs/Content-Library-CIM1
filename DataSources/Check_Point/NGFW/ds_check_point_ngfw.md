Vendor: Check Point
===================
Product: NGFW
-------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  323  |  139   |         33         |     13      |   13    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-login<br> ↳[smartdashboard-app-login](Ps/pC_smartdashboardapplogin.md)<br> ↳[syslog-checkpoint-app-login-1](Ps/pC_syslogcheckpointapplogin1.md)<br> ↳[syslog-checkpoint-app-login](Ps/pC_syslogcheckpointapplogin.md)<br><br> authentication-failed<br> ↳[checkpoint-auth-failed](Ps/pC_checkpointauthfailed.md)<br><br> authentication-successful<br> ↳[cef-checkpoint-auth-successful-2](Ps/pC_cefcheckpointauthsuccessful2.md)<br> ↳[checkpoint-auth-successful](Ps/pC_checkpointauthsuccessful.md)<br> ↳[cef-checkpoint-auth-successful](Ps/pC_cefcheckpointauthsuccessful.md)<br> ↳[checkpoint-auth-successful-1](Ps/pC_checkpointauthsuccessful1.md)<br> ↳[cef-checkpoint-auth-successful-1](Ps/pC_cefcheckpointauthsuccessful1.md)<br><br> failed-vpn-login<br> ↳[checkpoint-vpn-authentication](Ps/pC_checkpointvpnauthentication.md)<br><br> local-logon<br> ↳[checkpoint-local-logon](Ps/pC_checkpointlocallogon.md)<br><br> vpn-login<br> ↳[checkpoint-vpn-authentication](Ps/pC_checkpointvpnauthentication.md)<br> ↳[cef-checkpoint-vpn-login-3](Ps/pC_cefcheckpointvpnlogin3.md)<br> ↳[cef-checkpoint-vpn-login-4](Ps/pC_cefcheckpointvpnlogin4.md)<br> ↳[cef-checkpoint-vpn-login-2](Ps/pC_cefcheckpointvpnlogin2.md)<br> ↳[checkpoint-vpn-login-6](Ps/pC_checkpointvpnlogin6.md)<br><br> vpn-logout<br> ↳[checkpoint-vpn-logout](Ps/pC_checkpointvpnlogout.md)<br> ↳[cef-checkpoint-logout-2](Ps/pC_cefcheckpointlogout2.md)<br> ↳[cef-checkpoint-logout-1](Ps/pC_cefcheckpointlogout1.md)<br><br> web-activity-allowed<br> ↳[s-checkpoint-proxy](Ps/pC_scheckpointproxy.md)<br> ↳[checkpoint-url-filtering](Ps/pC_checkpointurlfiltering.md)<br> ↳[checkpoint-proxy](Ps/pC_checkpointproxy.md)<br> ↳[checkpoint-proxy-2](Ps/pC_checkpointproxy2.md)<br> ↳[checkpoint-firewall-allow-2](Ps/pC_checkpointfirewallallow2.md)<br> ↳[checkpoint-proxy-1](Ps/pC_checkpointproxy1.md)<br> ↳[checkpoint-web-activity](Ps/pC_checkpointwebactivity.md)<br> ↳[checkpoint-web-activity-1](Ps/pC_checkpointwebactivity1.md)<br><br> web-activity-denied<br> ↳[s-checkpoint-proxy](Ps/pC_scheckpointproxy.md)<br> ↳[checkpoint-url-filtering](Ps/pC_checkpointurlfiltering.md)<br> ↳[checkpoint-proxy](Ps/pC_checkpointproxy.md)<br> ↳[checkpoint-proxy-2](Ps/pC_checkpointproxy2.md)<br> ↳[checkpoint-proxy-1](Ps/pC_checkpointproxy1.md)<br> ↳[checkpoint-web-activity](Ps/pC_checkpointwebactivity.md)<br> ↳[checkpoint-web-activity-1](Ps/pC_checkpointwebactivity1.md)<br> | T1021 - Remote Services<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br> | [<ul><li>54 Rules</li></ul><ul><li>22 Models</li></ul>](RM/r_m_check_point_ngfw_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  vpn-logout<br> ↳[checkpoint-vpn-logout](Ps/pC_checkpointvpnlogout.md)<br> ↳[cef-checkpoint-logout-2](Ps/pC_cefcheckpointlogout2.md)<br> ↳[cef-checkpoint-logout-1](Ps/pC_cefcheckpointlogout1.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1484 - Group Policy Modification<br>    | [<ul><li>7 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_check_point_ngfw_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  vpn-logout<br> ↳[checkpoint-vpn-logout](Ps/pC_checkpointvpnlogout.md)<br> ↳[cef-checkpoint-logout-2](Ps/pC_cefcheckpointlogout2.md)<br> ↳[cef-checkpoint-logout-1](Ps/pC_cefcheckpointlogout1.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_ngfw_Brute_Force_Attack.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-login<br> ↳[smartdashboard-app-login](Ps/pC_smartdashboardapplogin.md)<br> ↳[syslog-checkpoint-app-login-1](Ps/pC_syslogcheckpointapplogin1.md)<br> ↳[syslog-checkpoint-app-login](Ps/pC_syslogcheckpointapplogin.md)<br><br> vpn-logout<br> ↳[checkpoint-vpn-logout](Ps/pC_checkpointvpnlogout.md)<br> ↳[cef-checkpoint-logout-2](Ps/pC_cefcheckpointlogout2.md)<br> ↳[cef-checkpoint-logout-1](Ps/pC_cefcheckpointlogout1.md)<br>    | T1078 - Valid Accounts<br>T1110 - Brute Force<br>    | [<ul><li>6 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_check_point_ngfw_Data_Access.md)    |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  vpn-login<br> ↳[checkpoint-vpn-authentication](Ps/pC_checkpointvpnauthentication.md)<br> ↳[cef-checkpoint-vpn-login-3](Ps/pC_cefcheckpointvpnlogin3.md)<br> ↳[cef-checkpoint-vpn-login-4](Ps/pC_cefcheckpointvpnlogin4.md)<br> ↳[cef-checkpoint-vpn-login-2](Ps/pC_cefcheckpointvpnlogin2.md)<br> ↳[checkpoint-vpn-login-6](Ps/pC_checkpointvpnlogin6.md)<br>    | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_ngfw_Physical_Security.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  local-logon<br> ↳[checkpoint-local-logon](Ps/pC_checkpointlocallogon.md)<br><br> vpn-logout<br> ↳[checkpoint-vpn-logout](Ps/pC_checkpointvpnlogout.md)<br> ↳[cef-checkpoint-logout-2](Ps/pC_cefcheckpointlogout2.md)<br> ↳[cef-checkpoint-logout-1](Ps/pC_cefcheckpointlogout1.md)<br>    | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>7 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_check_point_ngfw_Privilege_Escalation.md)    |
[Next Page -->>](2_ds_check_point_ngfw.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Execution                                                           | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                                                                                              | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | Credential Access                                                                                                                                                                                                                                                                                                                                | Discovery | Lateral Movement                                                                                                                                                                                                                          | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Impact                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br>[Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Internal Spearphishing](https://attack.mitre.org/techniques/T1534)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br>[Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br>[Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |
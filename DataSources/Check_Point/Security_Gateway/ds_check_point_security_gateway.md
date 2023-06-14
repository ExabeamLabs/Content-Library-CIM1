Vendor: Check Point
===================
Product: Security Gateway
-------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  73   |   40   |         14         |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  failed-vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>29 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_check_point_security_gateway_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1484 - Group Policy Modification<br>    | [<ul><li>7 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_check_point_security_gateway_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_security_gateway_Brute_Force_Attack.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1133 - External Remote Services<br>TA0010 - TA0010<br>    | [<ul><li>4 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1133 - External Remote Services<br>TA0010 - TA0010<br> | [<ul><li>11 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Leak.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1566 - Phishing<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_security_gateway_Phishing.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  vpn-logout<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_check_point_security_gateway_Privilege_Escalation.md)    |
[Next Page -->>](2_ds_check_point_security_gateway.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                                                                                              | Defense Evasion                                                                                                                                   | Credential Access                                                                                                                                                                                                                                                                                                                                | Discovery | Lateral Movement                                                     | Collection | Command and Control                                                                                                                       | Exfiltration                                                                                                                                                                                                                                                                                                                                                                                                                                                | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | -------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br>[Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> |        |
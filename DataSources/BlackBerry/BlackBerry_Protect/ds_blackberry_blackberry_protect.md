Vendor: BlackBerry
==================
Product: BlackBerry Protect
---------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  158  |   66   |         14         |      6      |    6    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> app-login<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>12 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Account_Manipulation.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> app-login<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  dlp-alert<br> ↳[cylance-dlp-alert](Ps/pC_cylancedlpalert.md)<br><br> file-alert<br> ↳[cylance-protect-file-alert](Ps/pC_cylanceprotectfilealert.md)<br>    | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0002 - TA0002<br>TA0010 - TA0010<br>    | [<ul><li>31 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> dlp-alert<br> ↳[cylance-dlp-alert](Ps/pC_cylancedlpalert.md)<br>    | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>T1114.003 - Email Collection: Email Forwarding Rule<br>TA0010 - TA0010<br> | [<ul><li>32 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Data_Leak.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> app-login<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> file-alert<br> ↳[cylance-protect-file-alert](Ps/pC_cylanceprotectfilealert.md)<br> | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>7 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_blackberry_blackberry_protect_Privilege_Escalation.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br><br> app-login<br> ↳[s-cylance-app-activity](Ps/pC_scylanceappactivity.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_blackberry_blackberry_protect_Ransomware.md)    |
[Next Page -->>](2_ds_blackberry_blackberry_protect.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution                                                               | Persistence                                                                                                                                                                                                                                                                                                                                                                                                        | Privilege Escalation                                                                                                                                                                                                                 | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                              | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                                                                                                      | Exfiltration                                                                | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [Impair Defenses](https://attack.mitre.org/techniques/T1562)<br><br>[Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> |        |
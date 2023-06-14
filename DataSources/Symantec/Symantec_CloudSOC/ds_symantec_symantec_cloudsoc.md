Vendor: Symantec
================
Product: Symantec CloudSOC
--------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  126  |   59   |         13         |      7      |    7    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-delete<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>67 Rules</li></ul><ul><li>37 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-delete<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>    | [<ul><li>44 Rules</li></ul><ul><li>24 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  dlp-alert<br> ↳[symantec-cloud-dlp-alert](Ps/pC_symantecclouddlpalert.md)<br>    | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0010 - TA0010<br>    | [<ul><li>29 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> dlp-alert<br> ↳[symantec-cloud-dlp-alert](Ps/pC_symantecclouddlpalert.md)<br>    | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>T1114.003 - Email Collection: Email Forwarding Rule<br>TA0010 - TA0010<br>  | [<ul><li>32 Rules</li></ul><ul><li>18 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Data_Leak.md)    |
|    [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)    |  file-delete<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Destruction_of_Data.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> dlp-alert<br> ↳[symantec-cloud-dlp-alert](Ps/pC_symantecclouddlpalert.md)<br>    | T1078 - Valid Accounts<br>TA0002 - TA0002<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-delete<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-download<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-upload<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br> | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>7 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-delete<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-download<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> file-upload<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br><br> failed-app-login<br> ↳[symantec-cloud-activity](Ps/pC_symanteccloudactivity.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_symantec_symantec_cloudsoc_Ransomware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                                                                                                                                                                                                    | Credential Access | Discovery                                                                         | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                                                                                                      | Exfiltration                                                                | Impact                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br> |                   | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br> |
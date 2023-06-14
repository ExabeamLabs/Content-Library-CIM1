Vendor: Box
===========
Product: Box Cloud Content Management
-------------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  109  |   45   |         17         |      8      |    8    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br><br> app-login<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-activity](Ps/pC_boxactivity.md)<br> ↳[cef-box-app-login](Ps/pC_cefboxapplogin.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>12 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_box_box_cloud_content_management_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_box_box_cloud_content_management_Account_Manipulation.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  file-write<br> ↳[cef-skyformation-file-activity](Ps/pC_cefskyformationfileactivity.md)<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-activity](Ps/pC_boxactivity.md)<br> ↳[cef-box-file-activity](Ps/pC_cefboxfileactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_box_box_cloud_content_management_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br><br> file-write<br> ↳[cef-skyformation-file-activity](Ps/pC_cefskyformationfileactivity.md)<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-activity](Ps/pC_boxactivity.md)<br> ↳[cef-box-file-activity](Ps/pC_cefboxfileactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br> | T1114.001 - T1114.001<br>T1114.003 - Email Collection: Email Forwarding Rule<br>     | [<ul><li>4 Rules</li></ul>](RM/r_m_box_box_cloud_content_management_Data_Leak.md)    |
|    [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)    |  file-delete<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-activity](Ps/pC_boxactivity.md)<br> ↳[cef-box-file-activity](Ps/pC_cefboxfileactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br>    | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_box_box_cloud_content_management_Destruction_of_Data.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br><br> app-login<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-activity](Ps/pC_boxactivity.md)<br> ↳[cef-box-app-login](Ps/pC_cefboxapplogin.md)<br>    | T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_box_box_cloud_content_management_Lateral_Movement.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[q-box-app-activity](Ps/pC_qboxappactivity.md)<br> ↳[box-skyformation-file-activity](Ps/pC_boxskyformationfileactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_box_box_cloud_content_management_Privilege_Escalation.md)    |
[Next Page -->>](2_ds_box_box_cloud_content_management.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Privilege Escalation                                                                                                                                      | Defense Evasion                                                                                                                                                                                                                                    | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br>[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |
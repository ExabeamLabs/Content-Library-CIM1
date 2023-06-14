Vendor: Egnyte
==============
Product: Egnyte
---------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  113  |   45   |         16         |      8      |    8    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[cef-egnyte-app-activity-6](Ps/pC_cefegnyteappactivity6.md)<br> ↳[cef-egnyte-app-activity-7](Ps/pC_cefegnyteappactivity7.md)<br> ↳[cef-egnyte-app-activity-4](Ps/pC_cefegnyteappactivity4.md)<br> ↳[cef-egnyte-app-activity-5](Ps/pC_cefegnyteappactivity5.md)<br> ↳[cef-egnyte-app-activity-8](Ps/pC_cefegnyteappactivity8.md)<br> ↳[cef-egnyte-app-activity-9](Ps/pC_cefegnyteappactivity9.md)<br> ↳[cef-egnyte-app-activity-2](Ps/pC_cefegnyteappactivity2.md)<br> ↳[cef-egnyte-app-activity-3](Ps/pC_cefegnyteappactivity3.md)<br> ↳[cef-egnyte-app-activity-1](Ps/pC_cefegnyteappactivity1.md)<br> ↳[cef-egnyte-app-activity-13](Ps/pC_cefegnyteappactivity13.md)<br> ↳[cef-egnyte-app-activity-11](Ps/pC_cefegnyteappactivity11.md)<br> ↳[cef-egnyte-app-activity-12](Ps/pC_cefegnyteappactivity12.md)<br> ↳[cef-egnyte-app-activity-10](Ps/pC_cefegnyteappactivity10.md)<br> ↳[cef-egnyte-app-activity](Ps/pC_cefegnyteappactivity.md)<br> ↳[egnyte-file-operations](Ps/pC_egnytefileoperations.md)<br><br> app-login<br> ↳[egnyte-app-login](Ps/pC_egnyteapplogin.md)<br><br> failed-app-login<br> ↳[egnyte-failed-app-login](Ps/pC_egnytefailedapplogin.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_egnyte_egnyte_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[cef-egnyte-app-activity-6](Ps/pC_cefegnyteappactivity6.md)<br> ↳[cef-egnyte-app-activity-7](Ps/pC_cefegnyteappactivity7.md)<br> ↳[cef-egnyte-app-activity-4](Ps/pC_cefegnyteappactivity4.md)<br> ↳[cef-egnyte-app-activity-5](Ps/pC_cefegnyteappactivity5.md)<br> ↳[cef-egnyte-app-activity-8](Ps/pC_cefegnyteappactivity8.md)<br> ↳[cef-egnyte-app-activity-9](Ps/pC_cefegnyteappactivity9.md)<br> ↳[cef-egnyte-app-activity-2](Ps/pC_cefegnyteappactivity2.md)<br> ↳[cef-egnyte-app-activity-3](Ps/pC_cefegnyteappactivity3.md)<br> ↳[cef-egnyte-app-activity-1](Ps/pC_cefegnyteappactivity1.md)<br> ↳[cef-egnyte-app-activity-13](Ps/pC_cefegnyteappactivity13.md)<br> ↳[cef-egnyte-app-activity-11](Ps/pC_cefegnyteappactivity11.md)<br> ↳[cef-egnyte-app-activity-12](Ps/pC_cefegnyteappactivity12.md)<br> ↳[cef-egnyte-app-activity-10](Ps/pC_cefegnyteappactivity10.md)<br> ↳[cef-egnyte-app-activity](Ps/pC_cefegnyteappactivity.md)<br> ↳[egnyte-file-operations](Ps/pC_egnytefileoperations.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_egnyte_egnyte_Account_Manipulation.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  file-write<br> ↳[egnyte-file-operations](Ps/pC_egnytefileoperations.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_egnyte_egnyte_Data_Exfiltration.md)    |
|    [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)    |  file-delete<br> ↳[egnyte-file-operations](Ps/pC_egnytefileoperations.md)<br>    | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br> | [<ul><li>1 Rules</li></ul>](RM/r_m_egnyte_egnyte_Destruction_of_Data.md)    |
[Next Page -->>](2_ds_egnyte_egnyte.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Privilege Escalation                                                                                                                                      | Defense Evasion                                                                                                                                                                                                                                    | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br>[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |
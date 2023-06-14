Vendor: FireEye
===============
Product: FireEye Endpoint Security (HX)
---------------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  125  |   48   |         15         |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br><br> network-alert<br> ↳[s-fireeye-hx-alert-6](Ps/pC_sfireeyehxalert6.md)<br><br> process-alert<br> ↳[s-fireeye-hx-alert-4](Ps/pC_sfireeyehxalert4.md)<br><br> security-alert<br> ↳[cef-fireeye-hx-security-alert](Ps/pC_ceffireeyehxsecurityalert.md)<br> ↳[s-fireeye-hx-alert-s-1](Ps/pC_sfireeyehxalerts1.md)<br> ↳[s-fireeye-hx-alert-1](Ps/pC_sfireeyehxalert1.md)<br> ↳[fireeye-hx-alert](Ps/pC_fireeyehxalert.md)<br> ↳[s-fireeye-hx-alert](Ps/pC_sfireeyehxalert.md)<br> ↳[s-fireeye-hx-alert-hx](Ps/pC_sfireeyehxalerthx.md)<br> ↳[s-fireeye-hx-alert-2](Ps/pC_sfireeyehxalert2.md)<br> ↳[s-fireeye-hx-alert-3](Ps/pC_sfireeyehxalert3.md)<br> | T1003.002 - T1003.002<br>T1003.003 - T1003.003<br>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br>TA0002 - TA0002<br> | [<ul><li>78 Rules</li></ul><ul><li>35 Models</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br>    | T1083 - File and Directory Discovery<br>    | [<ul><li>24 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Data_Exfiltration.md)         |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br>    | T1114.001 - T1114.001<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  security-alert<br> ↳[cef-fireeye-hx-security-alert](Ps/pC_ceffireeyehxsecurityalert.md)<br> ↳[s-fireeye-hx-alert-s-1](Ps/pC_sfireeyehxalerts1.md)<br> ↳[s-fireeye-hx-alert-1](Ps/pC_sfireeyehxalert1.md)<br> ↳[fireeye-hx-alert](Ps/pC_fireeyehxalert.md)<br> ↳[s-fireeye-hx-alert](Ps/pC_sfireeyehxalert.md)<br> ↳[s-fireeye-hx-alert-hx](Ps/pC_sfireeyehxalerthx.md)<br> ↳[s-fireeye-hx-alert-2](Ps/pC_sfireeyehxalert2.md)<br> ↳[s-fireeye-hx-alert-3](Ps/pC_sfireeyehxalert3.md)<br>    | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Lateral_Movement.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Privilege_Abuse.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  file-write<br> ↳[s-fireeye-hx-alert-5](Ps/pC_sfireeyehxalert5.md)<br>    | T1486 - Data Encrypted for Impact<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_endpoint_security_(hx)_Ransomware.md)    |
[Next Page -->>](2_ds_fireeye_fireeye_endpoint_security_(hx).md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution                                                               | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Privilege Escalation                                                                                                                                                                                                                                                                                                       | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                              | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection                                                            | Command and Control | Exfiltration | Impact                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------- | ------------------- | ------------ | ------------------------------------------------------------------------------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> | [Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Impair Defenses](https://attack.mitre.org/techniques/T1562)<br><br>[Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1562/004)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br> |                     |              | [Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |
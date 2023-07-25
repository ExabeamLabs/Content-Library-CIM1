Vendor: Proofpoint
==================
Product: ObserveIT
------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  123  |   56   |     17     |      2      |    2    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>32 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_proofpoint_observeit_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_proofpoint_observeit_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>    | [<ul><li>71 Rules</li></ul><ul><li>39 Models</li></ul>](RM/r_m_proofpoint_observeit_Compromised_Credentials.md)          |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_proofpoint_observeit_Data_Access.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1114.003 - Email Collection: Email Forwarding Rule<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_proofpoint_observeit_Data_Leak.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br> | [<ul><li>31 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_proofpoint_observeit_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1078 - Valid Accounts<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>TA0002 - TA0002<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_proofpoint_observeit_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>15 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_proofpoint_observeit_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_proofpoint_observeit_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>17 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_proofpoint_observeit_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br><br> remote-logon<br> ↳[observeit-dlp-alert-1](Ps/pC_observeitdlpalert1.md)<br> ↳[observeit-dlp-alert-2](Ps/pC_observeitdlpalert2.md)<br> ↳[observeit-security-alert-2](Ps/pC_observeitsecurityalert2.md)<br> ↳[observeit-security-alert-1](Ps/pC_observeitsecurityalert1.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_proofpoint_observeit_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Credential Access                                                                                                                                                                                                                                                                | Discovery                                                                    | Lateral Movement                                                                                                                                               | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br>[Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)<br><br>[Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003)<br><br> | [Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> | [Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
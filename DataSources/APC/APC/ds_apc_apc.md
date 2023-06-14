Vendor: APC
===========
Product: APC
------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  108  |   44   |         17         |      5      |    5    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  authentication-failed<br> ↳[apc-authentication-failed](Ps/pC_apcauthenticationfailed.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>32 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_apc_apc_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1021 - Remote Services<br>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br> | [<ul><li>58 Rules</li></ul><ul><li>25 Models</li></ul>](RM/r_m_apc_apc_Compromised_Credentials.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  authentication-failed<br> ↳[apc-authentication-failed](Ps/pC_apcauthenticationfailed.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>    | [<ul><li>31 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_apc_apc_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in<br> ↳[apc-dlp-email-alert-in](Ps/pC_apcdlpemailalertin.md)<br><br> network-alert<br> ↳[apc-network-alert](Ps/pC_apcnetworkalert.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1190 - Exploit Public Fasing Application<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>TA0002 - TA0002<br>    | [<ul><li>7 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_apc_apc_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  dlp-email-alert-in<br> ↳[apc-dlp-email-alert-in](Ps/pC_apcdlpemailalertin.md)<br><br> dlp-email-alert-in-failed<br> ↳[apc-dlp-email-alert-in-failed](Ps/pC_apcdlpemailalertinfailed.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>10 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_apc_apc_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1555.005 - T1555.005<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_apc_apc_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  dlp-email-alert-in<br> ↳[apc-dlp-email-alert-in](Ps/pC_apcdlpemailalertin.md)<br><br> dlp-email-alert-in-failed<br> ↳[apc-dlp-email-alert-in-failed](Ps/pC_apcdlpemailalertinfailed.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br> | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>16 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_apc_apc_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  authentication-failed<br> ↳[apc-authentication-failed](Ps/pC_apcauthenticationfailed.md)<br><br> remote-logon<br> ↳[apc-remote-logon](Ps/pC_apcremotelogon.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_apc_apc_Ransomware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Credential Access                                                                                                                                                                                                                                                                | Discovery                                                                    | Lateral Movement                                                                                                                                               | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br>[Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br>[Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003)<br><br> | [Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> | [Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
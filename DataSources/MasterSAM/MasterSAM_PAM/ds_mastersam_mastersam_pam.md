Vendor: MasterSAM
=================
Product: MasterSAM PAM
----------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  88   |   35   |         16         |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-password-change<br> ↳[mastersam-pam-password-change](Ps/pC_mastersampampasswordchange.md)<br><br> authentication-failed<br> ↳[mastersam-pam-auth-failed-3](Ps/pC_mastersampamauthfailed3.md)<br> ↳[mastersam-pam-auth-failed-2](Ps/pC_mastersampamauthfailed2.md)<br><br> authentication-successful<br> ↳[mastersam-pam-auth-successful-1](Ps/pC_mastersampamauthsuccessful1.md)<br> ↳[mastersam-pam-auth-successful-3](Ps/pC_mastersampamauthsuccessful3.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>35 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-change<br> ↳[mastersam-pam-password-change](Ps/pC_mastersampampasswordchange.md)<br>    | T1098 - Account Manipulation<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_mastersam_mastersam_pam_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  authentication-successful<br> ↳[mastersam-pam-auth-successful-1](Ps/pC_mastersampamauthsuccessful1.md)<br> ↳[mastersam-pam-auth-successful-3](Ps/pC_mastersampamauthsuccessful3.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>    | [<ul><li>39 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Compromised_Credentials.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  authentication-failed<br> ↳[mastersam-pam-auth-failed-3](Ps/pC_mastersampamauthfailed3.md)<br> ↳[mastersam-pam-auth-failed-2](Ps/pC_mastersampamauthfailed2.md)<br><br> authentication-successful<br> ↳[mastersam-pam-auth-successful-1](Ps/pC_mastersampamauthsuccessful1.md)<br> ↳[mastersam-pam-auth-successful-3](Ps/pC_mastersampamauthsuccessful3.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br> | [<ul><li>31 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  authentication-successful<br> ↳[mastersam-pam-auth-successful-1](Ps/pC_mastersampamauthsuccessful1.md)<br> ↳[mastersam-pam-auth-successful-3](Ps/pC_mastersampamauthsuccessful3.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>TA0002 - TA0002<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  account-password-change<br> ↳[mastersam-pam-password-change](Ps/pC_mastersampampasswordchange.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1098 - Account Manipulation<br>    | [<ul><li>10 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1555.005 - T1555.005<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>15 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_mastersam_mastersam_pam_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  authentication-failed<br> ↳[mastersam-pam-auth-failed-3](Ps/pC_mastersampamauthfailed3.md)<br> ↳[mastersam-pam-auth-failed-2](Ps/pC_mastersampamauthfailed2.md)<br><br> authentication-successful<br> ↳[mastersam-pam-auth-successful-1](Ps/pC_mastersampamauthsuccessful1.md)<br> ↳[mastersam-pam-auth-successful-3](Ps/pC_mastersampamauthsuccessful3.md)<br><br> remote-logon<br> ↳[mastersam-pam-remote-logon](Ps/pC_mastersampamremotelogon.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_mastersam_mastersam_pam_Ransomware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                               | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Credential Access                                                                                                                                                                                                                                                                | Discovery                                                                    | Lateral Movement                                                                                                                                               | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br>[Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)<br><br>[Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003)<br><br> | [Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> | [Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br><br> | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br> |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
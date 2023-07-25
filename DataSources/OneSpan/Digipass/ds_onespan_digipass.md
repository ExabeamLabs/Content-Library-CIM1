Vendor: OneSpan
===============
Product: Digipass
-----------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  48   |   22   |     5      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>   | [<ul><li>18 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_onespan_digipass_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1098 - Account Manipulation<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_digipass_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>   | [<ul><li>30 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_onespan_digipass_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>5 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_onespan_digipass_Data_Access.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_onespan_digipass_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_digipass_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1078 - Valid Accounts<br>T1098 - Account Manipulation<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_onespan_digipass_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_digipass_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  account-password-reset<br> ↳[digipass-app-login](Ps/pC_digipassapplogin.md)<br><br> app-login<br> ↳[digipass-nac-logon](Ps/pC_digipassnaclogon.md)<br><br> nac-logon<br> ↳[digipass-nac-failed-logon](Ps/pC_digipassnacfailedlogon.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_onespan_digipass_Ransomware.md)    |

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                               | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement                                                     | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | -------------------------------------------------------------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
Vendor: LastPass
================
Product: LastPass
-----------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  88   |   33   |         10         |      5      |    5    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-creation<br> ↳[lastpass-account-creation](Ps/pC_lastpassaccountcreation.md)<br><br> account-password-change<br> ↳[lastpass-account-password-change](Ps/pC_lastpassaccountpasswordchange.md)<br><br> app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_lastpass_lastpass_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-creation<br> ↳[lastpass-account-creation](Ps/pC_lastpassaccountcreation.md)<br><br> account-password-change<br> ↳[lastpass-account-password-change](Ps/pC_lastpassaccountpasswordchange.md)<br><br> app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br>    | T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136 - Create Account<br>T1136.001 - Create Account: Create: Local Account<br>T1136.002 - T1136.002<br> | [<ul><li>24 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_lastpass_lastpass_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br>    | [<ul><li>43 Rules</li></ul><ul><li>24 Models</li></ul>](RM/r_m_lastpass_lastpass_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>20 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_lastpass_lastpass_Data_Access.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br>    | T1114.003 - Email Collection: Email Forwarding Rule<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_lastpass_lastpass_Data_Leak.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br>    | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_lastpass_lastpass_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_lastpass_lastpass_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_lastpass_lastpass_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_lastpass_lastpass_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[lastpass-app-activity](Ps/pC_lastpassappactivity.md)<br> ↳[lastpass-app-activity-1](Ps/pC_lastpassappactivity1.md)<br><br> app-login<br> ↳[lastpass-app-login](Ps/pC_lastpassapplogin.md)<br> ↳[lastpass-app-login-1](Ps/pC_lastpassapplogin1.md)<br> ↳[lastpass-app-login-2](Ps/pC_lastpassapplogin2.md)<br><br> failed-app-login<br> ↳[lastpass-app-login-failed](Ps/pC_lastpassapploginfailed.md)<br> ↳[lastpass-app-login-failed-1](Ps/pC_lastpassapploginfailed1.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_lastpass_lastpass_Ransomware.md)    |
[Next Page -->>](2_ds_lastpass_lastpass.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Create Account: Create: Local Account](https://attack.mitre.org/techniques/T1136/001)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
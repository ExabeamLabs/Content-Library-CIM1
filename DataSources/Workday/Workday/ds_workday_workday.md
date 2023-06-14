Vendor: Workday
===============
Product: Workday
----------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  67   |   26   |         6          |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br><br> authentication-failed<br> ↳[sk4-workday-app-auth-failed](Ps/pC_sk4workdayappauthfailed.md)<br><br> failed-app-login<br> ↳[sk4-workday-failed-app-login](Ps/pC_sk4workdayfailedapplogin.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_workday_workday_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_workday_workday_Account_Manipulation.md)    |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br><br> failed-app-login<br> ↳[sk4-workday-failed-app-login](Ps/pC_sk4workdayfailedapplogin.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>43 Rules</li></ul><ul><li>24 Models</li></ul>](RM/r_m_workday_workday_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br><br> failed-app-login<br> ↳[sk4-workday-failed-app-login](Ps/pC_sk4workdayfailedapplogin.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>20 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_workday_workday_Data_Access.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br>    | T1114.003 - Email Collection: Email Forwarding Rule<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_workday_workday_Data_Leak.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_workday_workday_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br><br> failed-app-login<br> ↳[sk4-workday-failed-app-login](Ps/pC_sk4workdayfailedapplogin.md)<br>    | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>         | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_workday_workday_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_workday_workday_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity<br> ↳[workday-app-activity-1](Ps/pC_workdayappactivity1.md)<br> ↳[workday-app-activity-2](Ps/pC_workdayappactivity2.md)<br><br> app-login<br> ↳[workday-app-login-1](Ps/pC_workdayapplogin1.md)<br> ↳[sk4-workday-app-login](Ps/pC_sk4workdayapplogin.md)<br> ↳[workday-app-login-2](Ps/pC_workdayapplogin2.md)<br><br> failed-app-login<br> ↳[sk4-workday-failed-app-login](Ps/pC_sk4workdayfailedapplogin.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_workday_workday_Privileged_Activity.md)    |
[Next Page -->>](2_ds_workday_workday.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
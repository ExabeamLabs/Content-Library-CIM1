Vendor: Epic
============
Product: Epic SIEM
------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  68   |   26   |         7          |      5      |    5    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-password-change<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br><br> app-activity<br> ↳[cef-epic-app-activity-11](Ps/pC_cefepicappactivity11.md)<br> ↳[cef-epic-app-activity-10](Ps/pC_cefepicappactivity10.md)<br> ↳[cef-epic-app-activity-12](Ps/pC_cefepicappactivity12.md)<br> ↳[cef-epic-app-activity-5](Ps/pC_cefepicappactivity5.md)<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br> ↳[cef-epic-app-activity-6](Ps/pC_cefepicappactivity6.md)<br> ↳[cef-epic-app-activity-3](Ps/pC_cefepicappactivity3.md)<br> ↳[cef-epic-app-activity-4](Ps/pC_cefepicappactivity4.md)<br> ↳[cef-epic-app-activity-9](Ps/pC_cefepicappactivity9.md)<br> ↳[cef-epic-app-activity-7](Ps/pC_cefepicappactivity7.md)<br> ↳[cef-epic-app-activity-8](Ps/pC_cefepicappactivity8.md)<br> ↳[cef-epic-app-activity-1](Ps/pC_cefepicappactivity1.md)<br> ↳[cef-epic-app-activity-2](Ps/pC_cefepicappactivity2.md)<br><br> app-login<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br> ↳[cef-epic-app-login](Ps/pC_cefepicapplogin.md)<br><br> authentication-successful<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br> ↳[cef-epic-auth-successful](Ps/pC_cefepicauthsuccessful.md)<br><br> failed-app-login<br> ↳[cef-epic-failed-app-login](Ps/pC_cefepicfailedapplogin.md)<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_epic_epic_siem_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-change<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br><br> app-activity<br> ↳[cef-epic-app-activity-11](Ps/pC_cefepicappactivity11.md)<br> ↳[cef-epic-app-activity-10](Ps/pC_cefepicappactivity10.md)<br> ↳[cef-epic-app-activity-12](Ps/pC_cefepicappactivity12.md)<br> ↳[cef-epic-app-activity-5](Ps/pC_cefepicappactivity5.md)<br> ↳[leef-epic-app-activity](Ps/pC_leefepicappactivity.md)<br> ↳[cef-epic-app-activity-6](Ps/pC_cefepicappactivity6.md)<br> ↳[cef-epic-app-activity-3](Ps/pC_cefepicappactivity3.md)<br> ↳[cef-epic-app-activity-4](Ps/pC_cefepicappactivity4.md)<br> ↳[cef-epic-app-activity-9](Ps/pC_cefepicappactivity9.md)<br> ↳[cef-epic-app-activity-7](Ps/pC_cefepicappactivity7.md)<br> ↳[cef-epic-app-activity-8](Ps/pC_cefepicappactivity8.md)<br> ↳[cef-epic-app-activity-1](Ps/pC_cefepicappactivity1.md)<br> ↳[cef-epic-app-activity-2](Ps/pC_cefepicappactivity2.md)<br>    | T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br> | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_epic_epic_siem_Account_Manipulation.md)    |
[Next Page -->>](2_ds_epic_epic_siem.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
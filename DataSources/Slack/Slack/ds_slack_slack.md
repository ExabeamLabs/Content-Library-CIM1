Vendor: Slack
=============
Product: Slack
--------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  62   |   26   |         6          |      4      |    4    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[slack-app-activity-1](Ps/pC_slackappactivity1.md)<br> ↳[slack-app-activity-2](Ps/pC_slackappactivity2.md)<br> ↳[slack-app-activity-3](Ps/pC_slackappactivity3.md)<br> ↳[slack-app-activity-4](Ps/pC_slackappactivity4.md)<br> ↳[slack-app-activity-5](Ps/pC_slackappactivity5.md)<br> ↳[slack-app-activity-6](Ps/pC_slackappactivity6.md)<br> ↳[slack-app-activity-7](Ps/pC_slackappactivity7.md)<br> ↳[slack-app-activity-8](Ps/pC_slackappactivity8.md)<br> ↳[cef-slack-app-activity](Ps/pC_cefslackappactivity.md)<br><br> app-login<br> ↳[slack-app-login](Ps/pC_slackapplogin.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>12 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_slack_slack_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[slack-app-activity-1](Ps/pC_slackappactivity1.md)<br> ↳[slack-app-activity-2](Ps/pC_slackappactivity2.md)<br> ↳[slack-app-activity-3](Ps/pC_slackappactivity3.md)<br> ↳[slack-app-activity-4](Ps/pC_slackappactivity4.md)<br> ↳[slack-app-activity-5](Ps/pC_slackappactivity5.md)<br> ↳[slack-app-activity-6](Ps/pC_slackappactivity6.md)<br> ↳[slack-app-activity-7](Ps/pC_slackappactivity7.md)<br> ↳[slack-app-activity-8](Ps/pC_slackappactivity8.md)<br> ↳[cef-slack-app-activity](Ps/pC_cefslackappactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br> | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_slack_slack_Account_Manipulation.md)    |
[Next Page -->>](2_ds_slack_slack.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
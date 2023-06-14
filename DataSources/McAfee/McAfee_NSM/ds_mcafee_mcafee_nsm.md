Vendor: McAfee
==============
Product: McAfee NSM
-------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  72   |   28   |         6          |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_mcafee_mcafee_nsm_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br><br> network-alert<br> ↳[syslog-mcafee-network-alert](Ps/pC_syslogmcafeenetworkalert.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>50 Rules</li></ul><ul><li>25 Models</li></ul>](RM/r_m_mcafee_mcafee_nsm_Compromised_Credentials.md)         |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>6 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_mcafee_mcafee_nsm_Data_Access.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_mcafee_mcafee_nsm_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> network-alert<br> ↳[syslog-mcafee-network-alert](Ps/pC_syslogmcafeenetworkalert.md)<br>    | T1078 - Valid Accounts<br>TA0002 - TA0002<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_mcafee_mcafee_nsm_Malware.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_mcafee_mcafee_nsm_Privilege_Abuse.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_mcafee_mcafee_nsm_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-login<br> ↳[mcafee-nsm-app-login](Ps/pC_mcafeensmapplogin.md)<br><br> failed-app-login<br> ↳[mcafee-nsm-app-login-failed](Ps/pC_mcafeensmapploginfailed.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_mcafee_mcafee_nsm_Ransomware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
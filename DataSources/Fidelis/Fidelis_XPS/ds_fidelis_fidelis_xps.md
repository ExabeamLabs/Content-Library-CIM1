Vendor: Fidelis
===============
Product: Fidelis XPS
--------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  71   |   28   |         7          |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  security-alert<br> ↳[n-forwarded-cef-fidelis-alert](Ps/pC_nforwardedceffidelisalert.md)<br> ↳[fidelis-leef-alert](Ps/pC_fidelisleefalert.md)<br>    | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>25 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_fidelis_fidelis_xps_Compromised_Credentials.md) |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br>    | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>    | [<ul><li>32 Rules</li></ul><ul><li>15 Models</li></ul>](RM/r_m_fidelis_fidelis_xps_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  security-alert<br> ↳[n-forwarded-cef-fidelis-alert](Ps/pC_nforwardedceffidelisalert.md)<br> ↳[fidelis-leef-alert](Ps/pC_fidelisleefalert.md)<br>    | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_fidelis_fidelis_xps_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-email-alert-in<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br><br> dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br><br> security-alert<br> ↳[n-forwarded-cef-fidelis-alert](Ps/pC_nforwardedceffidelisalert.md)<br> ↳[fidelis-leef-alert](Ps/pC_fidelisleefalert.md)<br> | T1190 - Exploit Public Fasing Application<br>TA0002 - TA0002<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_fidelis_fidelis_xps_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br>    | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_fidelis_fidelis_xps_Phishing.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  dlp-email-alert-in<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br><br> dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fidelis_fidelis_xps_Privilege_Abuse.md)    |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  dlp-email-alert-in<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br><br> dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br><br> security-alert<br> ↳[n-forwarded-cef-fidelis-alert](Ps/pC_nforwardedceffidelisalert.md)<br> ↳[fidelis-leef-alert](Ps/pC_fidelisleefalert.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_fidelis_fidelis_xps_Privileged_Activity.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  dlp-email-alert-out<br> ↳[fidelis-email-alert](Ps/pC_fidelisemailalert.md)<br>    | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>    | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_fidelis_fidelis_xps_Workforce_Protection.md)      |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration                                                                                                                                                                                                                                         | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br> |        |
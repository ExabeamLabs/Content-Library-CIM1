Vendor: Bitdefender
===================
Product: GravityZone
--------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  130  |   45   |         17         |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-login<br> ↳[gravityzone-security-alert-new-login](Ps/pC_gravityzonesecurityalertnewlogin.md)<br><br> web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_bitdefender_gravityzone_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  app-login<br> ↳[gravityzone-security-alert-new-login](Ps/pC_gravityzonesecurityalertnewlogin.md)<br><br> security-alert<br> ↳[gravityzone-security-alert-fw](Ps/pC_gravityzonesecurityalertfw.md)<br> ↳[gravityzone-security-alert-new-incident](Ps/pC_gravityzonesecurityalertnewincident.md)<br> ↳[gravityzone-security-alert-avc-1](Ps/pC_gravityzonesecurityalertavc1.md)<br> ↳[gravityzone-security-alert-aph](Ps/pC_gravityzonesecurityalertaph.md)<br> ↳[gravityzone-security-alert-av](Ps/pC_gravityzonesecurityalertav.md)<br> ↳[gravityzone-security-alert-avc](Ps/pC_gravityzonesecurityalertavc.md)<br> ↳[gravityzone-security-alert-av-1](Ps/pC_gravityzonesecurityalertav1.md)<br> ↳[gravityzone-security-alert-aph-1](Ps/pC_gravityzonesecurityalertaph1.md)<br> ↳[gravityzone-security-alert-hd](Ps/pC_gravityzonesecurityalerthd.md)<br> ↳[cef-bitdefender-gravityzone-alert](Ps/pC_cefbitdefendergravityzonealert.md)<br><br> web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>T1133 - External Remote Services<br>T1189 - Drive-by Compromise<br>T1190 - Exploit Public Fasing Application<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>78 Rules</li></ul><ul><li>39 Models</li></ul>](RM/r_m_bitdefender_gravityzone_Compromised_Credentials.md)         |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_bitdefender_gravityzone_Cryptomining.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-login<br> ↳[gravityzone-security-alert-new-login](Ps/pC_gravityzonesecurityalertnewlogin.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>5 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_bitdefender_gravityzone_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_bitdefender_gravityzone_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_bitdefender_gravityzone_Data_Leak.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_bitdefender_gravityzone_Phishing.md)    |
|    [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)    |  app-login<br> ↳[gravityzone-security-alert-new-login](Ps/pC_gravityzonesecurityalertnewlogin.md)<br><br> web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_bitdefender_gravityzone_Privilege_Abuse.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-login<br> ↳[gravityzone-security-alert-new-login](Ps/pC_gravityzonesecurityalertnewlogin.md)<br><br> web-activity-denied<br> ↳[gravityzone-web-activity-denied](Ps/pC_gravityzonewebactivitydenied.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_bitdefender_gravityzone_Ransomware.md)    |
[Next Page -->>](2_ds_bitdefender_gravityzone.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Execution                                                           | Persistence                                                                                                                                      | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement                                                            | Collection | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                            | Impact                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | --------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           | [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)<br><br> |            | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |
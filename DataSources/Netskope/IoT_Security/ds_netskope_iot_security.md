Vendor: Netskope
================
Product: IoT Security
---------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  26   |   11   |         3          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  network-alert<br> ↳[json-netskope-iot-network-alert-7](Ps/pC_jsonnetskopeiotnetworkalert7.md)<br> ↳[json-netskope-iot-network-alert](Ps/pC_jsonnetskopeiotnetworkalert.md)<br> ↳[json-netskope-iot-network-alert-6](Ps/pC_jsonnetskopeiotnetworkalert6.md)<br> ↳[json-netskope-iot-network-alert-5](Ps/pC_jsonnetskopeiotnetworkalert5.md)<br> ↳[json-netskope-iot-network-alert-4](Ps/pC_jsonnetskopeiotnetworkalert4.md)<br> ↳[json-netskope-iot-network-alert-3](Ps/pC_jsonnetskopeiotnetworkalert3.md)<br> ↳[json-netskope-iot-network-alert-2](Ps/pC_jsonnetskopeiotnetworkalert2.md)<br> ↳[json-netskope-iot-network-alert-1](Ps/pC_jsonnetskopeiotnetworkalert1.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>22 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_netskope_iot_security_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[json-netskope-iot-network-alert-7](Ps/pC_jsonnetskopeiotnetworkalert7.md)<br> ↳[json-netskope-iot-network-alert](Ps/pC_jsonnetskopeiotnetworkalert.md)<br> ↳[json-netskope-iot-network-alert-6](Ps/pC_jsonnetskopeiotnetworkalert6.md)<br> ↳[json-netskope-iot-network-alert-5](Ps/pC_jsonnetskopeiotnetworkalert5.md)<br> ↳[json-netskope-iot-network-alert-4](Ps/pC_jsonnetskopeiotnetworkalert4.md)<br> ↳[json-netskope-iot-network-alert-3](Ps/pC_jsonnetskopeiotnetworkalert3.md)<br> ↳[json-netskope-iot-network-alert-2](Ps/pC_jsonnetskopeiotnetworkalert2.md)<br> ↳[json-netskope-iot-network-alert-1](Ps/pC_jsonnetskopeiotnetworkalert1.md)<br> | TA0002 - TA0002<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_netskope_iot_security_Malware.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                         | Execution | Persistence | Privilege Escalation | Defense Evasion                                                                                                                                                                                            | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------------------------------------------------------------------------------- | --------- | ----------- | -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           |             |                      | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |
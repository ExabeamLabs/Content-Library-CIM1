Vendor: Microsoft
=================
Product: Azure AD Identity Protection
-------------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  34   |   12   |         6          |      1      |    1    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  security-alert<br> ↳[json-microsoft-o365-alert-10](Ps/pC_jsonmicrosofto365alert10.md)<br> ↳[json-microsoft-o365-alert-20](Ps/pC_jsonmicrosofto365alert20.md)<br> ↳[json-azure-ad-security-alert-1](Ps/pC_jsonazureadsecurityalert1.md)<br> ↳[json-microsoft-o365-alert-2](Ps/pC_jsonmicrosofto365alert2.md)<br> ↳[json-azure-ad-security-alert-2](Ps/pC_jsonazureadsecurityalert2.md)<br> ↳[json-azure-ad-security-alert](Ps/pC_jsonazureadsecurityalert.md)<br> ↳[azure-ad-security-alert-2](Ps/pC_azureadsecurityalert2.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br> | [<ul><li>25 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_microsoft_azure_ad_identity_protection_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  security-alert<br> ↳[json-microsoft-o365-alert-10](Ps/pC_jsonmicrosofto365alert10.md)<br> ↳[json-microsoft-o365-alert-20](Ps/pC_jsonmicrosofto365alert20.md)<br> ↳[json-azure-ad-security-alert-1](Ps/pC_jsonazureadsecurityalert1.md)<br> ↳[json-microsoft-o365-alert-2](Ps/pC_jsonmicrosofto365alert2.md)<br> ↳[json-azure-ad-security-alert-2](Ps/pC_jsonazureadsecurityalert2.md)<br> ↳[json-azure-ad-security-alert](Ps/pC_jsonazureadsecurityalert.md)<br> ↳[azure-ad-security-alert-2](Ps/pC_azureadsecurityalert2.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_microsoft_azure_ad_identity_protection_Lateral_Movement.md)    |
[Next Page -->>](2_ds_microsoft_azure_ad_identity_protection.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                      | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  |            |                     |              |        |
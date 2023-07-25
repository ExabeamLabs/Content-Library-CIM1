Vendor: Trend Micro
===================
Product: TippingPoint NGIPS
---------------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  81   |   37   |     7      |      3      |    3    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[tippingpoint-sms-alert](Ps/pC_tippingpointsmsalert.md)<br><br> database-delete<br> ↳[q-tippingpoint-sms-alert-5](Ps/pC_qtippingpointsmsalert5.md)<br> ↳[q-tippingpoint-sms-alert-4](Ps/pC_qtippingpointsmsalert4.md)<br> ↳[q-tippingpoint-sms-alert-3](Ps/pC_qtippingpointsmsalert3.md)<br> ↳[q-tippingpoint-sms-alert](Ps/pC_qtippingpointsmsalert.md)<br> ↳[q-tippingpoint-sms-alert-2](Ps/pC_qtippingpointsmsalert2.md)<br> ↳[q-tippingpoint-sms-alert-1](Ps/pC_qtippingpointsmsalert1.md)<br><br> network-alert<br> ↳[cef-tippingPoint-network-alert-1](Ps/pC_ceftippingpointnetworkalert1.md)<br> ↳[cef-tippingPoint-network-alert](Ps/pC_ceftippingpointnetworkalert.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>12 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_trend_micro_tippingpoint_ngips_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[tippingpoint-sms-alert](Ps/pC_tippingpointsmsalert.md)<br><br> database-delete<br> ↳[q-tippingpoint-sms-alert-5](Ps/pC_qtippingpointsmsalert5.md)<br> ↳[q-tippingpoint-sms-alert-4](Ps/pC_qtippingpointsmsalert4.md)<br> ↳[q-tippingpoint-sms-alert-3](Ps/pC_qtippingpointsmsalert3.md)<br> ↳[q-tippingpoint-sms-alert](Ps/pC_qtippingpointsmsalert.md)<br> ↳[q-tippingpoint-sms-alert-2](Ps/pC_qtippingpointsmsalert2.md)<br> ↳[q-tippingpoint-sms-alert-1](Ps/pC_qtippingpointsmsalert1.md)<br><br> network-alert<br> ↳[cef-tippingPoint-network-alert-1](Ps/pC_ceftippingpointnetworkalert1.md)<br> ↳[cef-tippingPoint-network-alert](Ps/pC_ceftippingpointnetworkalert.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br> | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_trend_micro_tippingpoint_ngips_Account_Manipulation.md)    |
[Next Page -->>](2_ds_trend_micro_tippingpoint_ngips.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                                                                                                                                                 | Privilege Escalation                                                | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
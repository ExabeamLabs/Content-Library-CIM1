Vendor: Okta
============
Product: Okta Adaptive MFA
--------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  146  |   55   |         14         |     14      |   14    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-creation<br> ↳[okta-account-creation](Ps/pC_oktaaccountcreation.md)<br><br> account-enabled<br> ↳[okta-account-enabled](Ps/pC_oktaaccountenabled.md)<br><br> account-lockout<br> ↳[json-okta-account-lockout](Ps/pC_jsonoktaaccountlockout.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br><br> account-password-change<br> ↳[okta-account-password-change](Ps/pC_oktaaccountpasswordchange.md)<br><br> account-password-reset<br> ↳[cef-okta-account-password-reset](Ps/pC_cefoktaaccountpasswordreset.md)<br> ↳[cef-okta-account-unlocked](Ps/pC_cefoktaaccountunlocked.md)<br><br> app-activity<br> ↳[okta-app-activity](Ps/pC_oktaappactivity.md)<br> ↳[okta-app-activity-ad](Ps/pC_oktaappactivityad.md)<br> ↳[s-okta-app-activity](Ps/pC_soktaappactivity.md)<br> ↳[okta-app-activity-1](Ps/pC_oktaappactivity1.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br><br> app-login<br> ↳[okta-app-login](Ps/pC_oktaapplogin.md)<br> ↳[s-okta-app-login](Ps/pC_soktaapplogin.md)<br> ↳[u-okta-app-login](Ps/pC_uoktaapplogin.md)<br> ↳[q-okta-app-login-2](Ps/pC_qoktaapplogin2.md)<br> ↳[q-okta-app-login-3](Ps/pC_qoktaapplogin3.md)<br> ↳[q-okta-app-login-1](Ps/pC_qoktaapplogin1.md)<br> ↳[okta-app-login-1](Ps/pC_oktaapplogin1.md)<br> ↳[s-okta-app-login-4](Ps/pC_soktaapplogin4.md)<br> ↳[q-okta-app-login-6](Ps/pC_qoktaapplogin6.md)<br> ↳[s-okta-app-login-5](Ps/pC_soktaapplogin5.md)<br> ↳[q-okta-app-login-4](Ps/pC_qoktaapplogin4.md)<br> ↳[s-okta-app-login-3](Ps/pC_soktaapplogin3.md)<br> ↳[q-okta-app-login-5](Ps/pC_qoktaapplogin5.md)<br> ↳[q-okta-app-login](Ps/pC_qoktaapplogin.md)<br> ↳[cef-okta-app-login](Ps/pC_cefoktaapplogin.md)<br> ↳[okta-app-activity](Ps/pC_oktaappactivity.md)<br> ↳[s-okta-app-activity](Ps/pC_soktaappactivity.md)<br> ↳[okta-app-activity-1](Ps/pC_oktaappactivity1.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[cef-okta-app-login-1](Ps/pC_cefoktaapplogin1.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br> ↳[json-okta-app-login](Ps/pC_jsonoktaapplogin.md)<br> ↳[json-okta-app-login-1](Ps/pC_jsonoktaapplogin1.md)<br><br> authentication-failed<br> ↳[json-okta-authentication-failed-4](Ps/pC_jsonoktaauthenticationfailed4.md)<br> ↳[json-okta-authentication-failed-5](Ps/pC_jsonoktaauthenticationfailed5.md)<br> ↳[json-okta-authentication-failed-3](Ps/pC_jsonoktaauthenticationfailed3.md)<br><br> authentication-successful<br> ↳[json-okta-authentication-success](Ps/pC_jsonoktaauthenticationsuccess.md)<br> ↳[cef-okta-logs-authentication](Ps/pC_cefoktalogsauthentication.md)<br> ↳[s-okta-app-login-2](Ps/pC_soktaapplogin2.md)<br> ↳[s-okta-app-login-1](Ps/pC_soktaapplogin1.md)<br><br> failed-app-login<br> ↳[json-okta-failed-app-login-1](Ps/pC_jsonoktafailedapplogin1.md)<br> ↳[json-okta-failed-app-login-2](Ps/pC_jsonoktafailedapplogin2.md)<br> ↳[q-okta-failed-app-login-1](Ps/pC_qoktafailedapplogin1.md)<br> ↳[q-okta-failed-app-login-2](Ps/pC_qoktafailedapplogin2.md)<br> ↳[okta-failed-app-login](Ps/pC_oktafailedapplogin.md)<br> ↳[q-okta-failed-app-login](Ps/pC_qoktafailedapplogin.md)<br> ↳[u-okta-failed-app-login](Ps/pC_uoktafailedapplogin.md)<br> ↳[s-okta-failed-app-login](Ps/pC_soktafailedapplogin.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[s-okta-failed-login-4](Ps/pC_soktafailedlogin4.md)<br> ↳[cef-okta-app-login-1](Ps/pC_cefoktaapplogin1.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[json-okta-failed-app-login-5](Ps/pC_jsonoktafailedapplogin5.md)<br> ↳[cef-okta-logs-authentication](Ps/pC_cefoktalogsauthentication.md)<br> ↳[json-okta-failed-app-login-6](Ps/pC_jsonoktafailedapplogin6.md)<br> ↳[json-okta-failed-app-login-4](Ps/pC_jsonoktafailedapplogin4.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br><br> member-added<br> ↳[json-okta-member-added](Ps/pC_jsonoktamemberadded.md)<br> ↳[cef-okta-member-added](Ps/pC_cefoktamemberadded.md)<br><br> member-removed<br> ↳[okta-member-removed](Ps/pC_oktamemberremoved.md)<br> | T1078 - Valid Accounts<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>    | [<ul><li>16 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_okta_okta_adaptive_mfa_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-creation<br> ↳[okta-account-creation](Ps/pC_oktaaccountcreation.md)<br><br> account-password-change<br> ↳[okta-account-password-change](Ps/pC_oktaaccountpasswordchange.md)<br><br> account-password-reset<br> ↳[cef-okta-account-password-reset](Ps/pC_cefoktaaccountpasswordreset.md)<br> ↳[cef-okta-account-unlocked](Ps/pC_cefoktaaccountunlocked.md)<br><br> app-activity<br> ↳[okta-app-activity](Ps/pC_oktaappactivity.md)<br> ↳[okta-app-activity-ad](Ps/pC_oktaappactivityad.md)<br> ↳[s-okta-app-activity](Ps/pC_soktaappactivity.md)<br> ↳[okta-app-activity-1](Ps/pC_oktaappactivity1.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br><br> member-added<br> ↳[json-okta-member-added](Ps/pC_jsonoktamemberadded.md)<br> ↳[cef-okta-member-added](Ps/pC_cefoktamemberadded.md)<br><br> member-removed<br> ↳[okta-member-removed](Ps/pC_oktamemberremoved.md)<br>    | T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136 - Create Account<br>T1136.001 - Create Account: Create: Local Account<br>T1136.002 - T1136.002<br> | [<ul><li>46 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_okta_okta_adaptive_mfa_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  account-lockout<br> ↳[json-okta-account-lockout](Ps/pC_jsonoktaaccountlockout.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_okta_okta_adaptive_mfa_Brute_Force_Attack.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[okta-app-activity](Ps/pC_oktaappactivity.md)<br> ↳[okta-app-activity-ad](Ps/pC_oktaappactivityad.md)<br> ↳[s-okta-app-activity](Ps/pC_soktaappactivity.md)<br> ↳[okta-app-activity-1](Ps/pC_oktaappactivity1.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br>    | T1114.003 - Email Collection: Email Forwarding Rule<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_okta_okta_adaptive_mfa_Data_Leak.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[okta-app-activity](Ps/pC_oktaappactivity.md)<br> ↳[okta-app-activity-ad](Ps/pC_oktaappactivityad.md)<br> ↳[s-okta-app-activity](Ps/pC_soktaappactivity.md)<br> ↳[okta-app-activity-1](Ps/pC_oktaappactivity1.md)<br> ↳[cef-okta-app-activity](Ps/pC_cefoktaappactivity.md)<br> ↳[q-okta-app-activity](Ps/pC_qoktaappactivity.md)<br> ↳[cef-okta-logs-app-activity](Ps/pC_cefoktalogsappactivity.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_okta_okta_adaptive_mfa_Privilege_Escalation.md)    |
[Next Page -->>](2_ds_okta_okta_adaptive_mfa.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Privilege Escalation                                                                                                                                          | Defense Evasion                                                                                                                                                                                                                                                               | Credential Access                                                | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Create Account: Create: Local Account](https://attack.mitre.org/techniques/T1136/001)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br> |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
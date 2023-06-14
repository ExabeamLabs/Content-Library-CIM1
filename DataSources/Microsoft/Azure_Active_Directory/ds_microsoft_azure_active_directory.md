Vendor: Microsoft
=================
Product: Azure Active Directory
-------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  92   |   37   |         8          |     11      |   11    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-disabled<br> ↳[azure-ad-account-disabled](Ps/pC_azureadaccountdisabled.md)<br><br> account-password-change<br> ↳[cef-azure-password-change](Ps/pC_cefazurepasswordchange.md)<br> ↳[azure-ad-account-password-change](Ps/pC_azureadaccountpasswordchange.md)<br> ↳[azure-ad-account-password-change-1](Ps/pC_azureadaccountpasswordchange1.md)<br> ↳[azure-ad-account-password-change-2](Ps/pC_azureadaccountpasswordchange2.md)<br> ↳[azure-ad-account-password-change-3](Ps/pC_azureadaccountpasswordchange3.md)<br> ↳[s-azure-ad-password-change-2](Ps/pC_sazureadpasswordchange2.md)<br> ↳[xml-10024](Ps/pC_xml10024.md)<br> ↳[xml-10014](Ps/pC_xml10014.md)<br> ↳[xml-30028](Ps/pC_xml30028.md)<br> ↳[xml-30010](Ps/pC_xml30010.md)<br><br> account-password-reset<br> ↳[xml-30029](Ps/pC_xml30029.md)<br> ↳[xml-30009](Ps/pC_xml30009.md)<br> ↳[xml-10025](Ps/pC_xml10025.md)<br> ↳[xml-10015](Ps/pC_xml10015.md)<br><br> account-unlocked<br> ↳[azure-ad-account-unlocked](Ps/pC_azureadaccountunlocked.md)<br><br> app-activity<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br><br> app-login<br> ↳[azure-ad-app-login](Ps/pC_azureadapplogin.md)<br> ↳[s-azure-ad-app-login-2](Ps/pC_sazureadapplogin2.md)<br> ↳[s-azure-ad-app-login](Ps/pC_sazureadapplogin.md)<br> ↳[cef-o365-app-login-1](Ps/pC_cefo365applogin1.md)<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[cef-azure-user-signin](Ps/pC_cefazureusersignin.md)<br><br> authentication-failed<br> ↳[cef-azure-auth-failed](Ps/pC_cefazureauthfailed.md)<br><br> failed-app-login<br> ↳[azure-ad-app-login](Ps/pC_azureadapplogin.md)<br> ↳[s-azure-ad-app-login-2](Ps/pC_sazureadapplogin2.md)<br> ↳[s-azure-ad-app-login](Ps/pC_sazureadapplogin.md)<br> ↳[cef-o365-app-login-1](Ps/pC_cefo365applogin1.md)<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br><br> member-added<br> ↳[azure-ad-member-added](Ps/pC_azureadmemberadded.md)<br> ↳[azure-ad-member-added-1](Ps/pC_azureadmemberadded1.md)<br><br> member-removed<br> ↳[azure-ad-member-removed](Ps/pC_azureadmemberremoved.md)<br> | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_microsoft_azure_active_directory_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-change<br> ↳[cef-azure-password-change](Ps/pC_cefazurepasswordchange.md)<br> ↳[azure-ad-account-password-change](Ps/pC_azureadaccountpasswordchange.md)<br> ↳[azure-ad-account-password-change-1](Ps/pC_azureadaccountpasswordchange1.md)<br> ↳[azure-ad-account-password-change-2](Ps/pC_azureadaccountpasswordchange2.md)<br> ↳[azure-ad-account-password-change-3](Ps/pC_azureadaccountpasswordchange3.md)<br> ↳[s-azure-ad-password-change-2](Ps/pC_sazureadpasswordchange2.md)<br> ↳[xml-10024](Ps/pC_xml10024.md)<br> ↳[xml-10014](Ps/pC_xml10014.md)<br> ↳[xml-30028](Ps/pC_xml30028.md)<br> ↳[xml-30010](Ps/pC_xml30010.md)<br><br> account-password-reset<br> ↳[xml-30029](Ps/pC_xml30029.md)<br> ↳[xml-30009](Ps/pC_xml30009.md)<br> ↳[xml-10025](Ps/pC_xml10025.md)<br> ↳[xml-10015](Ps/pC_xml10015.md)<br><br> app-activity<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br><br> member-added<br> ↳[azure-ad-member-added](Ps/pC_azureadmemberadded.md)<br> ↳[azure-ad-member-added-1](Ps/pC_azureadmemberadded1.md)<br><br> member-removed<br> ↳[azure-ad-member-removed](Ps/pC_azureadmemberremoved.md)<br>    | T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136 - Create Account<br> | [<ul><li>28 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_microsoft_azure_active_directory_Account_Manipulation.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br>    | T1114.003 - Email Collection: Email Forwarding Rule<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_microsoft_azure_active_directory_Data_Leak.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br><br> app-login<br> ↳[azure-ad-app-login](Ps/pC_azureadapplogin.md)<br> ↳[s-azure-ad-app-login-2](Ps/pC_sazureadapplogin2.md)<br> ↳[s-azure-ad-app-login](Ps/pC_sazureadapplogin.md)<br> ↳[cef-o365-app-login-1](Ps/pC_cefo365applogin1.md)<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[cef-azure-user-signin](Ps/pC_cefazureusersignin.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_microsoft_azure_active_directory_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[cef-azure-ad-app-login](Ps/pC_cefazureadapplogin.md)<br> ↳[s-azure-ad-app-activity-2](Ps/pC_sazureadappactivity2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_azure_active_directory_Privilege_Escalation.md)    |
[Next Page -->>](2_ds_microsoft_azure_active_directory.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                    | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access | Discovery | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration | Impact |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------- | --------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | ------ |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |                   |           |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              |        |
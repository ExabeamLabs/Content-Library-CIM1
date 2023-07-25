|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[cef-sap-authentication-attempt-1](Ps/pC_cefsapauthenticationattempt1.md)<br> ↳[cef-sap-authentication-attempt](Ps/pC_cefsapauthenticationattempt.md)<br><br> failed-app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> file-write<br> ↳[cef-sap-file-write](Ps/pC_cefsapfilewrite.md)<br><br> gcp-bucket-create<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-compute-list<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-function-write<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-general-activity<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-instance-screenshot<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-role-list<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-serviceaccount-creds-write<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-storage-list<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-storageobject-read<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> gcp-storageobject-write<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br> | T1003.002 - T1003.002<br>T1003.003 - T1003.003<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1078.004 - Valid Accounts: Cloud Accounts<br>T1083 - File and Directory Discovery<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br>T1535 - Unused/Unsupported Cloud Regions<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br> | [<ul><li>111 Rules</li></ul><ul><li>58 Models</li></ul>](RM/r_m_sap_sap_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> authentication-failed<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[cef-sap-authentication-attempt-1](Ps/pC_cefsapauthenticationattempt1.md)<br> ↳[cef-sap-authentication-attempt](Ps/pC_cefsapauthenticationattempt.md)<br><br> failed-app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br>    | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>    | [<ul><li>32 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_sap_sap_Lateral_Movement.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[cef-sap-authentication-attempt-1](Ps/pC_cefsapauthenticationattempt1.md)<br> ↳[cef-sap-authentication-attempt](Ps/pC_cefsapauthenticationattempt.md)<br><br> file-write<br> ↳[cef-sap-file-write](Ps/pC_cefsapfilewrite.md)<br><br> gcp-storageobject-write<br> ↳[gcp-general-activity](Ps/pC_gcpgeneralactivity.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br>    | T1003.002 - T1003.002<br>T1078 - Valid Accounts<br>T1204.002 - T1204.002<br>T1505.003 - Server Software Component: Web Shell<br>T1547.001 - T1547.001<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>TA0002 - TA0002<br>    | [<ul><li>17 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_sap_sap_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br> ↳[cef-sap-account-creation](Ps/pC_cefsapaccountcreation.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br> ↳[cef-sap-account-deleted](Ps/pC_cefsapaccountdeleted.md)<br><br> account-password-change<br> ↳[sap-account-password-change](Ps/pC_sapaccountpasswordchange.md)<br> ↳[cef-sap-account-password-change](Ps/pC_cefsapaccountpasswordchange.md)<br><br> app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> failed-app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> file-download<br> ↳[cef-sap-file-download](Ps/pC_cefsapfiledownload.md)<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-write<br> ↳[cef-sap-file-write](Ps/pC_cefsapfilewrite.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br>    | T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136 - Create Account<br>T1136.001 - Create Account: Create: Local Account<br>T1136.002 - T1136.002<br>T1531 - Account Access Removal<br>    | [<ul><li>35 Rules</li></ul><ul><li>15 Models</li></ul>](RM/r_m_sap_sap_Privilege_Abuse.md)          |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> failed-app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> file-download<br> ↳[cef-sap-file-download](Ps/pC_cefsapfiledownload.md)<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-write<br> ↳[cef-sap-file-write](Ps/pC_cefsapfilewrite.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br>    | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>18 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_sap_sap_Privileged_Activity.md)       |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br><br> authentication-failed<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[cef-sap-authentication-attempt-1](Ps/pC_cefsapauthenticationattempt1.md)<br> ↳[cef-sap-authentication-attempt](Ps/pC_cefsapauthenticationattempt.md)<br><br> failed-app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> file-write<br> ↳[cef-sap-file-write](Ps/pC_cefsapfilewrite.md)<br><br> remote-logon<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br>    | T1078 - Valid Accounts<br>T1486 - Data Encrypted for Impact<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_sap_sap_Ransomware.md)    |
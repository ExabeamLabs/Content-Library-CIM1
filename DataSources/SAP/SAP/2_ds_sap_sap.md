|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|      [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)      |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_sap_sap_Brute_Force_Attack.md)    |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1133 - External Remote Services<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>    | [<ul><li>57 Rules</li></ul><ul><li>31 Models</li></ul>](RM/r_m_sap_sap_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>6 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_sap_sap_Data_Access.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br> | [<ul><li>32 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_sap_sap_Lateral_Movement.md)        |
|    [Malware](../../../UseCases/uc_malware.md)    |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1078 - Valid Accounts<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>TA0002 - TA0002<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_sap_sap_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1098 - Account Manipulation<br>T1136 - Create Account<br>T1136.001 - Create Account: Create: Local Account<br>T1136.002 - T1136.002<br>T1531 - Account Access Removal<br>    | [<ul><li>30 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_sap_sap_Privilege_Abuse.md)         |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1078 - Valid Accounts<br>T1555.005 - T1555.005<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_sap_sap_Privilege_Escalation.md)      |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>    | [<ul><li>17 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_sap_sap_Privileged_Activity.md)      |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  account-creation<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-deleted<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-lockout<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> account-unlocked<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> app-login<br> ↳[sap-failed-app-login](Ps/pC_sapfailedapplogin.md)<br><br> authentication-failed<br> ↳[sap-remote-logon](Ps/pC_sapremotelogon.md)<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-remote-logon-1](Ps/pC_sapremotelogon1.md)<br><br> authentication-successful<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br><br> failed-app-login<br> ↳[cef-sap-app-activity-3](Ps/pC_cefsapappactivity3.md)<br><br> file-download<br> ↳[cef-sap-app-activity-2](Ps/pC_cefsapappactivity2.md)<br><br> remote-logon<br> ↳[cef-sap-app-activity-1](Ps/pC_cefsapappactivity1.md)<br> ↳[sap-app-login](Ps/pC_sapapplogin.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_sap_sap_Ransomware.md)    |
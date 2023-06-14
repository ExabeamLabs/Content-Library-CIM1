Vendor: Quest Software
======================
Product: Change Auditor
-----------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  225  |   85   |         34         |     13      |   13    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-lockout<br> ↳[quest-change-account-lockout](Ps/pC_questchangeaccountlockout.md)<br> ↳[quest-account-locked](Ps/pC_questaccountlocked.md)<br><br> account-password-change<br> ↳[quest-change-account-password-change](Ps/pC_questchangeaccountpasswordchange.md)<br> ↳[quest-password-changed](Ps/pC_questpasswordchanged.md)<br> ↳[quest-password-changed-1](Ps/pC_questpasswordchanged1.md)<br><br> account-unlocked<br> ↳[quest-account-unlocked](Ps/pC_questaccountunlocked.md)<br> ↳[quest-change-account-enabled](Ps/pC_questchangeaccountenabled.md)<br><br> failed-logon<br> ↳[s-quest-failed-logon](Ps/pC_squestfailedlogon.md)<br><br> local-logon<br> ↳[quest-change-local-logon](Ps/pC_questchangelocallogon.md)<br><br> member-added<br> ↳[quest-member-added](Ps/pC_questmemberadded.md)<br> ↳[quest-change-member-added-2](Ps/pC_questchangememberadded2.md)<br> ↳[quest-change-member-added](Ps/pC_questchangememberadded.md)<br> ↳[quest-change-member-added-1](Ps/pC_questchangememberadded1.md)<br><br> member-removed<br> ↳[quest-change-member-removed-1](Ps/pC_questchangememberremoved1.md)<br> ↳[quest-change-member-removed-3](Ps/pC_questchangememberremoved3.md)<br> ↳[quest-change-member-removed-2](Ps/pC_questchangememberremoved2.md)<br> ↳[quest-member-removed-1](Ps/pC_questmemberremoved1.md)<br><br> remote-logon<br> ↳[quest-change-remote-logon](Ps/pC_questchangeremotelogon.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>    | [<ul><li>40 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_quest_software_change_auditor_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-password-change<br> ↳[quest-change-account-password-change](Ps/pC_questchangeaccountpasswordchange.md)<br> ↳[quest-password-changed](Ps/pC_questpasswordchanged.md)<br> ↳[quest-password-changed-1](Ps/pC_questpasswordchanged1.md)<br><br> ds-access<br> ↳[s-quest-directory-access](Ps/pC_squestdirectoryaccess.md)<br> ↳[q-quest-directory-access](Ps/pC_qquestdirectoryaccess.md)<br><br> failed-ds-access<br> ↳[q-quest-directory-access](Ps/pC_qquestdirectoryaccess.md)<br><br> member-added<br> ↳[quest-member-added](Ps/pC_questmemberadded.md)<br> ↳[quest-change-member-added-2](Ps/pC_questchangememberadded2.md)<br> ↳[quest-change-member-added](Ps/pC_questchangememberadded.md)<br> ↳[quest-change-member-added-1](Ps/pC_questchangememberadded1.md)<br><br> member-removed<br> ↳[quest-change-member-removed-1](Ps/pC_questchangememberremoved1.md)<br> ↳[quest-change-member-removed-3](Ps/pC_questchangememberremoved3.md)<br> ↳[quest-change-member-removed-2](Ps/pC_questchangememberremoved2.md)<br> ↳[quest-member-removed-1](Ps/pC_questmemberremoved1.md)<br>    | T1098 - Account Manipulation<br>T1136 - Create Account<br>T1207 - Rogue Domain Controller<br>T1484 - Group Policy Modification<br>    | [<ul><li>60 Rules</li></ul><ul><li>28 Models</li></ul>](RM/r_m_quest_software_change_auditor_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  account-lockout<br> ↳[quest-change-account-lockout](Ps/pC_questchangeaccountlockout.md)<br> ↳[quest-account-locked](Ps/pC_questaccountlocked.md)<br><br> failed-logon<br> ↳[s-quest-failed-logon](Ps/pC_squestfailedlogon.md)<br>    | T1021.001 - Remote Services: Remote Desktop Protocol<br>T1110 - Brute Force<br>T1110.003 - T1110.003<br>    | [<ul><li>10 Rules</li></ul>](RM/r_m_quest_software_change_auditor_Brute_Force_Attack.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  file-delete<br> ↳[quest-change-audit-file-delete](Ps/pC_questchangeauditfiledelete.md)<br><br> file-read<br> ↳[quest-change-audit-file-open](Ps/pC_questchangeauditfileopen.md)<br><br> file-write<br> ↳[quest-change-audit-file-rename](Ps/pC_questchangeauditfilerename.md)<br> ↳[quest-change-audit-file-move](Ps/pC_questchangeauditfilemove.md)<br> ↳[quest-change-audit-file-write](Ps/pC_questchangeauditfilewrite.md)<br> ↳[quest-change-audit-file-create](Ps/pC_questchangeauditfilecreate.md)<br>    | T1083 - File and Directory Discovery<br>    | [<ul><li>24 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_quest_software_change_auditor_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  file-write<br> ↳[quest-change-audit-file-rename](Ps/pC_questchangeauditfilerename.md)<br> ↳[quest-change-audit-file-move](Ps/pC_questchangeauditfilemove.md)<br> ↳[quest-change-audit-file-write](Ps/pC_questchangeauditfilewrite.md)<br> ↳[quest-change-audit-file-create](Ps/pC_questchangeauditfilecreate.md)<br>    | TA0002 - TA0002<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_quest_software_change_auditor_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  file-write<br> ↳[quest-change-audit-file-rename](Ps/pC_questchangeauditfilerename.md)<br> ↳[quest-change-audit-file-move](Ps/pC_questchangeauditfilemove.md)<br> ↳[quest-change-audit-file-write](Ps/pC_questchangeauditfilewrite.md)<br> ↳[quest-change-audit-file-create](Ps/pC_questchangeauditfilecreate.md)<br>    | T1114.001 - T1114.001<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_quest_software_change_auditor_Data_Leak.md)    |
|    [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)    |  file-delete<br> ↳[quest-change-audit-file-delete](Ps/pC_questchangeauditfiledelete.md)<br>    | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_quest_software_change_auditor_Destruction_of_Data.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  failed-logon<br> ↳[s-quest-failed-logon](Ps/pC_squestfailedlogon.md)<br><br> local-logon<br> ↳[quest-change-local-logon](Ps/pC_questchangelocallogon.md)<br><br> remote-logon<br> ↳[quest-change-remote-logon](Ps/pC_questchangeremotelogon.md)<br>    | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1021.001 - Remote Services: Remote Desktop Protocol<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1110 - Brute Force<br>T1110.003 - T1110.003<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br> | [<ul><li>44 Rules</li></ul><ul><li>14 Models</li></ul>](RM/r_m_quest_software_change_auditor_Lateral_Movement.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  failed-logon<br> ↳[s-quest-failed-logon](Ps/pC_squestfailedlogon.md)<br><br> local-logon<br> ↳[quest-change-local-logon](Ps/pC_questchangelocallogon.md)<br><br> remote-logon<br> ↳[quest-change-remote-logon](Ps/pC_questchangeremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1210 - Exploitation of Remote Services<br>T1555.005 - T1555.005<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_quest_software_change_auditor_Privilege_Escalation.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  failed-logon<br> ↳[s-quest-failed-logon](Ps/pC_squestfailedlogon.md)<br><br> file-write<br> ↳[quest-change-audit-file-rename](Ps/pC_questchangeauditfilerename.md)<br> ↳[quest-change-audit-file-move](Ps/pC_questchangeauditfilemove.md)<br> ↳[quest-change-audit-file-write](Ps/pC_questchangeauditfilewrite.md)<br> ↳[quest-change-audit-file-create](Ps/pC_questchangeauditfilecreate.md)<br><br> remote-logon<br> ↳[quest-change-remote-logon](Ps/pC_questchangeremotelogon.md)<br>    | T1078 - Valid Accounts<br>T1486 - Data Encrypted for Impact<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_quest_software_change_auditor_Ransomware.md)    |
[Next Page -->>](2_ds_quest_software_change_auditor.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                   | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Privilege Escalation                                                                                                                                                                                                                                                                                                              | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Credential Access                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                | Discovery                                                                                                                                                     | Lateral Movement                                                                                                                                                                                                                                                                                                                                    | Collection                                                            | Command and Control                                                                                                                       | Exfiltration | Impact                                                                                                                                              |
| ------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Rogue Domain Controller](https://attack.mitre.org/techniques/T1207)<br><br>[Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br>[Use Alternate Authentication Material: Pass the Ticket](https://attack.mitre.org/techniques/T1550/003)<br><br>[Valid Accounts: Local Accounts](https://attack.mitre.org/techniques/T1078/003)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br>[Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br>[OS Credential Dumping: DCSync](https://attack.mitre.org/techniques/T1003/006)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br>[Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br><br> | [Exploitation of Remote Services](https://attack.mitre.org/techniques/T1210)<br><br>[Remote Services](https://attack.mitre.org/techniques/T1021)<br><br>[Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550)<br><br>[Remote Services: Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)<br><br> | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> |              | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br>[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |
|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  authentication-successful<br> ↳[moveit-authentication-successful-1](Ps/pC_moveitauthenticationsuccessful1.md)<br><br> failed-logon<br> ↳[moveit-failed-logon-1](Ps/pC_moveitfailedlogon1.md)<br> ↳[moveit-failed-logon](Ps/pC_moveitfailedlogon.md)<br><br> file-delete<br> ↳[moveit-file-delete-2](Ps/pC_moveitfiledelete2.md)<br> ↳[moveit-file-delete](Ps/pC_moveitfiledelete.md)<br> ↳[moveit-file-delete-1](Ps/pC_moveitfiledelete1.md)<br><br> file-write<br> ↳[moveit-file-write-2](Ps/pC_moveitfilewrite2.md)<br> ↳[moveit-file-write-1](Ps/pC_moveitfilewrite1.md)<br>    | T1003.002 - T1003.002<br>T1003.003 - T1003.003<br>T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1133 - External Remote Services<br> | [<ul><li>41 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_ipswitch_moveit_dmz_Compromised_Credentials.md) |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  account-password-change<br> ↳[moveit-account-password-change](Ps/pC_moveitaccountpasswordchange.md)<br><br> failed-logon<br> ↳[moveit-failed-logon-1](Ps/pC_moveitfailedlogon1.md)<br> ↳[moveit-failed-logon](Ps/pC_moveitfailedlogon.md)<br><br> file-delete<br> ↳[moveit-file-delete-2](Ps/pC_moveitfiledelete2.md)<br> ↳[moveit-file-delete](Ps/pC_moveitfiledelete.md)<br> ↳[moveit-file-delete-1](Ps/pC_moveitfiledelete1.md)<br><br> file-download<br> ↳[moveit-file-download](Ps/pC_moveitfiledownload.md)<br> ↳[moveit-file-download-1](Ps/pC_moveitfiledownload1.md)<br><br> file-upload<br> ↳[moveit-file-upload](Ps/pC_moveitfileupload.md)<br> ↳[moveit-file-upload-2](Ps/pC_moveitfileupload2.md)<br> ↳[moveit-file-upload-3](Ps/pC_moveitfileupload3.md)<br> ↳[moveit-file-upload-1](Ps/pC_moveitfileupload1.md)<br><br> file-write<br> ↳[moveit-file-write-2](Ps/pC_moveitfilewrite2.md)<br> ↳[moveit-file-write-1](Ps/pC_moveitfilewrite1.md)<br><br> member-added<br> ↳[moveit-member-added-2](Ps/pC_moveitmemberadded2.md)<br> ↳[moveit-member-added-1](Ps/pC_moveitmemberadded1.md)<br> | T1078 - Valid Accounts<br>T1098 - Account Manipulation<br>T1136 - Create Account<br>    | [<ul><li>29 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_ipswitch_moveit_dmz_Privilege_Abuse.md)         |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  failed-logon<br> ↳[moveit-failed-logon-1](Ps/pC_moveitfailedlogon1.md)<br> ↳[moveit-failed-logon](Ps/pC_moveitfailedlogon.md)<br><br> file-delete<br> ↳[moveit-file-delete-2](Ps/pC_moveitfiledelete2.md)<br> ↳[moveit-file-delete](Ps/pC_moveitfiledelete.md)<br> ↳[moveit-file-delete-1](Ps/pC_moveitfiledelete1.md)<br><br> file-download<br> ↳[moveit-file-download](Ps/pC_moveitfiledownload.md)<br> ↳[moveit-file-download-1](Ps/pC_moveitfiledownload1.md)<br><br> file-upload<br> ↳[moveit-file-upload](Ps/pC_moveitfileupload.md)<br> ↳[moveit-file-upload-2](Ps/pC_moveitfileupload2.md)<br> ↳[moveit-file-upload-3](Ps/pC_moveitfileupload3.md)<br> ↳[moveit-file-upload-1](Ps/pC_moveitfileupload1.md)<br><br> file-write<br> ↳[moveit-file-write-2](Ps/pC_moveitfilewrite2.md)<br> ↳[moveit-file-write-1](Ps/pC_moveitfilewrite1.md)<br>    | T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_ipswitch_moveit_dmz_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  authentication-failed<br> ↳[moveit-authentication-failed](Ps/pC_moveitauthenticationfailed.md)<br> ↳[moveit-authentication-failed-1](Ps/pC_moveitauthenticationfailed1.md)<br> ↳[moveit-ssh-login-failed](Ps/pC_moveitsshloginfailed.md)<br><br> authentication-successful<br> ↳[moveit-authentication-successful-1](Ps/pC_moveitauthenticationsuccessful1.md)<br><br> failed-logon<br> ↳[moveit-failed-logon-1](Ps/pC_moveitfailedlogon1.md)<br> ↳[moveit-failed-logon](Ps/pC_moveitfailedlogon.md)<br><br> file-write<br> ↳[moveit-file-write-2](Ps/pC_moveitfilewrite2.md)<br> ↳[moveit-file-write-1](Ps/pC_moveitfilewrite1.md)<br>    | T1078 - Valid Accounts<br>T1486 - Data Encrypted for Impact<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_ipswitch_moveit_dmz_Ransomware.md)    |
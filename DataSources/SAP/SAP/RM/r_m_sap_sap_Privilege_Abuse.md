Vendor: SAP
===========
### Product: [SAP](../ds_sap_sap.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  30   |   13   |     7      |     10      |   10    |

| Event Type       | Rules    | Models    |
| ---- | ---- | ---- |
| account-creation | <b>T1098 - Account Manipulation</b><br> ↳ <b>AM-UA-MA-F-new</b>: Account management activity for new user<br> ↳ <b>AM-GA-new</b>: First account management activity for group of a new user<br><br><b>T1136 - Create Account</b><br> ↳ <b>AC-UH-F</b>: First account creation activity from asset for user<br> ↳ <b>AC-UH-A</b>: Abnormal account creation activity from asset for user<br> ↳ <b>AC-OZ-F</b>: First account creation activity from network zone<br> ↳ <b>AC-OZ-A</b>: Abnormal account creation activity from network zone<br> ↳ <b>AC-OH-F</b>: First account creation activity from asset in the organization<br> ↳ <b>AC-OH-A</b>: Abnormal account creation activity from asset in the organization<br> ↳ <b>AC-UT-TOW-A</b>: Abnormal day for user to perform account creation activity<br> ↳ <b>AM-UA-AC-F</b>: First account creation activity for user<br> ↳ <b>AM-UA-AC-A</b>: Abnormal account creation activity for user<br> ↳ <b>AM-GA-AC-F</b>: First account creation activity for peer group<br> ↳ <b>AM-GA-AC-A</b>: Abnormal account creation activity for peer group<br> ↳ <b>AM-UA-MA-F-new</b>: Account management activity for new user<br> ↳ <b>AM-GA-new</b>: First account management activity for group of a new user<br><br><b>T1136.001 - Create Account: Create: Local Account</b><br> ↳ <b>AC-LocUA-F-new</b>: First account creation activity by a new local user<br> ↳ <b>AC-LocUA-A</b>: Abnormal account creation activity by local user<br><br><b>T1136.002 - T1136.002</b><br> ↳ <b>AM-UD-F</b>: First account creation on domain for user<br> ↳ <b>AM-UD-A</b>: Abnormal account creation on domain for user |  • <b>AE-GA</b>: All activity for peer groups<br> • <b>AE-UA</b>: All activity for users<br> • <b>AC-UT-TOW</b>: Account creation activity time for user<br> • <b>AM-UD</b>: Account creation on domain by user<br> • <b>AC-OH</b>: Account creation hosts in organization<br> • <b>AC-OZ</b>: Account creation activity from zone<br> • <b>AC-UH</b>: Account creation activity on host for user |
| account-deleted  | <b>T1531 - Account Access Removal</b><br> ↳ <b>AM-UA-AD-F</b>: First account deletion activity for user    |  • <b>AE-UA</b>: All activity for users    |
| app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application    |    |
| failed-app-login | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |
| file-download    | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| remote-logon     | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-F-F-CS</b>: First logon to a critical system for user<br> ↳ <b>AL-F-A-CS</b>: Abnormal logon to a critical system for user<br> ↳ <b>AL-UH-CS-NC</b>: Logon to a critical system for a user with no information<br> ↳ <b>AL-OU-F-CS</b>: First logon to a critical system that user has not previously accessed<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-I</b>: Interactive logon using a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account    |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>AL-OU-CS</b>: Logon to critical servers<br> • <b>RA-UH</b>: Assets accessed by this user remotely<br> • <b>AL-UsH</b>: Source hosts per User<br> • <b>IL-UH-SA</b>: Interactive logon hosts for service accounts    |
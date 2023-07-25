Vendor: Cisco
=============
### Product: [Cisco Adaptive Security Appliance](../ds_cisco_cisco_adaptive_security_appliance.md)
### Use-Case: [Privilege Abuse](../../../../UseCases/uc_privilege_abuse.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  24   |   14   |     9      |     10      |   10    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| dlp-email-alert-out  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account    |    |
| file-download        | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account    |    |
| process-created      | <b>T1047 - Windows Management Instrumentation</b><br> ↳ <b>WMIC-EXE-RENAME-ORG-F</b>: First time WMIC.exe has been used to rename a user account by this user.<br> ↳ <b>WMIC-EXE-RENAME-GRP-ORG-F</b>: First time WMIC.exe has been used to rename a group by this user.<br> ↳ <b>WMIC-EXE-RENAME-ORG-A</b>: Abnormal usage of WMIC.exe to rename a group by this user.<br><br><b>T1098 - Account Manipulation</b><br> ↳ <b>NET-EXE-ADD-GRP-ORG-F</b>: First time net.exe has been used to create/add to a group by this user.<br> ↳ <b>NET-EXE-ADD-GRP-ORG-A</b>: Abnormal usage of net.exe to create/add to a group by this user.<br> ↳ <b>NET-EXE-ACTIVE-ORG-F</b>: First time net.exe has been used to disable/enable a user account by this user.<br> ↳ <b>NET-EXE-ACTIVE-ORG-A</b>: Abnormal usage of net.exe to disable/enable a user account by this user.<br> ↳ <b>WMIC-EXE-RENAME-ORG-F</b>: First time WMIC.exe has been used to rename a user account by this user.<br> ↳ <b>WMIC-EXE-RENAME-GRP-ORG-F</b>: First time WMIC.exe has been used to rename a group by this user.<br> ↳ <b>WMIC-EXE-RENAME-ORG-A</b>: Abnormal usage of WMIC.exe to rename a group by this user.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>NET-EXE-ADD-GRP-ORG-F</b>: First time net.exe has been used to create/add to a group by this user.<br> ↳ <b>NET-EXE-ADD-GRP-ORG-A</b>: Abnormal usage of net.exe to create/add to a group by this user.<br> ↳ <b>NET-EXE-ACTIVE-ORG-F</b>: First time net.exe has been used to disable/enable a user account by this user.<br> ↳ <b>NET-EXE-ACTIVE-ORG-A</b>: Abnormal usage of net.exe to disable/enable a user account by this user.<br><br><b>T1136 - Create Account</b><br> ↳ <b>NET-EXE-ADD-GRP-ORG-F</b>: First time net.exe has been used to create/add to a group by this user.<br> ↳ <b>NET-EXE-ADD-GRP-ORG-A</b>: Abnormal usage of net.exe to create/add to a group by this user.<br><br><b>T1136.001 - Create Account: Create: Local Account</b><br> ↳ <b>AC-OZ-CLI-F</b>: First zone on which account was created using CLI command<br> ↳ <b>AC-OH-CLI-F</b>: First host on which account was created using CLI command |  • <b>WMIC-EXE-RENAME-GRP-ORG</b>: Using WMIC.exe to rename a group<br> • <b>WMIC-EXE-RENAME-ORG</b>: Using WMIC.exe to rename a user account<br> • <b>NET-EXE-ACTIVE-ORG</b>: Using net.exe to disable/enable a user account<br> • <b>NET-EXE-ADD-GRP-ORG</b>: Using net.exe to add a group account<br> • <b>AC-OH-CLI</b>: Hosts on which account was created using CLI command<br> • <b>AC-OZ-CLI</b>: Zones on which account was created using CLI command |
| remote-logon         | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-F-F-CS</b>: First logon to a critical system for user<br> ↳ <b>AL-F-A-CS</b>: Abnormal logon to a critical system for user<br> ↳ <b>AL-UH-CS-NC</b>: Logon to a critical system for a user with no information<br> ↳ <b>AL-OU-F-CS</b>: First logon to a critical system that user has not previously accessed<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1078.002 - T1078.002</b><br> ↳ <b>SL-UH-I</b>: Interactive logon using a service account<br> ↳ <b>SL-UH-A</b>: Abnormal access from asset for a service account    |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>AL-OU-CS</b>: Logon to critical servers<br> • <b>RA-UH</b>: Assets accessed by this user remotely<br> • <b>AL-UsH</b>: Source hosts per User<br> • <b>IL-UH-SA</b>: Interactive logon hosts for service accounts    |
| vpn-login    | <b>T1078 - Valid Accounts</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account    |    |
| vpn-logout    | <b>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions</b><br> ↳ <b>EM-InB-Perm-A</b>: Abnormal number of mailbox permission given by user.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WPA-UACount</b>: Abnormal number of privilege access events for user    |  • <b>EM-InB-Perm</b>: Models the number of mailbox permissions given by this user.<br> • <b>WPA-UACount</b>: Count of admin privilege events for user    |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity    |    |
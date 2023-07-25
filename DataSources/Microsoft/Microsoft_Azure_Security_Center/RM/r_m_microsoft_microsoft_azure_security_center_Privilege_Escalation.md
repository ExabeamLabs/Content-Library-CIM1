Vendor: Microsoft
=================
### Product: [Microsoft Azure Security Center](../ds_microsoft_microsoft_azure_security_center.md)
### Use-Case: [Privilege Escalation](../../../../UseCases/uc_privilege_escalation.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   2   |   2    |     7      |      3      |    3    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              | Models                                                                                            |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| process-alert  | <b>T1012 - Query Registry</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1056.004 - T1056.004</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1547.006 - T1547.006</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity<br><br><b>T1560 - Archive Collected Data</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user during endpoint activity |  • <b>EPA-UP-TEMP</b>: Process executable TEMP directories for this user during endpoint activity |
| security-alert | <b>T1021.002 - Remote Services: SMB/Windows Admin Shares</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br><br><b>T1087 - Account Discovery</b><br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session          |
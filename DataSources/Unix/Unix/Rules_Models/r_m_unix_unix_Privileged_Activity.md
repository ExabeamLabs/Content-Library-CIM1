Vendor: Unix
============
### Product: [Unix](../ds_unix_unix.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   2    |     5      |     27      |   27    |

| Event Type                 | Rules                                                                                                                                                                                                                                                                                                                        | Models                                                                                 |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- |
| dlp-email-alert-in         | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                                                                |                                                                                        |
| dlp-email-alert-in-failed  | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                                                                |                                                                                        |
| dlp-email-alert-out        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                                                                |                                                                                        |
| dlp-email-alert-out-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account                                                                                                                                                                                                                |                                                                                        |
| failed-logon               | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                                                                                                                                |                                                                                        |
| file-delete                | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                            |                                                                                        |
| file-read                  | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                            |                                                                                        |
| file-write                 | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                            |                                                                                        |
| kerberos-logon             | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                                                                                                                                                                                 |  • <b>AL-HT-EXEC</b>: Executive Assets                                                 |
| local-logon                | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset                                                                                                                                                               |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| remote-access              | <b>T1021 - Remote Services</b><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-HT-EXEC-new</b>: New user remote access to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                      |  • <b>AL-HT-EXEC</b>: Executive Assets                                                 |
| remote-logon               | <b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                          |  • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets |
| security-alert             | <b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive                                                                                                                                                                                                                |                                                                                        |
| task-created               | <b>T1053.005 - Scheduled Task/Job: Scheduled Task</b><b>T1543.003 - Create or Modify System Process: Windows Service</b><br> ↳ <b>WTC-HT-EXEC</b>: Non-Executive user created a scheduled task/service on executive asset<br> ↳ <b>WTC-HT-PRIV</b>: Non-Privileged user created a scheduled task/service on privileged asset |  • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>AL-HT-EXEC</b>: Executive Assets |
Vendor: IPSwitch
================
### Product: [MoveIt DMZ](../ds_ipswitch_moveit_dmz.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  22   |   8    |     7      |      5      |    5    |

| Event Type            | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Models                                                                                                                                                                                 |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| authentication-failed | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |  • <b>UA-GC</b>: Countries for peer group<br> • <b>UA-UC</b>: Countries for user                                                                                                       |
| failed-logon          | <b>T1076 - T1076</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-03</b>: Failed logon to a top failed logon asset by user<br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account<br> ↳ <b>SEQ-UH-06</b>: Abnormal failed logon to asset by user<br> ↳ <b>SEQ-UH-07</b>: Failed logon to an asset that user has not previously accessed<br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials<br><br><b>T1097 - T1097</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1078 - Valid Accounts</b><b>T1110 - Brute Force</b><br> ↳ <b>FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST</b>: Failed logins to multiple destinations from host<br> ↳ <b>SEQ-UH-08</b>: Abnormal number of failed logons for this user<br> ↳ <b>SEQ-UH-09</b>: Abnormal time of the week for a failed logon for user<br> ↳ <b>SEQ-UH-10</b>: Failed logons had multiple reasons<br><br><b>T1075 - T1075</b><br> ↳ <b>FAIL-PTH-ALERT-sH</b>: Possible unsuccessful pass the hash attack from the source<br> ↳ <b>FAIL-PTH-ALERT-dH</b>: Possible unsuccessful pass the hash attack by the user |  • <b>FL-UH</b>: All Failed Logons per user<br> • <b>AE-UA</b>: All activity for users<br> • <b>FL-OH</b>: All Failed Logons in the organization<br> • <b>AE-OHr</b>: Random hostnames |
| file-delete           | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group                                                           |
| file-download         | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |                                                                                                                                                                                        |
| file-upload           | <b>T1078 - Valid Accounts</b><br> ↳ <b>FA-Account-deactivated</b>: File Activity from a de-activated user account                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |                                                                                                                                                                                        |
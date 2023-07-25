Vendor: McAfee
==============
### Product: [McAfee Endpoint Security](../ds_mcafee_mcafee_endpoint_security.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  49   |   25   |     8      |     11      |   11    |

| Event Type             | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| failed-app-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-FL</b>: Failed login to application<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| file-write             | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-FG-F</b>: First access to folder for group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-SFU-F</b>: First access to folder containing source code by user<br><br><b>T1003.003 - T1003.003</b><br> ↳ <b>A-NTDS-Access-F</b>: The NTDS database was accessed from a new location on this asset.<br> ↳ <b>A-NTDS-Access-A</b>: The NTDS database was accessed from a non default location on this asset.<br> ↳ <b>A-NTDS-Access</b>: The NTDS database was accessed from a non default location without 'ntds.dit' in the file path on this asset.<br> ↳ <b>A-NTDS-Shadow-Copy1</b>: The NTDS database changed location to a shadowcopy using 'ntds.dit' and 'harddiskvolumeshadowcopy' in the file path on this asset.<br> ↳ <b>A-NTDS-Shadow-Copy2</b>: The NTDS database changed location to a shadowcopy using 'harddiskvolumeshadowcopy' in the file path on this asset.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |  • <b>FA-SFU</b>: Source code folder access by users<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-FG</b>: Folder access by groups<br> • <b>A-NTDS-Access</b>: Models the amount of accesses to paths that are related to NTDS                                                                                                                                                                                                                                                                                                    |
| process-created-failed | <b>T1003.003 - T1003.003</b><br> ↳ <b>PC-Process-Hash-F</b>: First time process path creation with this hash<br> ↳ <b>PC-Process-Hash-A</b>: Abnormal for process path creation with this hash                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |  • <b>PC-Process-Hash</b>: Hashes used to create processes.<br> • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset.                                                                                                                                                                                                                                                                                                                                                                                                                               |
| remote-logon           | <b>T1078 - Valid Accounts</b><br> ↳ <b>A-AL-DhU-A</b>: Abnormal user per asset<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>AL-F-MultiWs</b>: Multiple workstations in a single session<br> ↳ <b>NEW-USER-F</b>: User with no event history<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1021 - Remote Services</b><b>T1078 - Valid Accounts</b><br> ↳ <b>RL-UH-sZ-F</b>: First remote logon to asset from new or abnormal source network zone<br> ↳ <b>RL-UH-sZ-A</b>: Abnormal remote logon to asset from new or abnormal source network zone<br> ↳ <b>RLA-UsZ-F</b>: First source network zone for user<br> ↳ <b>RLA-UsZ-A</b>: Abnormal source network zone for user<br> ↳ <b>RLA-dZsZ-F</b>: First inter-zone communication from destination to source<br> ↳ <b>RLA-sZdZ-F</b>: First inter-zone communication from source to destination<br> ↳ <b>RLA-sZdZ-A</b>: Abnormal inter-zone communication<br> ↳ <b>RL-HU-F-new</b>: Remote logon to private asset for new user<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br><br><b>T1078.003 - Valid Accounts: Local Accounts</b><br> ↳ <b>AL-HLocU-F</b>: First local user logon to this asset                                               |  • <b>RL-HU</b>: Remote logon users<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>AE-UA</b>: All activity for users<br> • <b>RLA-sZdZ</b>: Destination zone communication<br> • <b>RLA-dZsZ</b>: Source zone communication<br> • <b>RLA-UsZ</b>: Source zones for user<br> • <b>RL-UH</b>: Remote logons<br> • <b>NKL-HU</b>: Users logging into this host remotely<br> • <b>A-AL-DhU</b>: Users per Host                                                       |
| security-alert         | <b>T1078 - Valid Accounts</b><br> ↳ <b>SA-AN-ALERT-F</b>: First security alert name on the asset<br> ↳ <b>SA-ON-ALERT-F</b>: First security alert (by name) in the organization<br> ↳ <b>SA-ON-ALERT-A</b>: Abnormal security alert (by name) in the organization<br> ↳ <b>SA-ZN-ALERT-F</b>: First security alert (by name) in the zone<br> ↳ <b>SA-ZN-ALERT-A</b>: Abnormal security alert (by name) in the zone<br> ↳ <b>SA-HN-ALERT-F</b>: First security alert (by name) in the asset<br> ↳ <b>SA-HN-ALERT-A</b>: Abnormal security alert (by name) in the asset<br> ↳ <b>SA-OU-ALERT-F</b>: First security alert triggered for this user in the organization<br> ↳ <b>SA-OU-ALERT-A</b>: Abnormal user triggering security alert in the organization<br> ↳ <b>SA-OG-ALERT-F</b>: First security alert triggered for peer group in the organization<br> ↳ <b>SA-OG-ALERT-A</b>: Abnormal peer group triggering security alert in the organization<br> ↳ <b>SA-UA-F</b>: First security alert name for user<br> ↳ <b>SA-UA-A</b>: Abnormal security alert name for user<br> ↳ <b>SA-OA-F</b>: First security alert name in the organization<br> ↳ <b>SA-OA-A</b>: Abnormal security alert name in the organization<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DISTINCT-NAMES</b>: Various security alerts on asset<br> ↳ <b>A-ALERT</b>: Security alert on asset<br><br><b>T1059.001 - Command and Scripting Interperter: PowerShell</b><br> ↳ <b>A-ALERT-COMPROMISED-POWERSHELL</b>: Powershell and security alerts |  • <b>SA-OA</b>: Security alert names in the organization<br> • <b>SA-UA</b>: Security alert names for user<br> • <b>SA-OG-ALERT</b>: Peer groups triggering security alerts in the organization<br> • <b>SA-OU-ALERT</b>: Users triggering security alerts in the organization<br> • <b>A-SA-HN-ALERT</b>: Security alert names triggered by the asset<br> • <b>A-SA-ZN-ALERT</b>: Security alert names triggered in the zone<br> • <b>A-SA-ON-ALERT</b>: Security alert names triggered in the organization<br> • <b>A-SA-AN-ALERT</b>: Security alert names on asset |
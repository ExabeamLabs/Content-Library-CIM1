Vendor: VMware View
===================
### Product: [VMware View](../ds_vmware_view_vmware_view.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  92   |   45   |     11     |      5      |    5    |

| Event Type              | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-password-change | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |  • <b>AE-UA</b>: All activity for users                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| app-activity            | <br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-InB-Ex</b>: A user has been given mailbox permissions for an executive user<br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own<br> ↳ <b>InB-Perm-N-A</b>: Abnormal for user to give mailbox permissions<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-UAg-F</b>: First user agent string for user<br> ↳ <b>APP-UAg-2</b>: Second new user agent string for user<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session<br> ↳ <b>APP-UsH-F</b>: First source asset for user in application<br> ↳ <b>APP-UsH-A</b>: Abnormal source asset for user in application<br> ↳ <b>APP-UOb-F</b>: First access to application object for user<br> ↳ <b>APP-UOb-A</b>: Abnormal access to application object for user<br> ↳ <b>APP-GOb-F</b>: First access to application object for peer group<br> ↳ <b>APP-GOb-A</b>: Abnormal access to application object for peer group<br> ↳ <b>APP-UappA-F</b>: First application activity for user<br> ↳ <b>APP-UappA-A</b>: Abnormal application activity for user<br> ↳ <b>APP-GappA-F</b>: First application activity for peer group<br> ↳ <b>APP-GappA-A</b>: Abnormal application activity for peer group<br> ↳ <b>APP-AA-F</b>: First application activity in the organization<br> ↳ <b>APP-AA-A</b>: Abnormal activity in application for the organization<br> ↳ <b>APP-UId-F</b>: First use of client Id for user<br> ↳ <b>APP-IdU-F</b>: Reuse of client Id<br> ↳ <b>APP-UMime-F</b>: First mime type for user<br> ↳ <b>APP-UMime-A</b>: Abnormal mime type for user<br> ↳ <b>APP-GMime-F</b>: First mime type for peer group<br> ↳ <b>APP-GMime-A</b>: Abnormal mime type for peer group<br> ↳ <b>APP-OMime-F</b>: First mime type for organization<br> ↳ <b>APP-OMime-A</b>: Abnormal mime type for organization<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br> ↳ <b>APP-AT-PRIV</b>: Non-privileged user performing privileged application activity<br> ↳ <b>APP-ObT-PRIV</b>: Non-privileged user accessing privileged application object<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br><br><b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                   |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions<br> • <b>APP-ObT-PRIV</b>: Privileged application objects<br> • <b>APP-AT-PRIV</b>: Privileged application activities<br> • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-OMime</b>: Mime types for organization<br> • <b>APP-GMime</b>: Mime types per peer group<br> • <b>APP-UMime</b>: Mime types per user<br> • <b>APP-IdU</b>: User per Client Id<br> • <b>APP-UId</b>: Client Id per User<br> • <b>APP-AA</b>: Activity per application<br> • <b>APP-GappA</b>: Application activity per peer group<br> • <b>APP-UappA</b>: Application activity per user<br> • <b>APP-GOb</b>: Application objects per peer group<br> • <b>APP-UOb</b>: Application objects per user<br> • <b>APP-UsH</b>: User's machines accessing applications<br> • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User<br> • <b>UA-UC</b>: Countries for user<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer group<br> • <b>AE-UA</b>: All activity for users           |
| app-login               | <br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-UAg-F</b>: First user agent string for user<br> ↳ <b>APP-UAg-2</b>: Second new user agent string for user<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session<br> ↳ <b>APP-UsH-F</b>: First source asset for user in application<br> ↳ <b>APP-UsH-A</b>: Abnormal source asset for user in application<br> ↳ <b>APP-UId-F</b>: First use of client Id for user<br> ↳ <b>APP-IdU-F</b>: Reuse of client Id<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br><br><b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |  • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-IdU</b>: User per Client Id<br> • <b>APP-UId</b>: Client Id per User<br> • <b>APP-UsH</b>: User's machines accessing applications<br> • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User<br> • <b>UA-UC</b>: Countries for user<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer group<br> • <b>AE-UA</b>: All activity for users                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| failed-app-login        | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-Account-deactivated</b>: Activity from a de-activated user account<br> ↳ <b>APP-F-FL</b>: Failed login to application<br><br><b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost-Failed</b>: User authentication or login failure from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost-Failed</b>: User authentication or login failure from a known ransomware IP<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |  • <b>UA-GC</b>: Countries for peer group<br> • <b>UA-UC</b>: Countries for user                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| remote-logon            | <br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br><br><br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>AL-HLocU-F</b>: First local user logon to this asset<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>AL-F-MultiWs</b>: Multiple workstations in a single session<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>AL-HT-EXEC-new</b>: New user logon to executive asset<br> ↳ <b>DC18-new</b>: Account switch by new user<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RL-UH-sZ-F</b>: First remote logon to asset from new or abnormal source network zone<br> ↳ <b>RL-UH-sZ-A</b>: Abnormal remote logon to asset from new or abnormal source network zone<br> ↳ <b>RLA-UsZ-F</b>: First source network zone for user<br> ↳ <b>RLA-UsZ-A</b>: Abnormal source network zone for user<br> ↳ <b>RLA-UsH-dZ-F</b>: First remote access to zone from new asset<br> ↳ <b>RLA-UsH-dZ-A</b>: Abnormal remote access to zone from new asset<br> ↳ <b>RLA-dZsZ-F</b>: First inter-zone communication from destination to source<br> ↳ <b>RLA-sZdZ-F</b>: First inter-zone communication from source to destination<br> ↳ <b>RLA-sZdZ-A</b>: Abnormal inter-zone communication<br> ↳ <b>RL-HU-F-new</b>: Remote logon to private asset for new user<br><br><b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user<br><br><b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP<br><br><b>T1208 - T1208</b><br> ↳ <b>A-KL-UToE-A</b>: Abnormal kerberos ticket options and encryption type for asset<br> ↳ <b>A-KL-ToEt</b>: Suspicious or weak encryption type used for obtaining the kerberos TGTs for this asset<br> ↳ <b>KL-ToEt</b>: Suspicious or weak encryption type used for obtaining kerberos TGTs<br> ↳ <b>KL-OEt-F</b>: First kerberos ticket encryption type for organization<br> ↳ <b>KL-OEt-A</b>: Abnormal kerberos ticket encryption type for organization<br> ↳ <b>KL-OTo-F</b>: First kerberos ticket options for organization<br> ↳ <b>KL-OTo-A</b>: Abnormal kerberos ticket options for organization<br> ↳ <b>KL-UTo-F</b>: First kerberos ticket options for user<br> ↳ <b>KL-UTo-A</b>: Abnormal kerberos ticket options for user<br> ↳ <b>KL-UToE-F</b>: First kerberos ticket options and encryption type combination for user<br> ↳ <b>KL-UToE-A</b>: Abnormal kerberos ticket options and encryption type for user<br><br><b>T1068 - Exploitation for Privilege Escalation</b><br> ↳ <b>ALERT-EXEC</b>: Security violation by Executive<br> ↳ <b>AL-HT-PRIV</b>: Non-Privileged logon to privileged asset<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>AS-PV-UHWoPC</b>: Access to Password Vault managed asset with no password checkout for user<br><br><b>T1075 - T1075</b><br> ↳ <b>A-PTH-ALERT-sH</b>: Possible pass the hash attack from this source host<br> ↳ <b>PTH-ALERT-sH</b>: Possible pass the hash attack from the source<br> ↳ <b>NTLM-mismatch</b>: <br><br><b>T1033 - System Owner/User Discovery</b><br> ↳ <b>A-AL-DhU-A</b>: Abnormal user per asset |  • <b>RL-HU</b>: Remote logon users<br> • <b>AL-HT-EXEC</b>: Executive Assets<br> • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>KL-UToE</b>: Ticket options and encryption type combination for user<br> • <b>KL-OTo</b>: Ticket Options for organization<br> • <b>KL-OEt</b>: Encryption Types for organization<br> • <b>AL-HT-PRIV</b>: Privilege Users Assets<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer group<br> • <b>UA-UC</b>: Countries for user<br> • <b>AS-PV-OA</b>: Password retrieval based accounts<br> • <b>AE-NTLM</b>: Models ntlm hostnames in the organization<br> • <b>AE-OHr</b>: Random hostnames<br> • <b>AE-UA</b>: All activity for users<br> • <b>RLA-sZdZ</b>: Destination zone communication<br> • <b>RLA-dZsZ</b>: Source zone communication<br> • <b>AL-UsH</b>: Source hosts per User<br> • <b>RLA-UsZ</b>: Source zones for user<br> • <b>RL-UH</b>: Remote logons<br> • <b>NKL-HU</b>: Users logging into this host remotely<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset<br> • <b>A-KL-UToE</b>: Ticket options and encryption type combination for asset<br> • <b>A-AE-OHr</b>: Random hostnames on asset<br> • <b>A-AL-DhU</b>: Users per Host |
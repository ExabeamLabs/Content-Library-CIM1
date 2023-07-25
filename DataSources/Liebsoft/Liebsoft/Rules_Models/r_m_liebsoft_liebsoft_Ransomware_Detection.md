Vendor: Liebsoft
================
### Product: [Liebsoft](../ds_liebsoft_liebsoft.md)
### Use-Case: [Ransomware Detection](../../../../UseCases/uc_ransomware_detection.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   2    |     2      |      2      |    2    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models                                                                                                                                                                      |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| account-switch | <b>T1204 - User Execution</b><br> ↳ <b>EPA-TEMP-DIRECTORY-F</b>: First execution of this process from a temporary directory on this asset<br> ↳ <b>EPA-TEMP-DIRECTORY-A</b>: Abnormal execution of this process from a temporary directory<br> ↳ <b>DEF-TEMP-DIRECTORY-F</b>: First time process has been executed from a temporary directory by this user<br> ↳ <b>DEF-TEMP-DIRECTORY-A</b>: Abnormal process has been executed from a temporary directory by this user |  • <b>AE-UP-TEMP</b>: Process executable TEMP directories for this user during a session<br> • <b>A-EPA-UP-TEMP</b>: Processes executed from TEMP directories on this asset |
| app-login      | <b>T1188 - T1188</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br> ↳ <b>Auth-Blacklist-Shost</b>: User authentication or login from a known blacklisted IP<br> ↳ <b>Auth-Ransomware-Shost</b>: User authentication or login from a known ransomware IP                                                                                                                                                                               |                                                                                                                                                                             |
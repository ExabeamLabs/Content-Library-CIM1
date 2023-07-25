Vendor: BeyondTrust
===================
### Product: [BeyondTrust Privilege Management](../ds_beyondtrust_beyondtrust_privilege_management.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  39   |   11   |     9      |      2      |    2    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| local-logon     | <b>T1078.003 - Valid Accounts: Local Accounts</b><br> ↳ <b>AL-HLocU-F</b>: First local user logon to this asset<br> ↳ <b>LL-GH-A-new</b>: Abnormal local logon to asset for group by new user<br> ↳ <b>LL-HU-F-new</b>: Local logon to private asset for new user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>A-AL-DhU-A</b>: Abnormal user per asset<br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>AL-F-MultiWs</b>: Multiple workstations in a single session<br> ↳ <b>NEW-USER-F</b>: User with no event history                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |  • <b>LL-HU</b>: Local logon users<br> • <b>LL-GH</b>: Local logon hosts (peer groups)<br> • <b>AE-UA</b>: All activity for users<br> • <b>NKL-HU</b>: Users logging into this host remotely<br> • <b>A-AL-DhU</b>: Users per Host                                                                                                                                                                                                                                            |
| process-created | <b>T1003.003 - T1003.003</b><br> ↳ <b>PC-Process-Hash-F</b>: First time process path creation with this hash<br> ↳ <b>PC-Process-Hash-A</b>: Abnormal for process path creation with this hash<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-Rubeus-CMD-Tool</b>: Command line parameters used by Rubeus hack tool detected on this asset<br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>A-CreateMiniDump-Hacktool</b>: CreateMiniDump Hacktool detected on this asset.<br> ↳ <b>A-LSASS-Mem-Dump</b>: LSASS Memory Dumping detected on this asset<br> ↳ <b>A-GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility on this asset<br> ↳ <b>A-ShadowCP-OSUtilities</b>: Shadow Copies Creation Using Operating Systems Utilities on this asset<br> ↳ <b>A-Procdump-Comsvcs-DLL</b>: Process Dump via Comsvcs DLL on this asset<br> ↳ <b>A-Cmdkey-Cred-Recon</b>: Cmdkey Cached Credentials Recon on this asset<br> ↳ <b>Mimikatz-process</b>: A highly dangerous attacker tool, Mimikatz, has been used<br> ↳ <b>Rubeus-CMD-Tool</b>: Command line parameters used by Rubeus hack tool detected<br> ↳ <b>LSASS-Mem-Dump</b>: LSASS Memory Dumping<br> ↳ <b>GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility<br><br><b>T1040 - Network Sniffing</b><br> ↳ <b>A-NSniff-Cred</b>: Potential network sniffing was observed on this asset.<br> ↳ <b>A-EPA-SNIFF</b>: Network sniffing tool has been found running on this asset<br> ↳ <b>EPA-SNIFF</b>: Network sniffing tool has been run by this user<br> ↳ <b>EPA-OU-SNIFF-F</b>: First time this user has run a network sniffing tool<br> ↳ <b>EPA-OU-SNIFF-A</b>: Abnormal user has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-F</b>: First time this peer group has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-A</b>: Abnormal peer group running a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-F</b>: First time this host has run a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-A</b>: Abnormal host running a network sniffing tool<br> ↳ <b>EPA-OZ-SNIFF-F</b>: First time this network zone on which a networking sniffing tool run.<br> ↳ <b>EPA-OZ-SNIFF-A</b>: Abnormal network zone on which network sniffing tool was run<br><br><b>T1016 - System Network Configuration Discovery</b><br> ↳ <b>WINCMD-Ipconfig</b>: 'Ipconfig' program used<br> ↳ <b>WINCMD-Route</b>: 'Route' program used<br> ↳ <b>WINCMD-Netsh</b>: 'Netsh' program used<br><br><b>T1003 - OS Credential Dumping</b><b>T1036 - Masquerading</b><br> ↳ <b>A-Proc-Dump-Comsvcs</b>: Process Dump via Rundll32 and Comsvcs.dll detected on this asset<br> ↳ <b>A-Sus-Procdump</b>: Suspicious Use of Procdump on this asset.<br><br><b>T1547.004 - T1547.004</b><br> ↳ <b>A-SecX-Tool-Exec</b>: SecurityXploded Tool execution detected on this asset<br><br><b>T1059.001 - Command and Scripting Interperter: PowerShell</b><br> ↳ <b>A-ALERT-COMPROMISED-POWERSHELL</b>: Powershell and security alerts |  • <b>PC-Process-Hash</b>: Hashes used to create processes.<br> • <b>EPA-OZ-SNIFF</b>: Network Zones on which network sniffing tools are run<br> • <b>EPA-OH-SNIFF</b>: Hosts that have been found to be running network sniffing tools<br> • <b>EPA-OG-SNIFF</b>: Peer groups that are running network sniffing tools<br> • <b>EPA-OU-SNIFF</b>: Users that are running network sniffing tools<br> • <b>A-PC-Process-Hash</b>: Hashes used to create processes on the asset. |
Vendor: Huawei
==============
### Product: [Unified Security Gateway](../ds_huawei_unified_security_gateway.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  83   |   22   |         14         |      4      |    4    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries    |  • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-UI-new</b>: ISP of users during application activity    |
| network-alert    | <b>T1190 - Exploit Public Fasing Application</b><br> ↳ <b>A-Log4j-Vul-Alert</b>: Alert for the CVE-2021-44228 vulnerability on the asset.<br> ↳ <b>Log4j-Vul-Alert</b>: Alert for the CVE-2021-44228 vulnerability<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-Other</b>: Alert on asset<br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset<br> ↳ <b>A-ALERT-Log4j</b>: Alert associated with an exploitation or post exploitation as seen with Log4j Vulnerability was detected.<br> ↳ <b>A-IDS-OLA-F</b>: First network alert on asset with no previous alerts for organization<br> ↳ <b>A-IDS-OLA-A</b>: Abnormal network alert for asset for organization<br> ↳ <b>A-IDS-ZLA-F</b>: First network alert on asset with no previous alerts for zone<br> ↳ <b>A-IDS-ZLA-A</b>: Abnormal network alert for asset for zone<br> ↳ <b>A-IDS-OLZ-F</b>: First network alert for zone in the organization<br> ↳ <b>A-IDS-OLZ-A</b>: Abnormal network alert for zone in the organization<br> ↳ <b>A-IDS-OdPort-F</b>: First network alert on port for organization<br> ↳ <b>A-IDS-OdPort-A</b>: Abnormal network alert on port for organization<br> ↳ <b>A-IDS-HdPort-F</b>: First network alert on port for asset<br> ↳ <b>A-IDS-HdPort-A</b>: Abnormal network alert on port for asset<br> ↳ <b>A-IDS-dZdPort-F</b>: First network alert on port for zone<br> ↳ <b>A-IDS-dZdPort-A</b>: Abnormal network alert on port for zone<br> ↳ <b>A-IDS-LZAN-F</b>: First network alert (by name) for zone<br> ↳ <b>A-IDS-LZAN-A</b>: Abnormal network alert (by name) for zone<br> ↳ <b>A-IDS-OAN-F</b>: First network alert (by name) for organization<br> ↳ <b>A-IDS-OAN-A</b>: Abnormal network alert (by name) for organization<br> ↳ <b>A-IDS-SERVER</b>: First or Abnormal network alert in server zone    |  • <b>A-AL-ZT-SERVER</b>: Server zones based on number of servers<br> • <b>A-IDS-OAN</b>: Network alert names triggered in the organization<br> • <b>A-IDS-LZAN</b>: Network alert names triggered in zone<br> • <b>A-IDS-dZdPort</b>: Destination ports on which network alerts have triggered in zone<br> • <b>A-IDS-HdPort</b>: Destination ports on which network alerts have triggered for the asset<br> • <b>A-IDS-OdPort</b>: Destination ports on which network alerts have triggered in the organization<br> • <b>A-IDS-OLZ</b>: Zones in which network alerts are triggered in the organization<br> • <b>A-IDS-ZLA</b>: Assets that triggered network alerts in the zone<br> • <b>A-IDS-OLA</b>: Assets that triggered network alerts in the organization |
| process-created    | <b>T1003.002 - T1003.002</b><br> ↳ <b>A-GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility on this asset<br> ↳ <b>GRAB-REG-HIVES</b>: Grabbing Sensitive Hives via Reg Utility<br> ↳ <b>ATP-PWDump</b>: Malicious exe was run which is a part of credential dumping tool<br><br><b>T1003.001 - T1003.001</b><br> ↳ <b>A-CreateMiniDump-Hacktool</b>: CreateMiniDump Hacktool detected on this asset.<br> ↳ <b>A-LSASS-Mem-Dump</b>: LSASS Memory Dumping detected on this asset<br> ↳ <b>A-Proc-Dump-Comsvcs</b>: Process Dump via Rundll32 and Comsvcs.dll detected on this asset<br> ↳ <b>A-Sus-Procdump</b>: Suspicious Use of Procdump on this asset.<br> ↳ <b>A-Procdump-Comsvcs-DLL</b>: Process Dump via Comsvcs DLL on this asset<br> ↳ <b>A-PC-Rundll-LsassDump</b>: Rundll32 was run with minidump via commandline on this asset.<br> ↳ <b>A-PC-Procdump-LsassDump</b>: Procdump was executed with lsass dump command line parameters on this asset.<br> ↳ <b>CreateMiniDump-Hacktool</b>: CreateMiniDump Hacktool<br> ↳ <b>LSASS-Mem-Dump</b>: LSASS Memory Dumping<br> ↳ <b>Proc-Dump-Comsvcs</b>: Process Dump via Rundll32 and Comsvcs.dll<br> ↳ <b>Sus-Procdump</b>: Suspicious Use of Procdump<br> ↳ <b>Procdump-Comsvcs-DLL</b>: Process Dump via Comsvcs DLL<br> ↳ <b>PC-Rundll-LsassDump</b>: Rundll32 was run with minidump via commandline<br> ↳ <b>PC-Procdump-LsassDump</b>: Procdump was executed with lsass dump command line parameters.<br><br><b>T1218.011 - Signed Binary Proxy Execution: Rundll32</b><br> ↳ <b>A-Procdump-Comsvcs-DLL</b>: Process Dump via Comsvcs DLL on this asset<br> ↳ <b>A-PC-Rundll-LsassDump</b>: Rundll32 was run with minidump via commandline on this asset.<br> ↳ <b>Procdump-Comsvcs-DLL</b>: Process Dump via Comsvcs DLL<br> ↳ <b>PC-Rundll-LsassDump</b>: Rundll32 was run with minidump via commandline<br><br><b>T1040 - Network Sniffing</b><br> ↳ <b>A-NSniff-Cred</b>: Potential network sniffing was observed on this asset.<br> ↳ <b>A-EPA-SNIFF</b>: Network sniffing tool has been found running on this asset<br> ↳ <b>A-EPA-OH-SNIFF-F</b>: First time this asset has had an execution of a network sniffing tool<br> ↳ <b>A-EPA-OH-SNIFF-A</b>: Abnormal asset running network sniffing tool<br> ↳ <b>A-EPA-OZ-SNIFF-F</b>: First zone on which network sniffing tool was run<br> ↳ <b>A-EPA-OZ-SNIFF-A</b>: Abnormal zone on which network sniffing tool was run<br> ↳ <b>EPA-SNIFF</b>: Network sniffing tool has been run by this user<br> ↳ <b>EPA-OU-SNIFF-F</b>: First time this user has run a network sniffing tool<br> ↳ <b>EPA-OU-SNIFF-A</b>: Abnormal user has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-F</b>: First time this peer group has run a network sniffing tool<br> ↳ <b>EPA-OG-SNIFF-A</b>: Abnormal peer group running a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-F</b>: First time this host has run a network sniffing tool<br> ↳ <b>EPA-OH-SNIFF-A</b>: Abnormal host running a network sniffing tool<br> ↳ <b>EPA-OZ-SNIFF-F</b>: First time this network zone on which a networking sniffing tool run.<br> ↳ <b>EPA-OZ-SNIFF-A</b>: Abnormal network zone on which network sniffing tool was run<br> ↳ <b>NSniff-Cred</b>: Potential network sniffing was observed<br><br><b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>A-ShadowCP-SymLink</b>: Shadow Copies Access via Symlink on this asset<br> ↳ <b>A-ShadowCP-OSUtilities</b>: Shadow Copies Creation Using Operating Systems Utilities on this asset<br> ↳ <b>Mimikatz-process</b>: A highly dangerous attacker tool, Mimikatz, has been used<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data<br> ↳ <b>ShadowCP-SymLink</b>: Shadow Copies Access via Symlink<br> ↳ <b>ShadowCP-OSUtilities</b>: Shadow Copies Creation Using Operating Systems Utilities<br> ↳ <b>Cmdkey-Cred-Recon</b>: Cmdkey Cached Credentials Recon<br><br><b>T1003.003 - T1003.003</b><br> ↳ <b>AD-Diagnostic-Tool</b>: Invocation of Active Directory Diagnostic Tool (ntdsutil.exe)<br><br><b>T1555 - Credentials from Password Stores</b><br> ↳ <b>A-SecX-Tool-Exec</b>: SecurityXploded Tool execution detected on this asset<br> ↳ <b>SecX-Tool-Exec</b>: SecurityXploded Tool execution detected<br><br><b>T1016 - System Network Configuration Discovery</b><br> ↳ <b>WINCMD-Route</b>: 'Route' program used<br> ↳ <b>WINCMD-Netsh</b>: 'Netsh' program used<br><br><b>TA0002 - TA0002</b><br> ↳ <b>EPA-UH-Pen-F</b>: Known pentest tool used<br><br><b>T1003.005 - T1003.005</b><br> ↳ <b>A-Cmdkey-Cred-Recon</b>: Cmdkey Cached Credentials Recon on this asset |  • <b>EPA-OZ-SNIFF</b>: Network Zones on which network sniffing tools are run<br> • <b>EPA-OH-SNIFF</b>: Hosts that have been found to be running network sniffing tools<br> • <b>EPA-OG-SNIFF</b>: Peer groups that are running network sniffing tools<br> • <b>EPA-OU-SNIFF</b>: Users that are running network sniffing tools<br> • <b>EPA-UH-Pen</b>: Malicious tools used by user    |
| vpn-login    | <b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>AE-UA-F-VPN</b>: First VPN connection for user<br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>VPN-GsH-A</b>: Abnormal VPN connection from device for peer group<br> ↳ <b>AE-GA-F-VPN-new</b>: First VPN connection for group of new user<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries<br> ↳ <b>PA-VPN-01</b>: VPN login after badge access<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>AE-UA-F-VPN</b>: First VPN connection for user<br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries    |  • <b>PA-VPN-01</b>: Users who vpn-in after badge access<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>AE-GA</b>: All activity for peer groups<br> • <b>VPN-GsH</b>: VPN endpoints in this peer group<br> • <b>UA-UI-new</b>: ISP of users during application activity<br> • <b>AE-UA</b>: All activity for users    |
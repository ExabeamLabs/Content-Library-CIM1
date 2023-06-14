Vendor: Citrix
==============
### Product: [Citrix XenApp](../ds_citrix_citrix_xenapp.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  31   |   14   |         9          |      2      |    2    |

| Event Type   | Rules    | Models    |
| ---- | ---- | ---- |
| app-login    | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |    |
| remote-logon | <b>T1021 - Remote Services</b><br> ↳ <b>A-RLA-sHdZ-F</b>: First remote access to zone from asset<br> ↳ <b>A-RLA-sHdZ-A</b>: Abnormal remote access to zone from asset<br> ↳ <b>A-RLA-dHsZ-F</b>: First remote access from zone to asset<br> ↳ <b>A-RLA-dHsZ-A</b>: Abnormal remote access from zone to asset<br> ↳ <b>RL-UH-sZ-F</b>: First remote logon to asset from new or abnormal source network zone<br> ↳ <b>RL-UH-sZ-A</b>: Abnormal remote logon to asset from new or abnormal source network zone<br> ↳ <b>RLA-UsZ-F</b>: First source network zone for user<br> ↳ <b>RLA-UsZ-A</b>: Abnormal source network zone for user<br> ↳ <b>RLA-UsH-dZ-F</b>: First remote access to zone from new asset<br> ↳ <b>RLA-UsH-dZ-A</b>: Abnormal remote access to zone from new asset<br> ↳ <b>RLA-dZsZ-F</b>: First inter-zone communication from destination to source<br> ↳ <b>RLA-sZdZ-F</b>: First inter-zone communication from source to destination<br> ↳ <b>RLA-sZdZ-A</b>: Abnormal inter-zone communication<br> ↳ <b>RL-UH-F</b>: First remote logon to asset<br> ↳ <b>RL-UH-A</b>: Abnormal remote logon to asset<br> ↳ <b>RL-GH-F</b>: First remote logon to asset for group<br> ↳ <b>RL-GH-A-new</b>: Abnormal remote logon to asset for group by new user<br> ↳ <b>RL-HU-F-new</b>: Remote logon to private asset for new user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>RL-UH-sZ-F</b>: First remote logon to asset from new or abnormal source network zone<br> ↳ <b>RL-UH-sZ-A</b>: Abnormal remote logon to asset from new or abnormal source network zone<br> ↳ <b>RLA-UsZ-F</b>: First source network zone for user<br> ↳ <b>RLA-UsZ-A</b>: Abnormal source network zone for user<br> ↳ <b>RLA-UsH-dZ-F</b>: First remote access to zone from new asset<br> ↳ <b>RLA-UsH-dZ-A</b>: Abnormal remote access to zone from new asset<br> ↳ <b>RLA-dZsZ-F</b>: First inter-zone communication from destination to source<br> ↳ <b>RLA-sZdZ-F</b>: First inter-zone communication from source to destination<br> ↳ <b>RLA-sZdZ-A</b>: Abnormal inter-zone communication<br> ↳ <b>RL-UH-F</b>: First remote logon to asset<br> ↳ <b>RL-UH-A</b>: Abnormal remote logon to asset<br> ↳ <b>RL-GH-F</b>: First remote logon to asset for group<br> ↳ <b>RL-GH-A-new</b>: Abnormal remote logon to asset for group by new user<br> ↳ <b>RL-HU-F-new</b>: Remote logon to private asset for new user<br><br><b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>A-AE-SwSh-F</b>: New server hostname using NTLM authentication in the organization.<br> ↳ <b>A-NTLM-WsSrv</b>: Hostname contains workstation or server<br> ↳ <b>A-NTLM-mismatch</b>: Mismatch between logged and resolved hostnames<br> ↳ <b>A-PTH-ALERT-sH-Possible</b>: Possible pass the hash attack with keylength of 0 in NTLM event and a 'null' sid on this source host.<br> ↳ <b>AE-NTLM-WsSrv</b>: New generic hostname found using ntlm authentication<br> ↳ <b>NTLM-mismatch</b>: <br> ↳ <b>PTH-ALERT-sH-Possible</b>: Possible pass the hash attack with keylength of 0 in NTLM event and a 'null' sid.<br><br><b>T1550 - Use Alternate Authentication Material</b><br> ↳ <b>RLA-UAPackage-F</b>: First time usage of Windows authentication package<br> ↳ <b>RLA-UAPackage-A</b>: Abnormal usage of Windows authentication package<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP<br><br><b>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting</b><br> ↳ <b>A-KL-ToEt-Roast</b>: Suspicious or weak encryption type used for obtaining the kerberos TGTs using non kerberos service for this asset<br> ↳ <b>KL-ToEt-Roast</b>: Suspicious or weak encryption type used for obtaining kerberos TGTs using non kerberos service<br><br><b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>EXPERT-PENTEST-DOMAINS</b>: Possible credentials theft attack detected<br><br><b>T1018 - Remote System Discovery</b><br> ↳ <b>A-RLA-sHdZ-F</b>: First remote access to zone from asset<br> ↳ <b>A-RLA-sHdZ-A</b>: Abnormal remote access to zone from asset<br> ↳ <b>A-RLA-dHsZ-F</b>: First remote access from zone to asset<br> ↳ <b>A-RLA-dHsZ-A</b>: Abnormal remote access from zone to asset |  • <b>RL-HU</b>: Remote logon users<br> • <b>RL-GH-A</b>: Assets accessed remotely by this peer group<br> • <b>RLA-UAPackage</b>: Windows authentication packages used when connecting to remote hosts<br> • <b>RL-UH</b>: Remote logons<br> • <b>AE-NTLM</b>: Models ntlm hostnames in the organization<br> • <b>AE-OHr</b>: Random hostnames<br> • <b>RLA-sZdZ</b>: Destination zone communication<br> • <b>RLA-dZsZ</b>: Source zone communication<br> • <b>AL-UsH</b>: Source hosts per User<br> • <b>RLA-UsZ</b>: Source zones for user<br> • <b>A-AE-OHr</b>: Random hostnames on asset<br> • <b>A-AE-NTLM</b>: Models the NTLM hostnames seen in the organization<br> • <b>A-RLA-dHsZ</b>: Destination Host to Source zone communication<br> • <b>A-RLA-sHdZ</b>: Source Host to Destination zone communication |
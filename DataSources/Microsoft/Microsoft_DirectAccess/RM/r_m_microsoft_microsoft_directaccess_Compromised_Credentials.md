Vendor: Microsoft
=================
### Product: [Microsoft DirectAccess](../ds_microsoft_microsoft_directaccess.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  31   |   11   |     3      |      2      |    2    |

| Event Type     | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| security-alert | <b>T1078 - Valid Accounts</b><br> ↳ <b>A-SA-AN-ALERT-F</b>: First security alert name on the asset<br> ↳ <b>A-SA-ON-ALERT-F</b>: First security alert (by name) in the organization<br> ↳ <b>A-SA-ON-ALERT-A</b>: Abnormal security alert (by name) in the organization<br> ↳ <b>A-SA-ZN-ALERT-F</b>: First security alert (by name) in the zone<br> ↳ <b>A-SA-ZN-ALERT-A</b>: Abnormal security alert (by name) in the zone<br> ↳ <b>A-SA-HN-ALERT-F</b>: First security alert (by name) in the asset<br> ↳ <b>A-SA-HN-ALERT-A</b>: Abnormal security alert (by name) in the asset<br> ↳ <b>A-SA-OA-ALERT-F</b>: First security alert for this asset for organization<br> ↳ <b>SA-OU-ALERT-F</b>: First security alert triggered for this user in the organization<br> ↳ <b>SA-OU-ALERT-A</b>: Abnormal user triggering security alert in the organization<br> ↳ <b>SA-OG-ALERT-F</b>: First security alert triggered for peer group in the organization<br> ↳ <b>SA-OG-ALERT-A</b>: Abnormal peer group triggering security alert in the organization<br> ↳ <b>SA-UA-F</b>: First security alert name for user<br> ↳ <b>SA-UA-A</b>: Abnormal security alert name for user<br> ↳ <b>SA-GA-F</b>: First security alert name in the peer group<br> ↳ <b>SA-GA-A</b>: Abnormal security alert name in the peer group<br> ↳ <b>SA-OA-F</b>: First security alert name in the organization<br> ↳ <b>SA-OA-A</b>: Abnormal security alert name in the organization<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>ALERT-VPN</b>: Security Alert on asset accessed by this user during VPN session<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-Critical</b>: Security Alert on a critical asset |  • <b>SA-OA</b>: Security alert names in the organization<br> • <b>SA-GA</b>: Security alert names in the peer group<br> • <b>SA-OG-ALERT</b>: Peer groups triggering security alerts in the organization<br> • <b>SA-OU-ALERT</b>: Users triggering security alerts in the organization<br> • <b>A-SA-OA-ALERT</b>: Assets triggering security alerts in the organization<br> • <b>A-SA-HN-ALERT</b>: Security alert names triggered by the asset<br> • <b>A-SA-ZN-ALERT</b>: Security alert names triggered in the zone<br> • <b>A-SA-ON-ALERT</b>: Security alert names triggered in the organization<br> • <b>A-SA-AN-ALERT</b>: Security alert names on asset |
| vpn-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>SL-UA-F-VPN</b>: First VPN connection for service account<br> ↳ <b>VPN02</b>: VPN source IP address is malicious<br> ↳ <b>VPN09</b>: VPN access by executive user<br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>VPN-GsH-F</b>: First VPN connection from device for peer group<br> ↳ <b>VPN29</b>: VPN connection from a known anonymous proxy<br> ↳ <b>VPN30</b>: VPN connections from multiple WAN IPs<br> ↳ <b>VPN31</b>: VPN connection using a disabled account<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |  • <b>VPN-GsH</b>: VPN endpoints in this peer group<br> • <b>UA-UI-new</b>: ISP of users during application activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
Vendor: Okta
============
### Product: [Okta Adaptive MFA](../ds_okta_okta_adaptive_mfa.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   3    |     10     |     12      |   12    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-activity          | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |    |
| app-activity-failed   | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP    |    |
| app-login    | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |    |
| authentication-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP    |    |
| failed-app-login      | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP    |    |
| failed-logon          | <b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>A-PTH-ALERT-sH-Failed</b>: Failed pass the hash attack with keylength of 0 in NTLM event and a 'null' sid on this source host.<br> ↳ <b>FAIL-PTH-ALERT-sH</b>: Possible unsuccessful pass the hash attack from the source<br> ↳ <b>FAIL-PTH-ALERT-dH</b>: Possible unsuccessful pass the hash attack by the user<br> ↳ <b>PTH-ALERT-sH-Failed</b>: Failed pass the hash attack with keylength of 0 in NTLM event and a 'null' sid.<br><br><b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-S</b>: Multiple users failed to login (S)<br> ↳ <b>A-FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>A-FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST-S</b>: Failed logins to multiple destinations from host (S)<br> ↳ <b>A-FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1110.003 - T1110.003</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users |  • <b>AE-OHr</b>: Random hostnames    |
| nac-logon    | <b>T1078 - Valid Accounts</b><br> ↳ <b>NAC-UL-F</b>: First network location for user<br> ↳ <b>NAC-UL-A</b>: Abnormal network location for user<br> ↳ <b>NAC-UM-F</b>: First MAC for user<br> ↳ <b>NAC-UM-A</b>: Abnormal MAC for user<br><br><b>T1021 - Remote Services</b><br> ↳ <b>NAC-UL-F</b>: First network location for user<br> ↳ <b>NAC-UL-A</b>: Abnormal network location for user    |  • <b>NAC-UM</b>: MAC addresses for user<br> • <b>NAC-UL</b>: Network locations for user |
| security-alert        | <b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DL</b>: DL Correlation rule alert on asset<br> ↳ <b>ALERT-DL</b>: DL Correlation rule alert on asset accessed by this user    |    |
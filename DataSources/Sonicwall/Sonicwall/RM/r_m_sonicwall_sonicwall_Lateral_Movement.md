Vendor: Sonicwall
=================
### Product: [Sonicwall](../ds_sonicwall_sonicwall.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  28   |   4    |     11     |      5      |    5    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| failed-logon         | <b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>A-PTH-ALERT-sH-Failed</b>: Failed pass the hash attack with keylength of 0 in NTLM event and a 'null' sid on this source host.<br> ↳ <b>FAIL-PTH-ALERT-sH</b>: Possible unsuccessful pass the hash attack from the source<br> ↳ <b>FAIL-PTH-ALERT-dH</b>: Possible unsuccessful pass the hash attack by the user<br> ↳ <b>PTH-ALERT-sH-Failed</b>: Failed pass the hash attack with keylength of 0 in NTLM event and a 'null' sid.<br><br><b>T1021.001 - Remote Services: Remote Desktop Protocol</b><br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1110 - Brute Force</b><br> ↳ <b>A-FL-MULTI-USERS-S</b>: Multiple users failed to login (S)<br> ↳ <b>A-FL-MULTI-USERS-L</b>: Multiple users failed to login (L)<br> ↳ <b>A-FL-MULTI-USERS-M</b>: Multiple users failed to login (M)<br> ↳ <b>A-FL-MULTI-DEST-S</b>: Failed logins to multiple destinations from host (S)<br> ↳ <b>A-FL-MULTI-DEST-M</b>: Failed logins to multiple destinations from host (M)<br> ↳ <b>RDP-Brute-Force</b>: Abnormal number of RDP failed logons for this user<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1550.003 - Use Alternate Authentication Material: Pass the Ticket</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1558 - Steal or Forge Kerberos Tickets</b><br> ↳ <b>KL-TfG</b>: Rare Kerberos ticket failure code<br> ↳ <b>KL-Tf-fail</b>: Failed logon due to a malformed authentication ticket<br><br><b>T1110.003 - T1110.003</b><br> ↳ <b>A-FL-MULTI-USERS-SRC</b>: The same host failed to login to multiple users |  • <b>AE-OHr</b>: Random hostnames    |
| failed-vpn-login     | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP    |    |
| vpn-login    | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |    |
| vpn-logout    | <b>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting</b><br> ↳ <b>KL-USnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by user<br> ↳ <b>KL-GSnCOUNT-A</b>: Abnormal number of services used to obtain TGTs by peer group<br><br><b>T1021 - Remote Services</b><br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>RA-UHcount-S</b>: Abnormal number of accessed hosts for user (S)<br> ↳ <b>RA-UHcount-M</b>: Abnormal number of accessed hosts for user (M)<br> ↳ <b>RA-UHcount-L</b>: Abnormal number of accessed hosts for user (L)<br> ↳ <b>RA-OHcount</b>: Abnormal number of accessed hosts for the organization<br> ↳ <b>RA-GHcount</b>: Abnormal number of accessed assets for group    |  • <b>KL-GSnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for peer group<br> • <b>KL-USnCOUNT</b>: Count of services used to obtain kerberos TGTs in a session for user<br> • <b>RA-OHcount</b>: Count of assets access per user in the organization |
| web-activity-allowed | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-URank-Tor</b>: User has accessed a tor-to-web proxy site<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NET-TOR-Outbound</b>: Outbound connection to a known TOR IP<br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server'<br> ↳ <b>WEB-UD-TorProxy</b>: User has accessed a known Tor web proxy<br> ↳ <b>WEB-UI-Tor</b>: User has accessed a known Tor exit node<br> ↳ <b>WEB-UU-Tor</b>: User has accessed a URL containing '/tor/server'<br> ↳ <b>WEB-URank-Tor</b>: User has accessed a tor-to-web proxy site    |    |
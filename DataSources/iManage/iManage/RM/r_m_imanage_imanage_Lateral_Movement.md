Vendor: iManage
===============
### Product: [iManage](../ds_imanage_imanage.md)
### Use-Case: [Lateral Movement](../../../../UseCases/uc_lateral_movement.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   9   |   0    |     3      |      3      |    3    |

| Event Type    | Rules    | Models |
| ---- | ---- | ------ |
| app-activity          | <b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost</b>: User authentication or login from a known TOR IP    |        |
| authentication-failed | <b>T1078 - Valid Accounts</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>Auth-Tor-Shost-Failed</b>: User authentication or login failure from a known TOR IP    |        |
| web-activity-denied   | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>WEB-URank-Tor</b>: User has accessed a tor-to-web proxy site<br><br><b>T1090.003 - Proxy: Multi-hop Proxy</b><br> ↳ <b>A-NETF-TOR-Outbound</b>: Outbound failed connection to a known TOR IP<br> ↳ <b>A-WEB-TorProxy</b>: Asset has accessed a known Tor web proxy<br> ↳ <b>A-WEB-UU-Tor</b>: Asset has accessed a URL containing '/tor/server'<br> ↳ <b>WEB-UD-TorProxy</b>: User has accessed a known Tor web proxy<br> ↳ <b>WEB-UI-Tor</b>: User has accessed a known Tor exit node<br> ↳ <b>WEB-UU-Tor</b>: User has accessed a URL containing '/tor/server'<br> ↳ <b>WEB-URank-Tor</b>: User has accessed a tor-to-web proxy site |        |
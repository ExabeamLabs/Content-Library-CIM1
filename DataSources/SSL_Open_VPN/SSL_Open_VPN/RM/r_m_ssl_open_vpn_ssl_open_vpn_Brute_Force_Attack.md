Vendor: SSL Open VPN
====================
### Product: [SSL Open VPN](../ds_ssl_open_vpn_ssl_open_vpn.md)
### Use-Case: [Brute Force Attack](../../../../UseCases/uc_brute_force_attack.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   1   |   1    |     1      |      7      |    7    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| vpn-logout | <b>T1110 - Brute Force</b><br> ↳ <b>AUTH-F-COUNT</b>: Abnormal number of failed authentications for user |  • <b>AUTH-F-COUNT</b>: Count of failed authentication events in a session |
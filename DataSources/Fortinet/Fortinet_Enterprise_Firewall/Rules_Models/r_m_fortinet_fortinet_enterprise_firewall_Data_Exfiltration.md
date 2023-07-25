Vendor: Fortinet
================
### Product: [Fortinet Enterprise Firewall](../ds_fortinet_fortinet_enterprise_firewall.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   4   |   1    |     1      |      6      |    6    |

| Event Type         | Rules                                                                                                                                                                                                                                                                                                                                                                                                          | Models                                                             |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| app-activity       | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>EM-InRule-EX</b>: User has created an inbox forwarding rule to forward email to an external domain email<br> ↳ <b>EM-InRule-Public</b>: User has created an inbox forwarding rule to forward email to a public email domain<br> ↳ <b>InB-Perm-N-F</b>: First time a user has given mailbox permissions on another mailbox that is not their own |  • <b>EM-InB-Perm-N</b>: Models users who give mailbox permissions |
| netflow-connection | <b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>A-NETFLOW-BitTorrent</b>: Asset accessed BitTorrent application                                                                                                                                                                                                                                                                                 |                                                                    |
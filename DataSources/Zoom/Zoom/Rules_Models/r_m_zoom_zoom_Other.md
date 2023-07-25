Vendor: Zoom
============
### Product: [Zoom](../ds_zoom_zoom.md)
### Use-Case: [Other](../../../../UseCases/uc_other.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   8   |   4    |     0      |      7      |    7    |

| Event Type                        | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models                                                                                                                                    |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| web-meeting-updated               | <br> ↳ <b>WCA-DP</b>: Meeting updated to remove password<br><br>                                                                                                                                                                                                                                                                                                                                                                         |                                                                                                                                           |
| webconference-login               | <br> ↳ <b>WCA-Ucountry-A</b>: Abnormal web conference login country for user<br> ↳ <b>WCA-TOW-A</b>: Abnormal web conference login time<br> ↳ <b>WCA-Tor-IP</b>: User performs web conference login from a known Tor exit node<br> ↳ <b>WCA-Threat-IP</b>: User performs web conference login from a known malicious IP<br> ↳ <b>WCA-Ransomware-IP</b>: User performs web conference login from an IP associated with Ransomware<br><br> |  • <b>WCA-TOW</b>: Web conference login time for user<br> • <b>WCA-Ucountry</b>: Web conference login countries for user                  |
| webconference-operations-activity | <br> ↳ <b>WCA-OU-F</b>: First time user performs web conference administrative activity<br> ↳ <b>WCA-OA-A</b>: Abnormal for any user in the organization to perform this web conference administrative activity<br><br>                                                                                                                                                                                                                  |  • <b>WCA-OA</b>: Web conference admin activities in the organization<br> • <b>WCA-OU</b>: Web conference admin users in the organization |
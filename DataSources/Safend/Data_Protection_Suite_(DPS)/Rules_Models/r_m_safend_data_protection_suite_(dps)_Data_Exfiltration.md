Vendor: Safend
==============
### Product: [Data Protection Suite (DPS)](../ds_safend_data_protection_suite_(dps).md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  21   |   12   |     3      |      4      |    4    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| dlp-alert  | <b>T1204 - User Execution</b><br> ↳ <b>DLP-UBp-F</b>: First blocked process for the user<br><br><b>T1048 - Exfiltration Over Alternative Protocol</b><br> ↳ <b>DLP-AN-ALERT-F</b>: First DLP alert name on the asset<br> ↳ <b>DLP-AN-ALERT-A</b>: Abnormal DLP alert name on the asset<br> ↳ <b>DLP-ON-ALERT-F</b>: First DLP alert (by name) in the organization<br> ↳ <b>DLP-ON-ALERT-A</b>: Abnormal DLP alert (by name) in the organization<br> ↳ <b>DLP-ZN-ALERT-F</b>: First DLP alert (by name) in the zone<br> ↳ <b>DLP-ZN-ALERT-A</b>: Abnormal DLP alert (by name) in the zone<br> ↳ <b>DLP-HN-ALERT-F</b>: First DLP alert (by name) in the asset<br> ↳ <b>DLP-HN-ALERT-A</b>: Abnormal DLP alert (by name) in the asset<br> ↳ <b>DLP-OA-ALERT-F</b>: First DLP alert triggered for asset in the organization<br> ↳ <b>DLP-OU-ALERT-F</b>: First DLP alert triggered for this user<br> ↳ <b>DLP-OU-ALERT-A</b>: Abnormal user triggering DLP alert<br> ↳ <b>DLP-OG-ALERT-F</b>: First DLP alert triggered for peer group in the organization<br> ↳ <b>DLP-OG-ALERT-A</b>: Abnormal peer group triggering DLP alert in the organization<br> ↳ <b>DLP-OA-F</b>: First DLP policy violation from asset for the organization |  • <b>DLP-UBp</b>: Processes that are blocked from execution for the user<br> • <b>DLP-OA</b>: Assets on which DLP policy violations occurred in the organization<br> • <b>DLP-OG-ALERT</b>: Peer groups triggering DLP alerts in the organization<br> • <b>DLP-OU-ALERT</b>: Users triggering DLP alerts in the organization<br> • <b>A-DLP-OA-ALERT</b>: Assets triggering DLP alerts in the organization<br> • <b>A-DLP-HN-ALERT</b>: DLP alert names triggered in the asset<br> • <b>A-DLP-ZN-ALERT</b>: DLP alert names triggered in the zone<br> • <b>A-DLP-ON-ALERT</b>: DLP alert names triggered in the organization<br> • <b>A-DLP-AN-ALERT</b>: DLP alert names on asset |
| usb-insert | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| usb-read   | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| usb-write  | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
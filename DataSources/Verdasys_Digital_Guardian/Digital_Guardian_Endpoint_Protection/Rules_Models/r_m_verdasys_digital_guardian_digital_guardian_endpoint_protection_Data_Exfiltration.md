Vendor: Verdasys Digital Guardian
=================================
### Product: [Digital Guardian Endpoint Protection](../ds_verdasys_digital_guardian_digital_guardian_endpoint_protection.md)
### Use-Case: [Data Exfiltration](../../../../UseCases/uc_data_exfiltration.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   6   |   3    |     1      |      1      |    1    |

| Event Type | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | Models                                                                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| usb-insert | <b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UH-F</b>: First asset for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User |
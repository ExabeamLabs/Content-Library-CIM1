Vendor: Microsoft
=================
### Product: [Windows](../ds_microsoft_windows.md)
### Use-Case: [Data Leak](../../../../UseCases/uc_data_leak.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  25   |   15   |         7          |      3      |    3    |

| Event Type | Rules    | Models    |
| ---------- | ---- | ---- |
| file-write | <b>T1114.001 - T1114.001</b><br> ↳ <b>FA-Outlook-pst</b>: A file ends with either  pst or ost    |    |
| usb-insert | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-UHD-000</b>: First USB activity event for user, asset and USB device<br> ↳ <b>UW-UHD-001</b>: First USB activity event for user and asset. The USB device (if present) has been used by/with other users/assets in the past.<br> ↳ <b>UW-UHD-010</b>: First USB activity event for user and USB device. The asset has been used with other USB devices in other USB events<br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-100</b>: First USB activity event for USB device and asset. The user has been seen performing USB activity in other USB events<br> ↳ <b>UW-UHD-101</b>: First USB activity event for asset. The user and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UD-F</b>: First device for user in USB event<br> ↳ <b>UW-DH-F</b>: First asset for device in USB event<br> ↳ <b>UW-UHD-F</b>: First asset and device for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device<br><br><b>T1091 - Replication Through Removable Media</b><br> ↳ <b>UW-UHD-000</b>: First USB activity event for user, asset and USB device<br> ↳ <b>UW-UHD-001</b>: First USB activity event for user and asset. The USB device (if present) has been used by/with other users/assets in the past.<br> ↳ <b>UW-UHD-010</b>: First USB activity event for user and USB device. The asset has been used with other USB devices in other USB events<br> ↳ <b>UW-UHD-011</b>: First USB activity event for user. The asset and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-100</b>: First USB activity event for USB device and asset. The user has been seen performing USB activity in other USB events<br> ↳ <b>UW-UHD-101</b>: First USB activity event for asset. The user and the USB device (if present) have been seen in other USB events<br> ↳ <b>UW-UHD-110</b>: First USB activity event for USB device. The user and the asset have been seen in other USB events<br> ↳ <b>UW-UD-F</b>: First device for user in USB event<br> ↳ <b>UW-DH-F</b>: First asset for device in USB event<br> ↳ <b>UW-UHD-F</b>: First asset and device for user in USB event<br> ↳ <b>UW-UH-A</b>: Abnormal asset for user in USB event<br> ↳ <b>UW-UD-A</b>: Abnormal USB device for user<br> ↳ <b>UW-DH-A</b>: Abnormal asset for USB device |  • <b>UW-DH</b>: Hosts that were used with USB Device<br> • <b>UW-UD</b>: USB Devices per User<br> • <b>UW-UH</b>: Hosts used with USB Device per User<br> • <b>UW-UHD</b>: Assets and USB Devices for users    |
| vpn-logout | <b>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB</b><br> ↳ <b>UW-FNum</b>: Abnormal number of files written to USB<br> ↳ <b>UW-BSum</b>: Abnormal amount of data written to USB<br><br><b>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol</b><br> ↳ <b>EM-FNum</b>: Abnormal number of outgoing emails<br> ↳ <b>EM-DNum</b>: Abnormal number of outgoing email domains<br> ↳ <b>EM-BSum-personal</b>: Abnormal size of outgoing emails to personal account<br> ↳ <b>EM-BSum</b>: Abnormal size of outgoing emails<br><br><b>TA0010 - TA0010</b><br> ↳ <b>DLP-UPCOUNT</b>: Abnormal number of DLP policy violations for user<br> ↳ <b>DLP-GPCOUNT</b>: Abnormal number of DLP policy violations for peer group<br> ↳ <b>DLP-BSum</b>: Abnormal amount of data written during DLP policy violation<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>VPN-BSum</b>: Abnormal amount of data uploaded during VPN Session<br><br><b>T1052 - Exfiltration Over Physical Medium</b><br> ↳ <b>PR-NPSum</b>: Abnormal number of pages printed    |  • <b>UW-BSum</b>: Sum of bytes written to USB<br> • <b>UW-FNum</b>: Count of assets Files Written to USB<br> • <b>EM-BSum</b>: Sum of bytes in outgoing emails<br> • <b>EM-BSum-personal</b>: Sum of bytes in outgoing emails to personal domains<br> • <b>EM-DNum</b>: Number of distinct domains<br> • <b>EM-FNum</b>: Count of outgoing emails<br> • <b>DLP-BSum</b>: Sum of bytes written during DLP policy violation<br> • <b>DLP-GPCOUNT</b>: Count of DLP policy violations for peer group<br> • <b>DLP-UPCOUNT</b>: Count of DLP policy violations for user<br> • <b>VPN-BSum</b>: Sum of bytes uploaded during VPN<br> • <b>PR-NPSum</b>: Number of pages printed by user |
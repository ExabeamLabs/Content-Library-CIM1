Vendor: BeyondTrust
===================
### Product: [BeyondTrust PowerBroker](../ds_beyondtrust_beyondtrust_powerbroker.md)
### Use-Case: [Privileged Activity](../../../../UseCases/uc_privileged_activity.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  12   |   7    |         2          |      2      |    2    |

| Event Type        | Rules    | Models    |
| ---- | ---- | ---- |
| privileged-access | <b>TA0002 - TA0002</b><br> ↳ <b>WPA-UP-F</b>: First privileged process for user<br> ↳ <b>WPA-UP-A</b>: Abnormal privileged process for user<br> ↳ <b>WPA-GP-F</b>: First privileged process for peer group<br> ↳ <b>WPA-GP-A</b>: Abnormal privileged process for peer group<br> ↳ <b>WPA-PD-F</b>: First directory for privileged process<br> ↳ <b>WPA-PD-A</b>: Abnormal directory for privileged process<br> ↳ <b>WPA-HP-F</b>: First privileged process for host<br> ↳ <b>WPA-HP-A</b>: Abnormal privileged process for host<br> ↳ <b>WPA-OP-F</b>: First privileged process for organization<br> ↳ <b>WPA-OP-A</b>: Abnormal privileged process for organization |  • <b>WPA-OP</b>: Processes for organization<br> • <b>WPA-HP</b>: Processes for host<br> • <b>WPA-PD</b>: Directories per process<br> • <b>WPA-GP</b>: Privileged processes for peer group<br> • <b>WPA-GP-All</b>: Processes for peer group<br> • <b>WPA-UP</b>: Privileged processes for user<br> • <b>WPA-UP-All</b>: Processes for user |
| process-created   | <b>T1482 - Domain Trust Discovery</b><br> ↳ <b>A-Trickbot-Recon</b>: Trickbot malware domain recon activity on this asset<br> ↳ <b>Trickbot-Recon</b>: Trickbot malware domain recon activity    |    |
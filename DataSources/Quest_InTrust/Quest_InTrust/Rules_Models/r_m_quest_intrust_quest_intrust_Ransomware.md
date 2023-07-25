Vendor: Quest InTrust
=====================
### Product: [Quest InTrust](../ds_quest_intrust_quest_intrust.md)
### Use-Case: [Ransomware](../../../../UseCases/uc_ransomware.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   3   |   0    |     2      |      3      |    3    |

| Event Type      | Rules                                                                                                                                                                                                                                                                                                                                                                                  | Models |
| --------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------ |
| process-created | <b>T1070.004 - Indicator Removal on Host: File Deletion</b><br> ↳ <b>A-Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected on this asset.<br> ↳ <b>Fsutil-Sus-Invocation</b>: Suspicious parameters of fsutil were detected.<br><br><b>T1055 - Process Injection</b><br> ↳ <b>A-WannaCry</b>: Artifacts seen by WannaCry malware have been observed on this asset |        |
Vendor: Microsoft
=================
Product: Microsoft Azure
------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  17   |   17   |         8          |     13      |   13    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|   [Cloud Data Protection](../../../UseCases/uc_cloud_data_protection.md)   |  azure-blob-read<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-blob-write<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-container-acl<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-disk-write<br> ↳[azure-disks-write](Ps/pC_azurediskswrite.md)<br><br> azure-snapshot-write<br> ↳[azure-snapshots-write](Ps/pC_azuresnapshotswrite.md)<br><br> azure-storage-list<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br>    | T1078.004 - Valid Accounts: Cloud Accounts<br>T1204 - User Execution<br>T1580 - T1580<br>TA0009 - TA0009<br> | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_microsoft_microsoft_azure_Cloud_Data_Protection.md)   |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  azure-blob-read<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-blob-write<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-container-acl<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-disk-write<br> ↳[azure-disks-write](Ps/pC_azurediskswrite.md)<br><br> azure-image-write<br> ↳[azure-images-write](Ps/pC_azureimageswrite.md)<br><br> azure-instance-creds-write<br> ↳[azure-sshpublickeys-write](Ps/pC_azuresshpublickeyswrite.md)<br><br> azure-instance-write<br> ↳[azure-virtualmachines-write](Ps/pC_azurevirtualmachineswrite.md)<br><br> azure-keyvault-read<br> ↳[azure-keyvault-activity](Ps/pC_azurekeyvaultactivity.md)<br><br> azure-keyvault-write<br> ↳[azure-keyvault-activity](Ps/pC_azurekeyvaultactivity.md)<br><br> azure-role-assign<br> ↳[azure-roleassignments-write](Ps/pC_azureroleassignmentswrite.md)<br><br> azure-role-write<br> ↳[azure-roledefiniton-write](Ps/pC_azureroledefinitonwrite.md)<br><br> azure-snapshot-write<br> ↳[azure-snapshots-write](Ps/pC_azuresnapshotswrite.md)<br><br> azure-storage-list<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br> | T1078.004 - Valid Accounts: Cloud Accounts<br>T1535 - Unused/Unsupported Cloud Regions<br>    | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_microsoft_microsoft_azure_Compromised_Credentials.md) |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  azure-instance-write<br> ↳[azure-virtualmachines-write](Ps/pC_azurevirtualmachineswrite.md)<br>    | T1496 - Resource Hijacking<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_microsoft_microsoft_azure_Cryptomining.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  azure-blob-write<br> ↳[azure-blob-activity1](Ps/pC_azureblobactivity1.md)<br> ↳[azure-blob-activity2](Ps/pC_azureblobactivity2.md)<br><br> azure-image-write<br> ↳[azure-images-write](Ps/pC_azureimageswrite.md)<br><br> azure-instance-write<br> ↳[azure-virtualmachines-write](Ps/pC_azurevirtualmachineswrite.md)<br>    | T1204 - User Execution<br>T1204.003 - T1204.003<br>    | [<ul><li>4 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_microsoft_microsoft_azure_Malware.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  azure-role-assign<br> ↳[azure-roleassignments-write](Ps/pC_azureroleassignmentswrite.md)<br><br> azure-role-write<br> ↳[azure-roledefiniton-write](Ps/pC_azureroledefinitonwrite.md)<br>    | TA0004 - TA0004<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_microsoft_microsoft_azure_Privilege_Escalation.md)    |

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                             | Execution                                                           | Persistence                                                         | Privilege Escalation                                                | Defense Evasion                                                                                                                                          | Credential Access | Discovery | Lateral Movement | Collection | Command and Control | Exfiltration | Impact                                                                  |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- | --------- | ---------------- | ---------- | ------------------- | ------------ | ----------------------------------------------------------------------- |
| [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535)<br><br> |                   |           |                  |            |                     |              | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |
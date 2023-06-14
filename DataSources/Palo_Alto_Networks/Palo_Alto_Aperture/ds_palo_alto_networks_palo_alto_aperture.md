Vendor: Palo Alto Networks
==========================
Product: Palo Alto Aperture
---------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  170  |   74   |         22         |      8      |    8    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  app-activity<br> ↳[palo-alto-app-activity-1](Ps/pC_paloaltoappactivity1.md)<br> ↳[palo-alto-app-activity-2](Ps/pC_paloaltoappactivity2.md)<br><br> app-login<br> ↳[palo-alto-app-login-1](Ps/pC_paloaltoapplogin1.md)<br>    | T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>12 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  app-activity<br> ↳[palo-alto-app-activity-1](Ps/pC_paloaltoappactivity1.md)<br> ↳[palo-alto-app-activity-2](Ps/pC_paloaltoappactivity2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Account_Manipulation.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  dlp-alert<br> ↳[s-pan-policyviolation-alert](Ps/pC_spanpolicyviolationalert.md)<br> ↳[palo-alto-dlp-alert-1](Ps/pC_paloaltodlpalert1.md)<br> ↳[s-pan-incident-alert](Ps/pC_spanincidentalert.md)<br> ↳[palo-alto-dlp-alert](Ps/pC_paloaltodlpalert.md)<br><br> file-write<br> ↳[s-pan-networks-file-activity](Ps/pC_spannetworksfileactivity.md)<br> ↳[palo-alto-file-operations](Ps/pC_paloaltofileoperations.md)<br> | T1020 - Automated Exfiltration<br>T1071 - Application Layer Protocol<br>TA0002 - TA0002<br>TA0010 - TA0010<br>      | [<ul><li>31 Rules</li></ul><ul><li>19 Models</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Data_Exfiltration.md)    |
|    [Destruction of Data](../../../UseCases/uc_destruction_of_data.md)    |  file-delete<br> ↳[palo-alto-file-operations](Ps/pC_paloaltofileoperations.md)<br>    | T1070.004 - Indicator Removal on Host: File Deletion<br>T1485 - Data Destruction<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Destruction_of_Data.md)    |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity<br> ↳[palo-alto-app-activity-1](Ps/pC_paloaltoappactivity1.md)<br> ↳[palo-alto-app-activity-2](Ps/pC_paloaltoappactivity2.md)<br><br> app-login<br> ↳[palo-alto-app-login-1](Ps/pC_paloaltoapplogin1.md)<br><br> security-alert<br> ↳[s-pan-security-alert](Ps/pC_spansecurityalert.md)<br>    | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1090.003 - Proxy: Multi-hop Proxy<br> | [<ul><li>5 Rules</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Lateral_Movement.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[palo-alto-app-activity-1](Ps/pC_paloaltoappactivity1.md)<br> ↳[palo-alto-app-activity-2](Ps/pC_paloaltoappactivity2.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Privilege_Escalation.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[palo-alto-app-activity-1](Ps/pC_paloaltoappactivity1.md)<br> ↳[palo-alto-app-activity-2](Ps/pC_paloaltoappactivity2.md)<br><br> app-login<br> ↳[palo-alto-app-login-1](Ps/pC_paloaltoapplogin1.md)<br><br> file-write<br> ↳[s-pan-networks-file-activity](Ps/pC_spannetworksfileactivity.md)<br> ↳[palo-alto-file-operations](Ps/pC_paloaltofileoperations.md)<br>    | T1078 - Valid Accounts<br>T1486 - Data Encrypted for Impact<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_palo_alto_networks_palo_alto_aperture_Ransomware.md)    |
[Next Page -->>](2_ds_palo_alto_networks_palo_alto_aperture.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                         | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  | Privilege Escalation                                                                                                                                                                                                                                | Defense Evasion                                                                                                                                                                                                                                                                                                                                                                                                                                              | Credential Access                                                          | Discovery                                                                         | Lateral Movement | Collection                                                                                                                                                            | Command and Control                                                                                                                                                                                                      | Exfiltration                                                                | Impact                                                                                                                                              |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br> |           | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Server Software Component](https://attack.mitre.org/techniques/T1505)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068)<br><br>[Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547)<br><br> | [Obfuscated Files or Information: Indicator Removal from Tools](https://attack.mitre.org/techniques/T1027/005)<br><br>[Indicator Removal on Host: File Deletion](https://attack.mitre.org/techniques/T1070/004)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Indicator Removal on Host](https://attack.mitre.org/techniques/T1070)<br><br>[Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> |                  | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Automated Exfiltration](https://attack.mitre.org/techniques/T1020)<br><br> | [Data Destruction](https://attack.mitre.org/techniques/T1485)<br><br>[Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486)<br><br> |
Vendor: Juniper Networks
========================
Product: Juniper Networks Pulse Secure
--------------------------------------
| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  134  |   67   |         19         |      7      |    7    |

|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  account-deleted<br> ↳[s-pulsesecure-account-deleted](Ps/pC_spulsesecureaccountdeleted.md)<br> ↳[pulsesecure-account-deleted](Ps/pC_pulsesecureaccountdeleted.md)<br> ↳[cc-pulsesecure-account-deleted](Ps/pC_ccpulsesecureaccountdeleted.md)<br><br> app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br><br> authentication-failed<br> ↳[cc-pulsesecure-authentication-failed](Ps/pC_ccpulsesecureauthenticationfailed.md)<br> ↳[cc-pulsesecure-certificate-failed](Ps/pC_ccpulsesecurecertificatefailed.md)<br> ↳[cc-pulsesecure-authentication-failed-1](Ps/pC_ccpulsesecureauthenticationfailed1.md)<br> ↳[cc-pulsesecure-password-restriction-failed](Ps/pC_ccpulsesecurepasswordrestrictionfailed.md)<br><br> authentication-successful<br> ↳[cc-pulsesecure-authentication-successful](Ps/pC_ccpulsesecureauthenticationsuccessful.md)<br> ↳[cc-pulsesecure-password-restriction-passed](Ps/pC_ccpulsesecurepasswordrestrictionpassed.md)<br> ↳[cc-pulsesecure-authentication-successful-1](Ps/pC_ccpulsesecureauthenticationsuccessful1.md)<br> ↳[cc-pulsesecure-certificate-passed](Ps/pC_ccpulsesecurecertificatepassed.md)<br><br> failed-vpn-login<br> ↳[cc-pulsesecure-failed-vpn-login](Ps/pC_ccpulsesecurefailedvpnlogin.md)<br> ↳[cc-pulsesecure-failed-vpn-login-1](Ps/pC_ccpulsesecurefailedvpnlogin1.md)<br><br> vpn-login<br> ↳[cc-pulsesecure-vpn-resume](Ps/pC_ccpulsesecurevpnresume.md)<br> ↳[cc-pulsesecure-vpn-start-1](Ps/pC_ccpulsesecurevpnstart1.md)<br> ↳[pulsesecure-vpn-login](Ps/pC_pulsesecurevpnlogin.md)<br> ↳[cc-pulsesecure-vpn-start](Ps/pC_ccpulsesecurevpnstart.md)<br> ↳[cc-pulsesecure-access-control](Ps/pC_ccpulsesecureaccesscontrol.md)<br> ↳[s-pulsesecure-vpn-login](Ps/pC_spulsesecurevpnlogin.md)<br><br> vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1133 - External Remote Services<br>    | [<ul><li>29 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Abnormal_Authentication_&_Access.md) |
|    [Account Manipulation](../../../UseCases/uc_account_manipulation.md)    |  account-deleted<br> ↳[s-pulsesecure-account-deleted](Ps/pC_spulsesecureaccountdeleted.md)<br> ↳[pulsesecure-account-deleted](Ps/pC_pulsesecureaccountdeleted.md)<br> ↳[cc-pulsesecure-account-deleted](Ps/pC_ccpulsesecureaccountdeleted.md)<br><br> app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br><br> vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136 - Create Account<br>T1484 - Group Policy Modification<br>T1531 - Account Access Removal<br>    | [<ul><li>12 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Account_Manipulation.md)    |
|    [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)    |  vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Brute_Force_Attack.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br><br> vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1078 - Valid Accounts<br>T1110 - Brute Force<br>    | [<ul><li>20 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Data_Access.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1133 - External Remote Services<br>TA0010 - TA0010<br>    | [<ul><li>4 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br><br> vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1114.003 - Email Collection: Email Forwarding Rule<br>T1133 - External Remote Services<br>TA0010 - TA0010<br> | [<ul><li>14 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Data_Leak.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1566 - Phishing<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Phishing.md)    |
|    [Physical Security](../../../UseCases/uc_physical_security.md)    |  vpn-login<br> ↳[cc-pulsesecure-vpn-resume](Ps/pC_ccpulsesecurevpnresume.md)<br> ↳[cc-pulsesecure-vpn-start-1](Ps/pC_ccpulsesecurevpnstart1.md)<br> ↳[pulsesecure-vpn-login](Ps/pC_pulsesecurevpnlogin.md)<br> ↳[cc-pulsesecure-vpn-start](Ps/pC_ccpulsesecurevpnstart.md)<br> ↳[cc-pulsesecure-access-control](Ps/pC_ccpulsesecureaccesscontrol.md)<br> ↳[s-pulsesecure-vpn-login](Ps/pC_spulsesecurevpnlogin.md)<br>    | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Physical_Security.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br><br> vpn-logout<br> ↳[cc-pulsesecure-vpn-end](Ps/pC_ccpulsesecurevpnend.md)<br> ↳[cc-pulsesecure-vpn-end-1](Ps/pC_ccpulsesecurevpnend1.md)<br> ↳[cc-pulsesecure-vpn-close](Ps/pC_ccpulsesecurevpnclose.md)<br> ↳[cc-pulsesecure-vpn-timeout](Ps/pC_ccpulsesecurevpntimeout.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>8 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Privilege_Escalation.md)    |
|    [Privileged Activity](../../../UseCases/uc_privileged_activity.md)    |  app-activity<br> ↳[s-juniper-pulse-activity](Ps/pC_sjuniperpulseactivity.md)<br> ↳[cef-juniper-pulse-activity](Ps/pC_cefjuniperpulseactivity.md)<br>    | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_juniper_networks_juniper_networks_pulse_secure_Privileged_Activity.md)    |
[Next Page -->>](2_ds_juniper_networks_juniper_networks_pulse_secure.md)

MITRE ATT&CK® Framework for Enterprise
--------------------------------------
| Initial Access                                                                                                                                                                                                                                                                                      | Execution | Persistence                                                                                                                                                                                                                                                                                                                                                                                                    | Privilege Escalation                                                                                                                              | Defense Evasion                                                                                                                                   | Credential Access                                                                                                                                                                                                                                                                                                                                | Discovery | Lateral Movement                                                     | Collection                                                                                                                                                            | Command and Control                                                                                                                       | Exfiltration                                                                                                                                                                                                                                                                                                                                                                                                                                                | Impact                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------- | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Exploit Public Fasing Application](https://attack.mitre.org/techniques/T1190)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> |           | [Create Account](https://attack.mitre.org/techniques/T1136)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Account Manipulation](https://attack.mitre.org/techniques/T1098)<br><br>[Account Manipulation: Exchange Email Delegate Permissions](https://attack.mitre.org/techniques/T1098/002)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br> | [Group Policy Modification](https://attack.mitre.org/techniques/T1484)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Brute Force](https://attack.mitre.org/techniques/T1110)<br><br>[Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)<br><br>[Credentials from Password Stores](https://attack.mitre.org/techniques/T1555)<br><br>[Steal or Forge Kerberos Tickets: Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br><br> |           | [Remote Services](https://attack.mitre.org/techniques/T1021)<br><br> | [Email Collection](https://attack.mitre.org/techniques/T1114)<br><br>[Email Collection: Email Forwarding Rule](https://attack.mitre.org/techniques/T1114/003)<br><br> | [Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br><br>[Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol](https://attack.mitre.org/techniques/T1048/003)<br><br>[Exfiltration Over Physical Medium: Exfiltration over USB](https://attack.mitre.org/techniques/T1052/001)<br><br>[Exfiltration Over Physical Medium](https://attack.mitre.org/techniques/T1052)<br><br> | [Account Access Removal](https://attack.mitre.org/techniques/T1531)<br><br> |
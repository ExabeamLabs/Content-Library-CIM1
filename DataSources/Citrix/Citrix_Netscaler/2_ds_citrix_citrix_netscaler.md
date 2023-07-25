|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|      [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)      |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Brute_Force_Attack.md)         |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1021 - Remote Services<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1078.003 - Valid Accounts: Local Accounts<br>T1102 - Web Service<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1550 - Use Alternate Authentication Material<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>107 Rules</li></ul><ul><li>61 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Compromised_Credentials.md) |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_citrix_citrix_netscaler_Cryptomining.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1078 - Valid Accounts<br>T1110 - Brute Force<br>    | [<ul><li>6 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0010 - TA0010<br>    | [<ul><li>11 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Data_Exfiltration.md)         |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>TA0010 - TA0010<br>    | [<ul><li>16 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1018 - Remote System Discovery<br>T1021 - Remote Services<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1550 - Use Alternate Authentication Material<br>T1550.002 - Use Alternate Authentication Material: Pass the Hash<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>    | [<ul><li>45 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Lateral_Movement.md)         |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1550.003 - Use Alternate Authentication Material: Pass the Ticket<br>T1558 - Steal or Forge Kerberos Tickets<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0002 - TA0002<br>    | [<ul><li>29 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566 - Phishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Phishing.md)    |
|       [Physical Security](../../../UseCases/uc_physical_security.md)       |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Physical_Security.md)          |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1133 - External Remote Services<br>    | [<ul><li>15 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>7 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Privilege_Escalation.md)       |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1021 - Remote Services<br>T1068 - Exploitation for Privilege Escalation<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.002 - T1078.002<br>T1102 - Web Service<br>    | [<ul><li>18 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Privileged_Activity.md)       |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_citrix_citrix_netscaler_Ransomware.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  app-login<br> ↳[citrix-file-share](Ps/pC_citrixfileshare.md)<br><br> authentication-successful<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> database-access<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> remote-logon<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> vpn-login<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br><br> vpn-logout<br> ↳[netscaler-failed-vpn-login](Ps/pC_netscalerfailedvpnlogin.md)<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> web-activity-allowed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Workforce_Protection.md)       |
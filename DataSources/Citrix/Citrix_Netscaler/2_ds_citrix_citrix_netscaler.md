|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-login<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> failed-vpn-login<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> process-created<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> vpn-login<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> vpn-logout<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br>    | T1003 - OS Credential Dumping<br>T1003.001 - T1003.001<br>T1003.002 - T1003.002<br>T1003.003 - T1003.003<br>T1003.005 - T1003.005<br>T1016 - System Network Configuration Discovery<br>T1040 - Network Sniffing<br>T1078 - Valid Accounts<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>T1190 - Exploit Public Fasing Application<br>T1218.011 - Signed Binary Proxy Execution: Rundll32<br>T1555 - Credentials from Password Stores<br>TA0002 - TA0002<br>    | [<ul><li>94 Rules</li></ul><ul><li>29 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-login<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> authentication-failed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br><br> failed-vpn-login<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> process-created<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> vpn-login<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> vpn-logout<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br> | T1021 - Remote Services<br>T1021.001 - Remote Services: Remote Desktop Protocol<br>T1021.003 - T1021.003<br>T1021.006 - T1021.006<br>T1047 - Windows Management Instrumentation<br>T1059.001 - Command and Scripting Interperter: PowerShell<br>T1078 - Valid Accounts<br>T1090 - Proxy<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1210 - Exploitation of Remote Services<br>T1219 - Remote Access Software<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>T1563.002 - T1563.002<br> | [<ul><li>52 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Lateral_Movement.md)         |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  app-login<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> process-created<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> vpn-login<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br><br> vpn-logout<br> ↳[raw-netscaler-vpn-stop](Ps/pC_rawnetscalervpnstop.md)<br> ↳[netscaler-cef-vpn-end](Ps/pC_netscalercefvpnend.md)<br>    | T1047 - Windows Management Instrumentation<br>T1078 - Valid Accounts<br>T1098 - Account Manipulation<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1133 - External Remote Services<br>T1136 - Create Account<br>T1136.001 - Create Account: Create: Local Account<br>    | [<ul><li>15 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_citrix_citrix_netscaler_Privilege_Abuse.md)          |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-login<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br><br> authentication-failed<br> ↳[s-netscaler-auth-failed](Ps/pC_snetscalerauthfailed.md)<br><br> failed-vpn-login<br> ↳[netscaler-cef-failed-vpn-login](Ps/pC_netscalerceffailedvpnlogin.md)<br><br> process-created<br> ↳[netscaler-process-created](Ps/pC_netscalerprocesscreated.md)<br><br> vpn-login<br> ↳[raw-netscaler-ica-login](Ps/pC_rawnetscalericalogin.md)<br> ↳[raw-netscaler-vpn-start](Ps/pC_rawnetscalervpnstart.md)<br> ↳[netscaler-cef-vpn-start](Ps/pC_netscalercefvpnstart.md)<br>    | T1003.001 - T1003.001<br>T1059.003 - T1059.003<br>T1070 - Indicator Removal on Host<br>T1070.001 - Indicator Removal on Host: Clear Windows Event Logs<br>T1078 - Valid Accounts<br>T1218.011 - Signed Binary Proxy Execution: Rundll32<br>T1222.001 - File and Directory Permissions Modification: Windows File and Directory Permissions Modification<br>T1486 - Data Encrypted for Impact<br>T1490 - Inhibit System Recovery<br>    | [<ul><li>7 Rules</li></ul>](RM/r_m_citrix_citrix_netscaler_Ransomware.md)    |
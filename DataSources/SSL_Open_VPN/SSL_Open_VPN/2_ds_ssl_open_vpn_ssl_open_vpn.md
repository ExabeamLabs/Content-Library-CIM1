|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|      [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)      |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Brute_Force_Attack.md)        |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>    | [<ul><li>78 Rules</li></ul><ul><li>41 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Compromised_Credentials.md) |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1078 - Valid Accounts<br>T1110 - Brute Force<br>    | [<ul><li>21 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1133 - External Remote Services<br>TA0010 - TA0010<br>    | [<ul><li>4 Rules</li></ul><ul><li>4 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Data_Exfiltration.md)         |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1114.003 - Email Collection: Email Forwarding Rule<br>T1133 - External Remote Services<br>TA0010 - TA0010<br> | [<ul><li>14 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>    | [<ul><li>9 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Lateral_Movement.md)          |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1078 - Valid Accounts<br>TA0002 - TA0002<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1566 - Phishing<br>    | [<ul><li>2 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Phishing.md)    |
|       [Physical Security](../../../UseCases/uc_physical_security.md)       |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Physical_Security.md)         |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1133 - External Remote Services<br>    | [<ul><li>9 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>8 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Privilege_Escalation.md)      |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Privileged_Activity.md)       |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-failed<br> ↳[openvpn-app-activity](Ps/pC_openvpnappactivity.md)<br><br> authentication-successful<br> ↳[openvpn-auth-failed](Ps/pC_openvpnauthfailed.md)<br> ↳[openvpn-auth-failed-2](Ps/pC_openvpnauthfailed2.md)<br><br> failed-app-login<br> ↳[openvpn-vpn-login](Ps/pC_openvpnvpnlogin.md)<br> ↳[openvpn-vpn-login-1](Ps/pC_openvpnvpnlogin1.md)<br><br> failed-vpn-login<br> ↳[openvpn-vpn-end](Ps/pC_openvpnvpnend.md)<br> ↳[openvpn-vpn-end-1](Ps/pC_openvpnvpnend1.md)<br> ↳[openvpn-vpn-end-4](Ps/pC_openvpnvpnend4.md)<br> ↳[openvpn-vpn-end-2](Ps/pC_openvpnvpnend2.md)<br> ↳[openvpn-vpn-end-3](Ps/pC_openvpnvpnend3.md)<br><br> network-alert<br> ↳[graylog-ras-vpn-start](Ps/pC_graylograsvpnstart.md)<br><br> vpn-login<br> ↳[openvpn-failed-vpn-login](Ps/pC_openvpnfailedvpnlogin.md)<br><br> vpn-logout<br> ↳[openvpn-auth-successful](Ps/pC_openvpnauthsuccessful.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_ssl_open_vpn_ssl_open_vpn_Ransomware.md)    |
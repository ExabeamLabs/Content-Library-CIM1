|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|      [Brute Force Attack](../../../UseCases/uc_brute_force_attack.md)      |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_security_gateway_Brute_Force_Attack.md)        |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>    | [<ul><li>66 Rules</li></ul><ul><li>34 Models</li></ul>](RM/r_m_check_point_security_gateway_Compromised_Credentials.md) |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_check_point_security_gateway_Cryptomining.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1110 - Brute Force<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0010 - TA0010<br>    | [<ul><li>12 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Exfiltration.md)        |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1048.003 - Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol<br>T1052 - Exfiltration Over Physical Medium<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>TA0010 - TA0010<br> | [<ul><li>17 Rules</li></ul><ul><li>13 Models</li></ul>](RM/r_m_check_point_security_gateway_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1021 - Remote Services<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br>TA0010 - TA0010<br>TA0011 - TA0011<br>    | [<ul><li>32 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_check_point_security_gateway_Lateral_Movement.md)        |
|    [Malware](../../../UseCases/uc_malware.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0011 - TA0011<br>    | [<ul><li>28 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_check_point_security_gateway_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566 - Phishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_security_gateway_Phishing.md)    |
|       [Physical Security](../../../UseCases/uc_physical_security.md)       |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1133 - External Remote Services<br>    | [<ul><li>1 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_check_point_security_gateway_Physical_Security.md)         |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1133 - External Remote Services<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_security_gateway_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1555.005 - T1555.005<br>    | [<ul><li>5 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_check_point_security_gateway_Privilege_Escalation.md)      |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_check_point_security_gateway_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_check_point_security_gateway_Ransomware.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  failed-vpn-login<br> ↳[cef-connectra-vpn-logout](Ps/pC_cefconnectravpnlogout.md)<br> ↳[checkpoint-connectra-vpn-logout](Ps/pC_checkpointconnectravpnlogout.md)<br> ↳[cef-checkpoint-vpn-end](Ps/pC_cefcheckpointvpnend.md)<br> ↳[connectra-vpn-end](Ps/pC_connectravpnend.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> network-connection-failed<br> ↳[checkpoint-vpn-login](Ps/pC_checkpointvpnlogin.md)<br><br> vpn-login<br> ↳[cef-connectra-vpn-login-failed](Ps/pC_cefconnectravpnloginfailed.md)<br> ↳[r-syslog-chkpnt-vpn-end](Ps/pC_rsyslogchkpntvpnend.md)<br> ↳[checkpoint-connectra-failed-vpn-login](Ps/pC_checkpointconnectrafailedvpnlogin.md)<br> ↳[connectra-failed-vpn-login](Ps/pC_connectrafailedvpnlogin.md)<br> ↳[checkpoint-failed-vpn-login](Ps/pC_checkpointfailedvpnlogin.md)<br> ↳[checkpoint-vpn-login-1](Ps/pC_checkpointvpnlogin1.md)<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br><br> vpn-logout<br> ↳[r-syslog-chkpnt-vpn-start](Ps/pC_rsyslogchkpntvpnstart.md)<br> ↳[r-syslog-chkpnt-vpn-set-ip](Ps/pC_rsyslogchkpntvpnsetip.md)<br> ↳[connectra-vpn-login](Ps/pC_connectravpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login-1](Ps/pC_checkpointconnectravpnlogin1.md)<br> ↳[cef-checkpoint-vpn-login](Ps/pC_cefcheckpointvpnlogin.md)<br> ↳[checkpoint-connectra-vpn-login](Ps/pC_checkpointconnectravpnlogin.md)<br> ↳[cef-checkpoint-vpn-login-1](Ps/pC_cefcheckpointvpnlogin1.md)<br><br> web-activity-allowed<br> ↳[cef-connectra-vpn-login](Ps/pC_cefconnectravpnlogin.md)<br> ↳[cef-connectra-vpn-changeip](Ps/pC_cefconnectravpnchangeip.md)<br><br> web-activity-denied<br> ↳[checkpoint-vpn-login-2](Ps/pC_checkpointvpnlogin2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_check_point_security_gateway_Workforce_Protection.md)      |
|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|         [Cryptomining](../../../UseCases/uc_cryptomining.md)         |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Cryptomining.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>8 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_secure_web_appliance_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_secure_web_appliance_Data_Leak.md)    |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>    | [<ul><li>10 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1189 - Drive-by Compromise<br>T1190 - Exploit Public Fasing Application<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>    | [<ul><li>26 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_cisco_secure_web_appliance_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Phishing.md)    |
|      [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)      |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Privilege_Abuse.md)    |
|  [Privileged Activity](../../../UseCases/uc_privileged_activity.md)  |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br><br> web-activity-denied<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cisco_secure_web_appliance_Ransomware.md)    |
| [Workforce Protection](../../../UseCases/uc_workforce_protection.md) |  web-activity-allowed<br> ↳[syslog-cisco-wsa-web-activity](Ps/pC_syslogciscowsawebactivity.md)<br> ↳[cisco-w3c-proxy](Ps/pC_ciscow3cproxy.md)<br> ↳[elk-cisco-wsa-web-activity](Ps/pC_elkciscowsawebactivity.md)<br> ↳[syslog-cisco-wsa-web-activity-nxlog](Ps/pC_syslogciscowsawebactivitynxlog.md)<br> ↳[cisco-wsa-squid-proxy](Ps/pC_ciscowsasquidproxy.md)<br> ↳[q-wsa-proxy](Ps/pC_qwsaproxy.md)<br> ↳[cisco-wsa-web-activity](Ps/pC_ciscowsawebactivity.md)<br> ↳[cisco-wsa-web-activity-1](Ps/pC_ciscowsawebactivity1.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cisco_secure_web_appliance_Workforce_Protection.md) |
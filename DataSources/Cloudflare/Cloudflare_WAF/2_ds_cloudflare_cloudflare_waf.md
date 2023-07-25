|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>T1133 - External Remote Services<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>   | [<ul><li>79 Rules</li></ul><ul><li>46 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Compromised_Credentials.md) |
|    [Cryptomining](../../../UseCases/uc_cryptomining.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Cryptomining.md)    |
|    [Data Access](../../../UseCases/uc_data_access.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1078 - Valid Accounts<br>    | [<ul><li>19 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Data_Access.md)    |
|       [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)       |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>8 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Data_Exfiltration.md)         |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1114.003 - Email Collection: Email Forwarding Rule<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>9 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Data_Leak.md)    |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br>    | [<ul><li>46 Rules</li></ul><ul><li>17 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Lateral_Movement.md)        |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0011 - TA0011<br>    | [<ul><li>29 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Phishing.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>7 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>    | [<ul><li>3 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Privilege_Escalation.md)      |
|     [Privileged Activity](../../../UseCases/uc_privileged_activity.md)     |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>    | [<ul><li>4 Rules</li></ul><ul><li>1 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Privileged_Activity.md)       |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Ransomware.md)    |
|    [Workforce Protection](../../../UseCases/uc_workforce_protection.md)    |  app-activity<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Workforce_Protection.md)      |
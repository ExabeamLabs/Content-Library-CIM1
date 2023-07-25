|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|        [Cryptomining](../../../UseCases/uc_cryptomining.md)        |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Cryptomining.md)    |
|   [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)   |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>8 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Data_Exfiltration.md)  |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>6 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Data_Leak.md)          |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  network-connection-failed<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1071 - Application Layer Protocol<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br>    | [<ul><li>62 Rules</li></ul><ul><li>20 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Lateral_Movement.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[cloudflare-network-alert](Ps/pC_cloudflarenetworkalert.md)<br><br> network-connection-failed<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> network-connection-successful<br> ↳[cef-cloudflare-net-connection](Ps/pC_cefcloudflarenetconnection.md)<br><br> web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1189 - Drive-by Compromise<br>T1190 - Exploit Public Fasing Application<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0002 - TA0002<br>TA0011 - TA0011<br>     | [<ul><li>34 Rules</li></ul><ul><li>9 Models</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Phishing.md)    |
|     [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)     |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Privilege_Abuse.md)    |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>    | [<ul><li>2 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Privileged_Activity.md)    |
|          [Ransomware](../../../UseCases/uc_ransomware.md)          |  web-activity-allowed<br> ↳[skyformation-cloudflare-waf-4](Ps/pC_skyformationcloudflarewaf4.md)<br> ↳[skyformation-cloudflare-waf-3](Ps/pC_skyformationcloudflarewaf3.md)<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br><br> web-activity-denied<br> ↳[skyformation-cloudflare-waf](Ps/pC_skyformationcloudflarewaf.md)<br> ↳[skyformation-cloudflare-waf-1](Ps/pC_skyformationcloudflarewaf1.md)<br> ↳[skyformation-cloudflare-waf-2](Ps/pC_skyformationcloudflarewaf2.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_cloudflare_cloudflare_waf_Ransomware.md)    |
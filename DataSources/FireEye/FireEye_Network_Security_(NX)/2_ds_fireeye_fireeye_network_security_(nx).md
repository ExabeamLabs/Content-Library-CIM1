|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
|         [Cryptomining](../../../UseCases/uc_cryptomining.md)         |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1496 - Resource Hijacking<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Cryptomining.md)    |
|    [Data Exfiltration](../../../UseCases/uc_data_exfiltration.md)    |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>T1568 - Dynamic Resolution<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>7 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Data_Exfiltration.md)    |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1041 - Exfiltration Over C2 Channel<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1567 - Exfiltration Over Web Service<br>T1567.002 - Exfiltration Over Web Service: Exfiltration to Cloud Storage<br>    | [<ul><li>5 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Data_Leak.md)    |
|     [Lateral Movement](../../../UseCases/uc_lateral_movement.md)     |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1090.003 - Proxy: Multi-hop Proxy<br>    | [<ul><li>9 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Lateral_Movement.md)    |
|    [Malware](../../../UseCases/uc_malware.md)    |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0002 - TA0002<br>    | [<ul><li>27 Rules</li></ul><ul><li>8 Models</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Malware.md)    |
|    [Phishing](../../../UseCases/uc_phishing.md)    |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1534 - Internal Spearphishing<br>T1566.002 - Phishing: Spearphishing Link<br>T1598.003 - T1598.003<br>    | [<ul><li>4 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Phishing.md)    |
|      [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)      |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Privilege_Abuse.md)    |
|  [Privileged Activity](../../../UseCases/uc_privileged_activity.md)  |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1068 - Exploitation for Privilege Escalation<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1102 - Web Service<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Privileged_Activity.md)    |
|    [Ransomware](../../../UseCases/uc_ransomware.md)    |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>1 Rules</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Ransomware.md)    |
| [Workforce Protection](../../../UseCases/uc_workforce_protection.md) |  network-alert<br> ↳[fireeye-mps-xml-extended-head-alert](Ps/pC_fireeyempsxmlextendedheadalert.md)<br><br> security-alert<br> ↳[fireeye-cef-alert](Ps/pC_fireeyecefalert.md)<br> ↳[n-forwarded-cef-fireeye-alert](Ps/pC_nforwardedceffireeyealert.md)<br> ↳[fireeye-mps-xml-extended-consolidated-alert](Ps/pC_fireeyempsxmlextendedconsolidatedalert.md)<br> ↳[s-fireeye-mps-alert](Ps/pC_sfireeyempsalert.md)<br> ↳[leef-fireeye-alert](Ps/pC_leeffireeyealert.md)<br> ↳[fireeye-mps-json-generic-alert-1](Ps/pC_fireeyempsjsongenericalert1.md)<br> ↳[fireeye-mps-json-unformatted-alert](Ps/pC_fireeyempsjsonunformattedalert.md)<br> ↳[fireeye-cef-alert-no-connector](Ps/pC_fireeyecefalertnoconnector.md)<br> ↳[q-fireeye-mps](Ps/pC_qfireeyemps.md)<br> ↳[fireeye-mps-json-generic-alert](Ps/pC_fireeyempsjsongenericalert.md)<br> ↳[fireeye-mps-xml-normal-alert](Ps/pC_fireeyempsxmlnormalalert.md)<br> ↳[fireeye-cef-email-alert](Ps/pC_fireeyecefemailalert.md)<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br><br> web-activity-allowed<br> ↳[fireeye-web-activity](Ps/pC_fireeyewebactivity.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>    | [<ul><li>4 Rules</li></ul><ul><li>2 Models</li></ul>](RM/r_m_fireeye_fireeye_network_security_(nx)_Workforce_Protection.md) |
|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
|    [Data Leak](../../../UseCases/uc_data_leak.md)    |  dlp-alert<br> ↳[cef-sophos-dlp-alert-8](Ps/pC_cefsophosdlpalert8.md)<br> ↳[cef-sophos-dlp-alert-6](Ps/pC_cefsophosdlpalert6.md)<br> ↳[cef-sophos-dlp-alert-7](Ps/pC_cefsophosdlpalert7.md)<br> ↳[cef-sophos-dlp-alert-13](Ps/pC_cefsophosdlpalert13.md)<br> ↳[cc-sophos-dlp-alert](Ps/pC_ccsophosdlpalert.md)<br> ↳[sophos-leef-epp-usb-block](Ps/pC_sophosleefeppusbblock.md)<br> ↳[sophos-leef-epp-dlp-alert](Ps/pC_sophosleefeppdlpalert.md)<br> ↳[sophos-dlp-alert-1](Ps/pC_sophosdlpalert1.md)<br> ↳[sophos-epp-logwriter-alert](Ps/pC_sophosepplogwriteralert.md)<br><br> usb-insert<br> ↳[sophos-usb-insert](Ps/pC_sophosusbinsert.md)<br> ↳[cef-sophos-usb-insert](Ps/pC_cefsophosusbinsert.md)<br> ↳[cef-sophos-usb-insert-1](Ps/pC_cefsophosusbinsert1.md)<br> ↳[sophos-app-usb-insert](Ps/pC_sophosappusbinsert.md)<br><br> usb-read<br> ↳[cef-sophos-usb-read](Ps/pC_cefsophosusbread.md)<br><br> usb-write<br> ↳[sophos-leef-epp-usb-activity](Ps/pC_sophosleefeppusbactivity.md)<br> ↳[sophos-leef-epp-usb-activity-2](Ps/pC_sophosleefeppusbactivity2.md)<br>    | T1020 - Automated Exfiltration<br>T1052.001 - Exfiltration Over Physical Medium: Exfiltration over USB<br>T1071 - Application Layer Protocol<br>T1091 - Replication Through Removable Media<br>TA0010 - TA0010<br>    | [<ul><li>43 Rules</li></ul><ul><li>22 Models</li></ul>](RM/r_m_sophos_sophos_endpoint_protection_Data_Leak.md)       |
|    [Lateral Movement](../../../UseCases/uc_lateral_movement.md)    |  app-activity-failed<br> ↳[sophos-app-activity-failed](Ps/pC_sophosappactivityfailed.md)<br> ↳[sophos-app-activity-failed-1](Ps/pC_sophosappactivityfailed1.md)<br><br> network-connection-failed<br> ↳[sophos-network-connection-1](Ps/pC_sophosnetworkconnection1.md)<br> ↳[sophos-network-connection-3](Ps/pC_sophosnetworkconnection3.md)<br><br> security-alert<br> ↳[cef-sophos-security-alert-40](Ps/pC_cefsophossecurityalert40.md)<br> ↳[cef-sophos-security-alert-41](Ps/pC_cefsophossecurityalert41.md)<br> ↳[cef-sophos-security-alert-2](Ps/pC_cefsophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-3](Ps/pC_cefsophossecurityalert3.md)<br> ↳[cef-sophos-security-alert-4](Ps/pC_cefsophossecurityalert4.md)<br> ↳[cef-sophos-security-alert-42](Ps/pC_cefsophossecurityalert42.md)<br> ↳[cef-sophos-security-alert-5](Ps/pC_cefsophossecurityalert5.md)<br> ↳[cef-sophos-security-alert-43](Ps/pC_cefsophossecurityalert43.md)<br> ↳[cef-sophos-security-alert-6](Ps/pC_cefsophossecurityalert6.md)<br> ↳[cef-sophos-security-alert-26](Ps/pC_cefsophossecurityalert26.md)<br> ↳[cef-sophos-security-alert-7](Ps/pC_cefsophossecurityalert7.md)<br> ↳[cef-sophos-security-alert-8](Ps/pC_cefsophossecurityalert8.md)<br> ↳[sophos-leef-epp-web-alert](Ps/pC_sophosleefeppwebalert.md)<br> ↳[cef-sophos-security-alert-30](Ps/pC_cefsophossecurityalert30.md)<br> ↳[cef-sophos-security-alert-1](Ps/pC_cefsophossecurityalert1.md)<br> ↳[cc-sophos-security-alert](Ps/pC_ccsophossecurityalert.md)<br> ↳[cef-sophos-security-alert-39](Ps/pC_cefsophossecurityalert39.md)<br> ↳[cef-sophos-security-alert-18](Ps/pC_cefsophossecurityalert18.md)<br> ↳[sophos-security-alert](Ps/pC_sophossecurityalert.md)<br> ↳[sophos-security-alert-1](Ps/pC_sophossecurityalert1.md)<br> ↳[sophos-leef-epp-virus-alert](Ps/pC_sophosleefeppvirusalert.md)<br> ↳[sophos-security-alert-2](Ps/pC_sophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-11](Ps/pC_cefsophossecurityalert11.md)<br> ↳[cef-sophos-security-alert-33](Ps/pC_cefsophossecurityalert33.md)<br> ↳[cef-sophos-security-alert-12](Ps/pC_cefsophossecurityalert12.md)<br> ↳[cef-sophos-security-alert-34](Ps/pC_cefsophossecurityalert34.md)<br> ↳[cef-sophos-security-alert-10](Ps/pC_cefsophossecurityalert10.md)<br> ↳[cef-sophos-security-alert-32](Ps/pC_cefsophossecurityalert32.md)<br> ↳[cef-sophos-security-alert-15](Ps/pC_cefsophossecurityalert15.md)<br> ↳[cef-sophos-security-alert-37](Ps/pC_cefsophossecurityalert37.md)<br> ↳[cef-sophos-security-alert-38](Ps/pC_cefsophossecurityalert38.md)<br> ↳[cef-sophos-security-alert-13](Ps/pC_cefsophossecurityalert13.md)<br> ↳[cef-sophos-security-alert-35](Ps/pC_cefsophossecurityalert35.md)<br> ↳[cef-sophos-security-alert-14](Ps/pC_cefsophossecurityalert14.md)<br> ↳[cef-sophos-security-alert-36](Ps/pC_cefsophossecurityalert36.md)<br> ↳[sophos-epp-logwriter-alert](Ps/pC_sophosepplogwriteralert.md)<br> ↳[sophos-threat-alert](Ps/pC_sophosthreatalert.md)<br> ↳[sophos-threat-alert-1](Ps/pC_sophosthreatalert1.md)<br> ↳[syslog-sophos-snmp-alert-detected](Ps/pC_syslogsophossnmpalertdetected.md)<br> ↳[xml-sophos-security-alert](Ps/pC_xmlsophossecurityalert.md)<br> ↳[syslog-sophos-snmp-alert-belongs](Ps/pC_syslogsophossnmpalertbelongs.md)<br>    | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1190 - Exploit Public Fasing Application<br>TA0010 - TA0010<br>TA0011 - TA0011<br> | [<ul><li>23 Rules</li></ul><ul><li>7 Models</li></ul>](RM/r_m_sophos_sophos_endpoint_protection_Lateral_Movement.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  dlp-alert<br> ↳[cef-sophos-dlp-alert-8](Ps/pC_cefsophosdlpalert8.md)<br> ↳[cef-sophos-dlp-alert-6](Ps/pC_cefsophosdlpalert6.md)<br> ↳[cef-sophos-dlp-alert-7](Ps/pC_cefsophosdlpalert7.md)<br> ↳[cef-sophos-dlp-alert-13](Ps/pC_cefsophosdlpalert13.md)<br> ↳[cc-sophos-dlp-alert](Ps/pC_ccsophosdlpalert.md)<br> ↳[sophos-leef-epp-usb-block](Ps/pC_sophosleefeppusbblock.md)<br> ↳[sophos-leef-epp-dlp-alert](Ps/pC_sophosleefeppdlpalert.md)<br> ↳[sophos-dlp-alert-1](Ps/pC_sophosdlpalert1.md)<br> ↳[sophos-epp-logwriter-alert](Ps/pC_sophosepplogwriteralert.md)<br><br> file-alert<br> ↳[syslog-sophos-snmp-denied](Ps/pC_syslogsophossnmpdenied.md)<br> ↳[syslog-sophos-snmp-alert-detected](Ps/pC_syslogsophossnmpalertdetected.md)<br> ↳[syslog-sophos-snmp-alert-belongs](Ps/pC_syslogsophossnmpalertbelongs.md)<br><br> network-alert<br> ↳[sophos-network-alert](Ps/pC_sophosnetworkalert.md)<br><br> network-connection-failed<br> ↳[sophos-network-connection-1](Ps/pC_sophosnetworkconnection1.md)<br> ↳[sophos-network-connection-3](Ps/pC_sophosnetworkconnection3.md)<br><br> process-alert<br> ↳[sophos-web-alert](Ps/pC_sophoswebalert.md)<br><br> security-alert<br> ↳[cef-sophos-security-alert-40](Ps/pC_cefsophossecurityalert40.md)<br> ↳[cef-sophos-security-alert-41](Ps/pC_cefsophossecurityalert41.md)<br> ↳[cef-sophos-security-alert-2](Ps/pC_cefsophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-3](Ps/pC_cefsophossecurityalert3.md)<br> ↳[cef-sophos-security-alert-4](Ps/pC_cefsophossecurityalert4.md)<br> ↳[cef-sophos-security-alert-42](Ps/pC_cefsophossecurityalert42.md)<br> ↳[cef-sophos-security-alert-5](Ps/pC_cefsophossecurityalert5.md)<br> ↳[cef-sophos-security-alert-43](Ps/pC_cefsophossecurityalert43.md)<br> ↳[cef-sophos-security-alert-6](Ps/pC_cefsophossecurityalert6.md)<br> ↳[cef-sophos-security-alert-26](Ps/pC_cefsophossecurityalert26.md)<br> ↳[cef-sophos-security-alert-7](Ps/pC_cefsophossecurityalert7.md)<br> ↳[cef-sophos-security-alert-8](Ps/pC_cefsophossecurityalert8.md)<br> ↳[sophos-leef-epp-web-alert](Ps/pC_sophosleefeppwebalert.md)<br> ↳[cef-sophos-security-alert-30](Ps/pC_cefsophossecurityalert30.md)<br> ↳[cef-sophos-security-alert-1](Ps/pC_cefsophossecurityalert1.md)<br> ↳[cc-sophos-security-alert](Ps/pC_ccsophossecurityalert.md)<br> ↳[cef-sophos-security-alert-39](Ps/pC_cefsophossecurityalert39.md)<br> ↳[cef-sophos-security-alert-18](Ps/pC_cefsophossecurityalert18.md)<br> ↳[sophos-security-alert](Ps/pC_sophossecurityalert.md)<br> ↳[sophos-security-alert-1](Ps/pC_sophossecurityalert1.md)<br> ↳[sophos-leef-epp-virus-alert](Ps/pC_sophosleefeppvirusalert.md)<br> ↳[sophos-security-alert-2](Ps/pC_sophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-11](Ps/pC_cefsophossecurityalert11.md)<br> ↳[cef-sophos-security-alert-33](Ps/pC_cefsophossecurityalert33.md)<br> ↳[cef-sophos-security-alert-12](Ps/pC_cefsophossecurityalert12.md)<br> ↳[cef-sophos-security-alert-34](Ps/pC_cefsophossecurityalert34.md)<br> ↳[cef-sophos-security-alert-10](Ps/pC_cefsophossecurityalert10.md)<br> ↳[cef-sophos-security-alert-32](Ps/pC_cefsophossecurityalert32.md)<br> ↳[cef-sophos-security-alert-15](Ps/pC_cefsophossecurityalert15.md)<br> ↳[cef-sophos-security-alert-37](Ps/pC_cefsophossecurityalert37.md)<br> ↳[cef-sophos-security-alert-38](Ps/pC_cefsophossecurityalert38.md)<br> ↳[cef-sophos-security-alert-13](Ps/pC_cefsophossecurityalert13.md)<br> ↳[cef-sophos-security-alert-35](Ps/pC_cefsophossecurityalert35.md)<br> ↳[cef-sophos-security-alert-14](Ps/pC_cefsophossecurityalert14.md)<br> ↳[cef-sophos-security-alert-36](Ps/pC_cefsophossecurityalert36.md)<br> ↳[sophos-epp-logwriter-alert](Ps/pC_sophosepplogwriteralert.md)<br> ↳[sophos-threat-alert](Ps/pC_sophosthreatalert.md)<br> ↳[sophos-threat-alert-1](Ps/pC_sophosthreatalert1.md)<br> ↳[syslog-sophos-snmp-alert-detected](Ps/pC_syslogsophossnmpalertdetected.md)<br> ↳[xml-sophos-security-alert](Ps/pC_xmlsophossecurityalert.md)<br> ↳[syslog-sophos-snmp-alert-belongs](Ps/pC_syslogsophossnmpalertbelongs.md)<br><br> usb-read<br> ↳[cef-sophos-usb-read](Ps/pC_cefsophosusbread.md)<br><br> usb-write<br> ↳[sophos-leef-epp-usb-activity](Ps/pC_sophosleefeppusbactivity.md)<br> ↳[sophos-leef-epp-usb-activity-2](Ps/pC_sophosleefeppusbactivity2.md)<br> | T1053.003 - T1053.003<br>T1190 - Exploit Public Fasing Application<br>T1562.004 - Impair Defenses: Disable or Modify System Firewall<br>TA0002 - TA0002<br>TA0011 - TA0011<br>    | [<ul><li>34 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_sophos_sophos_endpoint_protection_Malware.md)         |
| [Privileged Activity](../../../UseCases/uc_privileged_activity.md) |  app-activity-failed<br> ↳[sophos-app-activity-failed](Ps/pC_sophosappactivityfailed.md)<br> ↳[sophos-app-activity-failed-1](Ps/pC_sophosappactivityfailed1.md)<br><br> file-alert<br> ↳[syslog-sophos-snmp-denied](Ps/pC_syslogsophossnmpdenied.md)<br> ↳[syslog-sophos-snmp-alert-detected](Ps/pC_syslogsophossnmpalertdetected.md)<br> ↳[syslog-sophos-snmp-alert-belongs](Ps/pC_syslogsophossnmpalertbelongs.md)<br><br> security-alert<br> ↳[cef-sophos-security-alert-40](Ps/pC_cefsophossecurityalert40.md)<br> ↳[cef-sophos-security-alert-41](Ps/pC_cefsophossecurityalert41.md)<br> ↳[cef-sophos-security-alert-2](Ps/pC_cefsophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-3](Ps/pC_cefsophossecurityalert3.md)<br> ↳[cef-sophos-security-alert-4](Ps/pC_cefsophossecurityalert4.md)<br> ↳[cef-sophos-security-alert-42](Ps/pC_cefsophossecurityalert42.md)<br> ↳[cef-sophos-security-alert-5](Ps/pC_cefsophossecurityalert5.md)<br> ↳[cef-sophos-security-alert-43](Ps/pC_cefsophossecurityalert43.md)<br> ↳[cef-sophos-security-alert-6](Ps/pC_cefsophossecurityalert6.md)<br> ↳[cef-sophos-security-alert-26](Ps/pC_cefsophossecurityalert26.md)<br> ↳[cef-sophos-security-alert-7](Ps/pC_cefsophossecurityalert7.md)<br> ↳[cef-sophos-security-alert-8](Ps/pC_cefsophossecurityalert8.md)<br> ↳[sophos-leef-epp-web-alert](Ps/pC_sophosleefeppwebalert.md)<br> ↳[cef-sophos-security-alert-30](Ps/pC_cefsophossecurityalert30.md)<br> ↳[cef-sophos-security-alert-1](Ps/pC_cefsophossecurityalert1.md)<br> ↳[cc-sophos-security-alert](Ps/pC_ccsophossecurityalert.md)<br> ↳[cef-sophos-security-alert-39](Ps/pC_cefsophossecurityalert39.md)<br> ↳[cef-sophos-security-alert-18](Ps/pC_cefsophossecurityalert18.md)<br> ↳[sophos-security-alert](Ps/pC_sophossecurityalert.md)<br> ↳[sophos-security-alert-1](Ps/pC_sophossecurityalert1.md)<br> ↳[sophos-leef-epp-virus-alert](Ps/pC_sophosleefeppvirusalert.md)<br> ↳[sophos-security-alert-2](Ps/pC_sophossecurityalert2.md)<br> ↳[cef-sophos-security-alert-11](Ps/pC_cefsophossecurityalert11.md)<br> ↳[cef-sophos-security-alert-33](Ps/pC_cefsophossecurityalert33.md)<br> ↳[cef-sophos-security-alert-12](Ps/pC_cefsophossecurityalert12.md)<br> ↳[cef-sophos-security-alert-34](Ps/pC_cefsophossecurityalert34.md)<br> ↳[cef-sophos-security-alert-10](Ps/pC_cefsophossecurityalert10.md)<br> ↳[cef-sophos-security-alert-32](Ps/pC_cefsophossecurityalert32.md)<br> ↳[cef-sophos-security-alert-15](Ps/pC_cefsophossecurityalert15.md)<br> ↳[cef-sophos-security-alert-37](Ps/pC_cefsophossecurityalert37.md)<br> ↳[cef-sophos-security-alert-38](Ps/pC_cefsophossecurityalert38.md)<br> ↳[cef-sophos-security-alert-13](Ps/pC_cefsophossecurityalert13.md)<br> ↳[cef-sophos-security-alert-35](Ps/pC_cefsophossecurityalert35.md)<br> ↳[cef-sophos-security-alert-14](Ps/pC_cefsophossecurityalert14.md)<br> ↳[cef-sophos-security-alert-36](Ps/pC_cefsophossecurityalert36.md)<br> ↳[sophos-epp-logwriter-alert](Ps/pC_sophosepplogwriteralert.md)<br> ↳[sophos-threat-alert](Ps/pC_sophosthreatalert.md)<br> ↳[sophos-threat-alert-1](Ps/pC_sophosthreatalert1.md)<br> ↳[syslog-sophos-snmp-alert-detected](Ps/pC_syslogsophossnmpalertdetected.md)<br> ↳[xml-sophos-security-alert](Ps/pC_xmlsophossecurityalert.md)<br> ↳[syslog-sophos-snmp-alert-belongs](Ps/pC_syslogsophossnmpalertbelongs.md)<br>    | T1068 - Exploitation for Privilege Escalation<br>T1078 - Valid Accounts<br>    | [<ul><li>3 Rules</li></ul>](RM/r_m_sophos_sophos_endpoint_protection_Privileged_Activity.md)    |
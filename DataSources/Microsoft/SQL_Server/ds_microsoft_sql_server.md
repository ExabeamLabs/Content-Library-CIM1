Vendor: Microsoft
=================
Product: SQL Server
-------------------
| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  110  |   42   |     17     |      7      |    7    |

|    Use-Case    | Event Types/Parsers    | MITRE TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Abnormal Authentication & Access](../../../UseCases/uc_abnormal_authentication_&_access.md) |  database-access<br> ↳[cef-mssql-database-login](Ps/pC_cefmssqldatabaselogin.md)<br><br> database-failed-login<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br><br> database-login<br> ↳[s-database-login-18454](Ps/pC_sdatabaselogin18454.md)<br> ↳[s-database-login-18453](Ps/pC_sdatabaselogin18453.md)<br> ↳[cef-syslog-microsoft-db-login](Ps/pC_cefsyslogmicrosoftdblogin.md)<br> ↳[cef-syslog-microsoft-db-impersonate](Ps/pC_cefsyslogmicrosoftdbimpersonate.md)<br> ↳[s-mssql-database-login-xml](Ps/pC_smssqldatabaseloginxml.md)<br> ↳[s-mssql-database-login](Ps/pC_smssqldatabaselogin.md)<br> ↳[mssql-database-login](Ps/pC_mssqldatabaselogin.md)<br> ↳[cef-microsoft-database-login](Ps/pC_cefmicrosoftdatabaselogin.md)<br> ↳[s-mssql-database-login-1](Ps/pC_smssqldatabaselogin1.md)<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br> ↳[xml-mssql-database-login-1](Ps/pC_xmlmssqldatabaselogin1.md)<br> ↳[s-mssql-database-login-failed-xml](Ps/pC_smssqldatabaseloginfailedxml.md)<br> ↳[cef-microsoft-database-failed-login-1](Ps/pC_cefmicrosoftdatabasefailedlogin1.md)<br> ↳[s-mssql-database-login-failed](Ps/pC_smssqldatabaseloginfailed.md)<br> ↳[cef-microsoft-database-failed-login](Ps/pC_cefmicrosoftdatabasefailedlogin.md)<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br> ↳[xml-mssql-database-login-1](Ps/pC_xmlmssqldatabaselogin1.md)<br> ↳[mssql-database-login-1](Ps/pC_mssqldatabaselogin1.md)<br> ↳[s-microsoft-database-login](Ps/pC_smicrosoftdatabaselogin.md)<br><br> database-query<br> ↳[mssql-database-query-3](Ps/pC_mssqldatabasequery3.md)<br> ↳[s-mssql-database-query-sl-xml](Ps/pC_smssqldatabasequeryslxml.md)<br> ↳[s-mssql-database-query-al](Ps/pC_smssqldatabasequeryal.md)<br> ↳[s-mssql-database-query-dl](Ps/pC_smssqldatabasequerydl.md)<br> ↳[s-mssql-database-query-sl](Ps/pC_smssqldatabasequerysl.md)<br> ↳[s-mssql-database-query-dl-xml](Ps/pC_smssqldatabasequerydlxml.md)<br> ↳[s-mssql-database-query-al-xml](Ps/pC_smssqldatabasequeryalxml.md)<br> ↳[mssql-database-query-2](Ps/pC_mssqldatabasequery2.md)<br> ↳[cef-mssql-database-access](Ps/pC_cefmssqldatabaseaccess.md)<br> ↳[mssql-database-query-2](Ps/pC_mssqldatabasequery2.md)<br><br> failed-app-login<br> ↳[s-failed-app-login](Ps/pC_sfailedapplogin.md)<br> ↳[exalms-sqlserver-failed-login](Ps/pC_exalmssqlserverfailedlogin.md)<br><br> file-read<br> ↳[s-microsoft-database-login](Ps/pC_smicrosoftdatabaselogin.md)<br><br> web-activity-denied<br> ↳[cef-microsoft-database-delete](Ps/pC_cefmicrosoftdatabasedelete.md)<br> | T1071.001 - Application Layer Protocol: Web Protocols<br>T1133 - External Remote Services<br>    | [<ul><li>6 Rules</li></ul><ul><li>6 Models</li></ul>](RM/r_m_microsoft_sql_server_Abnormal_Authentication_&_Access.md) |
|          [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md)          |  database-access<br> ↳[cef-mssql-database-login](Ps/pC_cefmssqldatabaselogin.md)<br><br> database-failed-login<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br><br> database-login<br> ↳[s-database-login-18454](Ps/pC_sdatabaselogin18454.md)<br> ↳[s-database-login-18453](Ps/pC_sdatabaselogin18453.md)<br> ↳[cef-syslog-microsoft-db-login](Ps/pC_cefsyslogmicrosoftdblogin.md)<br> ↳[cef-syslog-microsoft-db-impersonate](Ps/pC_cefsyslogmicrosoftdbimpersonate.md)<br> ↳[s-mssql-database-login-xml](Ps/pC_smssqldatabaseloginxml.md)<br> ↳[s-mssql-database-login](Ps/pC_smssqldatabaselogin.md)<br> ↳[mssql-database-login](Ps/pC_mssqldatabaselogin.md)<br> ↳[cef-microsoft-database-login](Ps/pC_cefmicrosoftdatabaselogin.md)<br> ↳[s-mssql-database-login-1](Ps/pC_smssqldatabaselogin1.md)<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br> ↳[xml-mssql-database-login-1](Ps/pC_xmlmssqldatabaselogin1.md)<br> ↳[s-mssql-database-login-failed-xml](Ps/pC_smssqldatabaseloginfailedxml.md)<br> ↳[cef-microsoft-database-failed-login-1](Ps/pC_cefmicrosoftdatabasefailedlogin1.md)<br> ↳[s-mssql-database-login-failed](Ps/pC_smssqldatabaseloginfailed.md)<br> ↳[cef-microsoft-database-failed-login](Ps/pC_cefmicrosoftdatabasefailedlogin.md)<br> ↳[xml-mssql-database-login](Ps/pC_xmlmssqldatabaselogin.md)<br> ↳[xml-mssql-database-login-1](Ps/pC_xmlmssqldatabaselogin1.md)<br> ↳[mssql-database-login-1](Ps/pC_mssqldatabaselogin1.md)<br> ↳[s-microsoft-database-login](Ps/pC_smicrosoftdatabaselogin.md)<br><br> database-query<br> ↳[mssql-database-query-3](Ps/pC_mssqldatabasequery3.md)<br> ↳[s-mssql-database-query-sl-xml](Ps/pC_smssqldatabasequeryslxml.md)<br> ↳[s-mssql-database-query-al](Ps/pC_smssqldatabasequeryal.md)<br> ↳[s-mssql-database-query-dl](Ps/pC_smssqldatabasequerydl.md)<br> ↳[s-mssql-database-query-sl](Ps/pC_smssqldatabasequerysl.md)<br> ↳[s-mssql-database-query-dl-xml](Ps/pC_smssqldatabasequerydlxml.md)<br> ↳[s-mssql-database-query-al-xml](Ps/pC_smssqldatabasequeryalxml.md)<br> ↳[mssql-database-query-2](Ps/pC_mssqldatabasequery2.md)<br> ↳[cef-mssql-database-access](Ps/pC_cefmssqldatabaseaccess.md)<br> ↳[mssql-database-query-2](Ps/pC_mssqldatabasequery2.md)<br><br> failed-app-login<br> ↳[s-failed-app-login](Ps/pC_sfailedapplogin.md)<br> ↳[exalms-sqlserver-failed-login](Ps/pC_exalmssqlserverfailedlogin.md)<br><br> file-read<br> ↳[s-microsoft-database-login](Ps/pC_smicrosoftdatabaselogin.md)<br><br> web-activity-denied<br> ↳[cef-microsoft-database-delete](Ps/pC_cefmicrosoftdatabasedelete.md)<br> | T1003.001 - T1003.001<br>T1003.003 - T1003.003<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1083 - File and Directory Discovery<br>T1102 - Web Service<br>T1189 - Drive-by Compromise<br>T1204.001 - T1204.001<br>T1213 - Data from Information Repositories<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>72 Rules</li></ul><ul><li>37 Models</li></ul>](RM/r_m_microsoft_sql_server_Compromised_Credentials.md)        |
[Next Page -->>](2_ds_microsoft_sql_server.md)

ATT&CK Matrix for Enterprise
----------------------------
| Initial Access                                                                                                                                                                                                                                                                                                                                                             | Execution                                                           | Persistence                                                                                                                                      | Privilege Escalation                                                | Defense Evasion                                                     | Credential Access                                                          | Discovery                                                                         | Lateral Movement                                                            | Collection                                                                              | Command and Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        | Exfiltration                                                                                                                                                                                            | Impact                                                                  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| [Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002)<br><br>[External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br>[Drive-by Compromise](https://attack.mitre.org/techniques/T1189)<br><br>[Phishing](https://attack.mitre.org/techniques/T1566)<br><br> | [User Execution](https://attack.mitre.org/techniques/T1204)<br><br> | [External Remote Services](https://attack.mitre.org/techniques/T1133)<br><br>[Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [Valid Accounts](https://attack.mitre.org/techniques/T1078)<br><br> | [OS Credential Dumping](https://attack.mitre.org/techniques/T1003)<br><br> | [File and Directory Discovery](https://attack.mitre.org/techniques/T1083)<br><br> | [Internal Spearphishing](https://attack.mitre.org/techniques/T1534)<br><br> | [Data from Information Repositories](https://attack.mitre.org/techniques/T1213)<br><br> | [Web Service](https://attack.mitre.org/techniques/T1102)<br><br>[Application Layer Protocol: Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br><br>[Dynamic Resolution](https://attack.mitre.org/techniques/T1568)<br><br>[Dynamic Resolution: Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br><br>[Proxy: Multi-hop Proxy](https://attack.mitre.org/techniques/T1090/003)<br><br>[Application Layer Protocol](https://attack.mitre.org/techniques/T1071)<br><br>[Proxy](https://attack.mitre.org/techniques/T1090)<br><br> | [Exfiltration Over Web Service: Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br><br>[Exfiltration Over Web Service](https://attack.mitre.org/techniques/T1567)<br><br> | [Resource Hijacking](https://attack.mitre.org/techniques/T1496)<br><br> |
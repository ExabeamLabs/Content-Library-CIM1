Vendor: ESET
============
### Product: [ESET Endpoint Security](../ds_eset_eset_endpoint_security.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  79   |   34   |     8      |      6      |    6    |

| Event Type                | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | Models                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| app-login                 | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br> ↳ <b>NEW-USER-F</b>: User with no event history<br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-UAg-F</b>: First user agent string for user<br> ↳ <b>APP-UAg-2</b>: Second new user agent string for user<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session<br> ↳ <b>APP-UsH-F</b>: First source asset for user in application<br> ↳ <b>APP-UsH-A</b>: Abnormal source asset for user in application<br> ↳ <b>APP-UId-F</b>: First use of client Id for user<br> ↳ <b>APP-IdU-F</b>: Reuse of client Id<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br><br><b>T1078 - Valid Accounts</b><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |  • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-IdU</b>: User per Client Id<br> • <b>APP-UId</b>: Client Id per User<br> • <b>APP-UsH</b>: User's machines accessing applications<br> • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>AE-UA</b>: All activity for users                                                                                                     |
| authentication-failed     | <b>T1133 - External Remote Services</b><br> ↳ <b>FA-UC-F</b>: Failed activity from a new country<br> ↳ <b>FA-GC-F</b>: First Failed activity in session from country in which peer group has never had a successful activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |  • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |  • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>AE-UA</b>: All activity for users                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| failed-logon              | <b>T1078 - Valid Accounts</b><br> ↳ <b>SEQ-UH-03</b>: Failed logon to a top failed logon asset by user<br> ↳ <b>SEQ-UH-04</b>: Failed logon by a service account<br> ↳ <b>SEQ-UH-05</b>: Failed interactive logon by a service account<br> ↳ <b>SEQ-UH-06</b>: Abnormal failed logon to asset by user<br> ↳ <b>SEQ-UH-07</b>: Failed logon to an asset that user has not previously accessed<br> ↳ <b>SEQ-UH-14</b>: Failed logon due to bad credentials<br><br><b>T1110 - Brute Force</b><br> ↳ <b>SEQ-UH-08</b>: Abnormal number of failed logons for this user<br> ↳ <b>SEQ-UH-09</b>: Abnormal time of the week for a failed logon for user<br> ↳ <b>SEQ-UH-10</b>: Failed logons had multiple reasons                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |  • <b>FL-UH</b>: All Failed Logons per user<br> • <b>AE-UA</b>: All activity for users<br> • <b>FL-OH</b>: All Failed Logons in the organization                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| security-alert            | <b>T1078 - Valid Accounts</b><br> ↳ <b>SA-AN-ALERT-F</b>: First security alert name on the asset<br> ↳ <b>SA-ON-ALERT-F</b>: First security alert (by name) in the organization<br> ↳ <b>SA-ON-ALERT-A</b>: Abnormal security alert (by name) in the organization<br> ↳ <b>SA-ZN-ALERT-F</b>: First security alert (by name) in the zone<br> ↳ <b>SA-ZN-ALERT-A</b>: Abnormal security alert (by name) in the zone<br> ↳ <b>SA-HN-ALERT-F</b>: First security alert (by name) in the asset<br> ↳ <b>SA-HN-ALERT-A</b>: Abnormal security alert (by name) in the asset<br> ↳ <b>SA-OU-ALERT-F</b>: First security alert triggered for this user in the organization<br> ↳ <b>SA-OU-ALERT-A</b>: Abnormal user triggering security alert in the organization<br> ↳ <b>SA-OG-ALERT-F</b>: First security alert triggered for peer group in the organization<br> ↳ <b>SA-OG-ALERT-A</b>: Abnormal peer group triggering security alert in the organization<br> ↳ <b>SA-UA-F</b>: First security alert name for user<br> ↳ <b>SA-UA-A</b>: Abnormal security alert name for user<br> ↳ <b>SA-OA-F</b>: First security alert name in the organization<br> ↳ <b>SA-OA-A</b>: Abnormal security alert name in the organization<br><br><b>T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools</b><br> ↳ <b>A-ALERT-DISTINCT-NAMES</b>: Various security alerts on asset<br> ↳ <b>A-ALERT</b>: Security alert on asset<br><br><b>T1059.001 - Command and Scripting Interperter: PowerShell</b><br> ↳ <b>A-ALERT-COMPROMISED-POWERSHELL</b>: Powershell and security alerts                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |  • <b>SA-OA</b>: Security alert names in the organization<br> • <b>SA-UA</b>: Security alert names for user<br> • <b>SA-OG-ALERT</b>: Peer groups triggering security alerts in the organization<br> • <b>SA-OU-ALERT</b>: Users triggering security alerts in the organization<br> • <b>A-SA-HN-ALERT</b>: Security alert names triggered by the asset<br> • <b>A-SA-ZN-ALERT</b>: Security alert names triggered in the zone<br> • <b>A-SA-ON-ALERT</b>: Security alert names triggered in the organization<br> • <b>A-SA-AN-ALERT</b>: Security alert names on asset                                                                                                                                                                                                                          |
| web-activity-denied       | <b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-HA-F</b>: First web activity event on asset<br> ↳ <b>A-WEB-Reputation-URL</b>: Asset attempted access to a url with bad reputation<br> ↳ <b>A-WEB-Reputation-Domain</b>: Asset attempted access to a domain with bad reputation<br> ↳ <b>A-WEB-Reputation-IP</b>: Asset attempted to connect to IP address with bad reputation<br> ↳ <b>WEBF-IP-Country-F</b>: Asset failed to directly connect to an IP address in a country never before accessed<br> ↳ <b>WEBF-IP-Country-A</b>: Abnormal direct access to an IP address by the asset belonging to an abnormal country for the asset to access has failed<br> ↳ <b>HCountry-Outbound-WEB-F</b>: First failed web browsing connection to this country from asset<br> ↳ <b>HCountry-Outbound-WEB-A</b>: Web browsing connection to abnormal country for asset has failed<br> ↳ <b>OCountry-Outbound-WEB-F</b>: First failed web browsing connection to this country from organization<br> ↳ <b>OCountry-Outbound-WEB-A</b>: Web browsing connection to abnormal country for the organization has failed<br> ↳ <b>WEB-UU-Reputation</b>: User attempted access to a url with bad reputation<br> ↳ <b>WEB-UD-Reputation-F</b>: First access to this web domain which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UD-Reputation-A</b>: Abnormal access to this web domain which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UD-Reputation-N</b>: Common access to this web domain which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UI-Reputation-F</b>: First access to this internet IP address which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UI-Reputation-A</b>: Abnormal access to this IP address which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UI-Reputation-N</b>: Common access to this IP address which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UD-ALERT-F</b>: First security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-A</b>: Abnormal security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-N</b>: Common security alert on this malicious domain for user<br> ↳ <b>WEB-UT-TOW-A</b>: Abnormal day for this user to access the web via the organization<br> ↳ <b>WEB-UZ-F</b>: First web activity for this user in this zone<br> ↳ <b>WEB-OZ-F</b>: First web activity from this zone for the organization<br> ↳ <b>WEB-Fail-10</b>: Failed to access 10 websites.<br> ↳ <b>WEB-IPF-Country-F</b>: User has failed trying to directly browse to an IP address belonging to a country never before accessed<br><br><b>T1550.002 - Use Alternate Authentication Material: Pass the Hash</b><br> ↳ <b>A-WEB-IP</b>: Asset has browsed to an IP address instead of a domain name<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |  • <b>WEB-OZ</b>: Network zones where users performs web activity in the organization<br> • <b>WEB-UZ</b>: Network zones where a user performs web activity from<br> • <b>WEB-UT-TOW</b>: Web activity activity time for user<br> • <b>WEB-UD-ALERT</b>: Top malicious web domain accessed by the user<br> • <b>WEB-UI-Reputation</b>: Top ip addresses flagged by a reputation service that have been accessed by the user<br> • <b>WEB-UD-Reputation</b>: Top web domain flagged by a reputation service that have been accessed by the user<br> • <b>A-NET-OCountry-Outbound</b>: Outbound country per organization<br> • <b>A-NET-HCountry-Outbound</b>: Outbound country per asset<br> • <b>A-WEB-IP</b>: IPs an asset has directly browsed to<br> • <b>A-WEB-HA</b>: Web activity per Host |
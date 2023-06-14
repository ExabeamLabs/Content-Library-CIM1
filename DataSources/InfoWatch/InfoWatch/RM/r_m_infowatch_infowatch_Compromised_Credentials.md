Vendor: InfoWatch
=================
### Product: [InfoWatch](../ds_infowatch_infowatch.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE ATT&CK® TTPs | Event Types | Parsers |
|:-----:|:------:|:------------------:|:-----------:|:-------:|
|  64   |   39   |         9          |      2      |    2    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| app-login    | <b>T1190 - Exploit Public Fasing Application</b><br> ↳ <b>A-APP-Log4j-String</b>: There was an attempt via app activity to exploit the CVE-2021-44228 vulnerability on this asset.<br> ↳ <b>A-App-Log4j-String-2</b>: There was an attempt via app activity to exploit the CVE-2021-44228 vulnerability using known keywords on the asset.<br> ↳ <b>APP-Log4j-String-2</b>: There was an attempt via app activity to exploit the CVE-2021-44228 vulnerability using known keywords.<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries<br> ↳ <b>APP-UApp-F</b>: First login or activity within an application for user<br> ↳ <b>APP-UApp-A</b>: Abnormal login or activity within an application for user<br> ↳ <b>APP-AppU-F</b>: First login to an application for a user with no history<br> ↳ <b>APP-F-SA-NC</b>: New service account access to application<br> ↳ <b>APP-AppG-F</b>: First login to an application for group<br> ↳ <b>APP-GApp-A</b>: Abnormal login to an application for group<br> ↳ <b>APP-UTi</b>: Abnormal user activity time<br> ↳ <b>APP-UAg-F</b>: First user agent string for user<br> ↳ <b>APP-UAg-2</b>: Second new user agent string for user<br> ↳ <b>APP-UAg-3</b>: More than two new user agents used by the user in the same session<br> ↳ <b>APP-UOs-F</b>: First os/browser combination for user<br> ↳ <b>APP-UsH-F</b>: First source asset for user in application<br> ↳ <b>APP-UsH-A</b>: Abnormal source asset for user in application<br> ↳ <b>APP-UId-F</b>: First use of client Id for user<br> ↳ <b>APP-IdU-F</b>: Reuse of client Id<br> ↳ <b>APP-AppSz-F</b>: First application access from network zone<br> ↳ <b>APP-AppED-F</b>: New Email-domain found in application<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UI-F</b>: First activity from ISP<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-GC-new</b>: Abnormal country for group by new user<br> ↳ <b>UA-OC-new</b>: Abnormal country for organization by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries<br> ↳ <b>UA-UC-Three</b>: Activity from 3 different countries    |  • <b>APP-AppED</b>: Email-domains per application<br> • <b>APP-AppSz</b>: Source zones per application<br> • <b>APP-IdU</b>: User per Client Id<br> • <b>APP-UId</b>: Client Id per User<br> • <b>APP-UsH</b>: User's machines accessing applications<br> • <b>APP-UOs-New</b>: OS and Browser from user agent<br> • <b>APP-UAg</b>: User Agent Strings<br> • <b>APP-UTi</b>: Application activity time for user<br> • <b>APP-GApp</b>: Group Logons to Applications<br> • <b>APP-AppG</b>: Groups per Application<br> • <b>APP-AppU</b>: User Logons to Applications<br> • <b>APP-UApp</b>: Applications per User<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-UI-new</b>: ISP of users during application activity    |
| web-activity-allowed | <b>T1190 - Exploit Public Fasing Application</b><br> ↳ <b>A-WEB-Mime-Types-Org-F</b>: First occurence of this mime type on this asset for organization<br> ↳ <b>A-WEB-Base64CommandUserAgent</b>: User agent with encoded commands was detected from this web activity.<br> ↳ <b>A-WEB-Log4j-String-2</b>: There was an attempt via web activity to exploit the CVE-2021-44228 vulnerability using known keywords on the asset.<br> ↳ <b>WEB-Log4j-String-2</b>: There was an attempt via web activity to exploit the CVE-2021-44228 vulnerability using known keywords.<br><br><b>T1071.001 - Application Layer Protocol: Web Protocols</b><br> ↳ <b>A-WEB-HA-F</b>: First web activity event on asset<br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller<br> ↳ <b>A-WEB-IP-Country-F</b>: Asset has directly browsed to an IP address in a country never before accessed<br> ↳ <b>A-WEB-IP-Country-A</b>: Abnormal direct access to an IP address by the asset belonging to an abnormal country for the asset to access<br> ↳ <b>A-NET-HCountry-Outbound-WEB-F</b>: First web connection to this country from asset<br> ↳ <b>A-NET-HCountry-Outbound-WEB-A</b>: Abnormal web browsing communication country for asset<br> ↳ <b>A-NET-OCountry-Outbound-WEB-F</b>: First web browsing connection to this country from organization<br> ↳ <b>A-NET-OCountry-Outbound-WEB-A</b>: Abnormal web browsing connection country for the organization<br> ↳ <b>WEB-UUa-OS-F</b>: First web activity using this operating system for this user<br> ↳ <b>WEB-GUa-OS-F</b>: First web activity using this operating system for the peer group<br> ↳ <b>WEB-OUa-OS-F</b>: First web activity using this operating system for the organization<br> ↳ <b>WEB-UUa-MobileBrowser-F</b>: First activity using this mobile web browser/app for this user to a new domain<br> ↳ <b>WEB-OsUa-MobileBrowser-F</b>: First activity using this mobile web browser for this mobile operating system<br> ↳ <b>WEB-UUa-Browser-F</b>: First activity using this web browser for this user to a new domain<br> ↳ <b>WEB-GUa-Browser-F</b>: First activity using this web browser for the peer group<br> ↳ <b>WEB-OUa-Browser-F</b>: First activity using this web browser for the organization<br> ↳ <b>WEB-UD-Reputation-F</b>: First access to this web domain which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UD-Reputation-A</b>: Abnormal access to this web domain which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UI-Reputation-F</b>: First access to this internet IP address which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UI-Reputation-A</b>: Abnormal access to this IP address which has been identified as risky by a reputation feed.<br> ↳ <b>WEB-UD-ALERT-A</b>: Abnormal security alert accessing this malicious domain for user<br> ↳ <b>WEB-UD-ALERT-N</b>: Common security alert on this malicious domain for user<br> ↳ <b>WEB-UT-TOW-A</b>: Abnormal day for this user to access the web via the organization<br> ↳ <b>WEB-UZ-F</b>: First web activity for this user in this zone<br> ↳ <b>WEB-GZ-F</b>: First web activity from this zone for the peer group<br> ↳ <b>WEB-OZ-F</b>: First web activity from this zone for the organization<br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br> ↳ <b>WEB-URank-F</b>: First web activity to this low ranked web domain<br> ↳ <b>WEB-URank-A</b>: Abnormal web activity to this low ranked web domain<br> ↳ <b>WEB-IP-Country-F</b>: User has directly browsed to an IP address belonging to a country never before accessed<br> ↳ <b>WEB-IP-COUNTRY-A</b>: Abnormal direct access to an IP address belonging to an abnormal country for user to access<br><br><b>T1189 - Drive-by Compromise</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br><br><b>T1204.001 - T1204.001</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br><br><b>T1566.002 - Phishing: Spearphishing Link</b><br> ↳ <b>WEB-URank-Binary</b>: Executable download from first low ranked web domain<br><br><b>T1078 - Valid Accounts</b><br> ↳ <b>WEB-ALERT-EXEC</b>: Security violation by Executive in web activity<br><br><b>T1568.002 - Dynamic Resolution: Domain Generation Algorithms</b><br> ↳ <b>WEB-UD-DGA-A</b>: Abnormal access to this domain which has been identified as DGA<br><br><b>T1102 - Web Service</b><br> ↳ <b>A-WEB-DC</b>: Web activity event on a Domain Controller |  • <b>WEB-IP</b>: IPs a user has directly browsed to<br> • <b>WEB-URank</b>: Web activity to low ranked domains for the user<br> • <b>WEB-OZ</b>: Network zones where users performs web activity in the organization<br> • <b>WEB-GZ</b>: Network zones where users performs web activity in the peer group<br> • <b>WEB-UZ</b>: Network zones where a user performs web activity from<br> • <b>WEB-UT-TOW</b>: Web activity activity time for user<br> • <b>WEB-UD-ALERT</b>: Top malicious web domain accessed by the user<br> • <b>WEB-UI-Reputation</b>: Top ip addresses flagged by a reputation service that have been accessed by the user<br> • <b>WEB-UD-Reputation</b>: Top web domain flagged by a reputation service that have been accessed by the user<br> • <b>WEB-OUa-Browser-New</b>: Top web browsers being used in this organization<br> • <b>WEB-GUa-Browser-New</b>: Top web browsers being used by peer group<br> • <b>WEB-UUa-Browser-New</b>: Top web browsers being used by user<br> • <b>WEB-OsUa-MobileBrowser-New</b>: Top mobile apps/web browsers being used in the organization for this type of device<br> • <b>WEB-UUa-MobileBrowser-New</b>: Top mobile apps/web browsers being used by user<br> • <b>WEB-OUa-OS-New</b>: Top operating systems being used to connect to the web for organization<br> • <b>WEB-GUa-OS-New</b>: Top operating systems being used to connect to the web for peer group<br> • <b>WEB-UUa-OS-New</b>: Top operating systems being used to connect to the web for user<br> • <b>WEB-UD-DGA</b>: Top web domains per user that seem to be DGA generated during web activity<br> • <b>A-WEB-Mime-Types-Src</b>: Web Activity MIME types for asset in organization<br> • <b>A-NET-OCountry-Outbound</b>: Outbound country per organization<br> • <b>A-NET-HCountry-Outbound</b>: Outbound country per asset<br> • <b>A-WEB-IP</b>: IPs an asset has directly browsed to<br> • <b>A-WEB-HA</b>: Web activity per Host |
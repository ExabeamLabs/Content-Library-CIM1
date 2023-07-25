Vendor: Tufin
=============
### Product: [SecureTrack](../ds_tufin_securetrack.md)
### Use-Case: [Compromised Credentials](../../../../UseCases/uc_compromised_credentials.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|   7   |   4    |     2      |      1      |    1    |

| Event Type                | Rules                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | Models                                                                                                                                                                               |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| authentication-successful | <b>T1078 - Valid Accounts</b><br> ↳ <b>AE-UA-F</b>: First activity type for user<br><br><b>T1133 - External Remote Services</b><br> ↳ <b>UA-UC-A</b>: Abnormal activity from country for user<br> ↳ <b>UA-GC-F</b>: First activity from country for group<br> ↳ <b>UA-OC-F</b>: First activity from country for organization<br> ↳ <b>UA-UC-new</b>: Abnormal country for user by new user<br> ↳ <b>UA-UC-Suspicious</b>: Activity from suspicious country<br> ↳ <b>UA-UC-Two</b>: Activity from two different countries |  • <b>UA-UC</b>: Countries for user activity<br> • <b>UA-OC</b>: Countries for organization<br> • <b>UA-GC</b>: Countries for peer groups<br> • <b>AE-UA</b>: All activity for users |
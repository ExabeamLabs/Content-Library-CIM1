Vendor: Unix
============
### Product: [Unix](../ds_unix_unix.md)
### Use-Case: [Data Access](../../../../UseCases/uc_data_access.md)

| Rules | Models | MITRE TTPs | Event Types | Parsers |
|:-----:|:------:|:----------:|:-----------:|:-------:|
|  45   |   23   |     4      |     28      |   28    |

| Event Type    | Rules    | Models    |
| ---- | ---- | ---- |
| database-query         | <b>T1213 - Data from Information Repositories</b><br> ↳ <b>DB-DbU-F</b>: First access to database for user<br> ↳ <b>DB-DbU-A</b>: Abnormal access to database for user<br> ↳ <b>DB-DbG-F</b>: First access to database for peer group<br> ↳ <b>DB-DbG-A</b>: Abnormal access to database for peer group<br> ↳ <b>DB-UDbZ-F</b>: First database activity from source zone per user, database<br> ↳ <b>DB-UDbZ-A</b>: Abnormal database activity from source zone per user, database<br> ↳ <b>DB-UDbH-F</b>: First database activity from host per user, database<br> ↳ <b>DB-UDbH-A</b>: Abnormal database activity from host per user, database<br> ↳ <b>DB-UDbI-F</b>: First database activity from IP per user, database<br> ↳ <b>DB-UDbI-A</b>: Abnormal database activity from IP per user, database<br> ↳ <b>DB-UDbO-F</b>: First database operation for user, database<br> ↳ <b>DB-UDbO-A</b>: Abnormal database operation for user, database<br> ↳ <b>DB-GDbO-F</b>: First database operation for peer group, database<br> ↳ <b>DB-GDbO-A</b>: Abnormal database operation for peer group, database<br> ↳ <b>DB-DbZO-F</b>: First database operation from source zone for database<br> ↳ <b>DB-DbZO-A</b>: Abnormal database operation from source zone for database<br> ↳ <b>DB-UDbR</b>: Abnormal database query response size for user, database<br> ↳ <b>DB-DbZR</b>: Abnormal database query response size for source zone, database    |  • <b>DB-DbZR</b>: Response size of database queries per zone, database<br> • <b>DB-UDbR</b>: Response size of database queries per user, database<br> • <b>DB-DbZO</b>: Database operations per database, source zone<br> • <b>DB-GDbO</b>: Database operations per peer group, database<br> • <b>DB-UDbO</b>: Database operations per user, database<br> • <b>DB-UDbI</b>: Database activity from source IP per user, database<br> • <b>DB-UDbH</b>: Database activity from host per user, database<br> • <b>DB-UDbZ</b>: Database activity from source zone per user, database<br> • <b>DB-DbG</b>: Peer groups per database<br> • <b>DB-DbU</b>: Users per database    |
| failed-app-login       | <b>T1078 - Valid Accounts</b><br> ↳ <b>APP-F-FL</b>: Failed login to application    |    |
| file-permission-change | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-F</b>: First file activity from country for user<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-UA-GC-A</b>: Abnormal file activity from country for group<br> ↳ <b>FA-UA-OC-F</b>: First file activity from country for organization<br> ↳ <b>FA-UA-OC-A</b>: Abnormal file activity from country for organization<br> ↳ <b>FA-UTi</b>: Abnormal user file activity time<br> ↳ <b>FA-UH-F</b>: First file access from asset for user<br> ↳ <b>FA-UH-A</b>: Abnormal file access from asset for user<br> ↳ <b>FA-OZ-F</b>: First file access from network zone for organization<br> ↳ <b>FA-OZ-A</b>: Abnormal file access from network zone for organization<br> ↳ <b>FA-UZ-F</b>: First file access from network zone for user<br> ↳ <b>FA-UZ-A</b>: Abnormal file access from network zone for user<br> ↳ <b>FA-UA-F</b>: First file access activity for user<br> ↳ <b>FA-UA-A</b>: Abnormal file access activity for user<br> ↳ <b>FA-OU-F</b>: First access to source code files for user in the organization<br> ↳ <b>FA-OU-A</b>: Abnormal access to source code files for user in the organization<br> ↳ <b>FA-OG-F</b>: First access to source code files for user in the peer group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-UD-F</b>: First file server access for user<br> ↳ <b>FA-UD-A</b>: Abnormal file server access for user<br> ↳ <b>FA-GD-F</b>: First file server access for group<br> ↳ <b>FA-GD-A</b>: Abnormal file server access for group |  • <b>FA-GD</b>: File server access per group<br> • <b>FA-UD</b>: File server access per user<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-OU</b>: Users accessing source code files in the organization<br> • <b>FA-UA</b>: File access activities for user<br> • <b>FA-UZ</b>: File accesses from network zone for user<br> • <b>FA-OZ</b>: File accesses from network zone for organization<br> • <b>FA-UH</b>: User file access source host<br> • <b>FA-UTi</b>: File activity time for user<br> • <b>FA-UA-OC</b>: Countries for organization file activities<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |
| file-read    | <b>T1083 - File and Directory Discovery</b><br> ↳ <b>FA-UA-UI-F</b>: First file activity from ISP<br> ↳ <b>FA-UA-UC-F</b>: First file activity from country for user<br> ↳ <b>FA-UA-UC-A</b>: Abnormal file activity from country for user<br> ↳ <b>FA-UA-GC-F</b>: First file activity from country for group<br> ↳ <b>FA-UA-GC-A</b>: Abnormal file activity from country for group<br> ↳ <b>FA-UA-OC-F</b>: First file activity from country for organization<br> ↳ <b>FA-UA-OC-A</b>: Abnormal file activity from country for organization<br> ↳ <b>FA-UTi</b>: Abnormal user file activity time<br> ↳ <b>FA-UH-F</b>: First file access from asset for user<br> ↳ <b>FA-UH-A</b>: Abnormal file access from asset for user<br> ↳ <b>FA-OZ-F</b>: First file access from network zone for organization<br> ↳ <b>FA-OZ-A</b>: Abnormal file access from network zone for organization<br> ↳ <b>FA-UZ-F</b>: First file access from network zone for user<br> ↳ <b>FA-UZ-A</b>: Abnormal file access from network zone for user<br> ↳ <b>FA-UA-F</b>: First file access activity for user<br> ↳ <b>FA-UA-A</b>: Abnormal file access activity for user<br> ↳ <b>FA-OU-F</b>: First access to source code files for user in the organization<br> ↳ <b>FA-OU-A</b>: Abnormal access to source code files for user in the organization<br> ↳ <b>FA-OG-F</b>: First access to source code files for user in the peer group<br> ↳ <b>FA-OG-A</b>: Abnormal access to source code files for user in the peer group<br> ↳ <b>FA-UD-F</b>: First file server access for user<br> ↳ <b>FA-UD-A</b>: Abnormal file server access for user<br> ↳ <b>FA-GD-F</b>: First file server access for group<br> ↳ <b>FA-GD-A</b>: Abnormal file server access for group |  • <b>FA-GD</b>: File server access per group<br> • <b>FA-UD</b>: File server access per user<br> • <b>FA-OG</b>: Users accessing source code files in the peer group<br> • <b>FA-OU</b>: Users accessing source code files in the organization<br> • <b>FA-UA</b>: File access activities for user<br> • <b>FA-UZ</b>: File accesses from network zone for user<br> • <b>FA-OZ</b>: File accesses from network zone for organization<br> • <b>FA-UH</b>: User file access source host<br> • <b>FA-UTi</b>: File activity time for user<br> • <b>FA-UA-OC</b>: Countries for organization file activities<br> • <b>FA-UA-GC</b>: Countries for peer groups file activities<br> • <b>FA-UA-UC</b>: Countries for user file activity<br> • <b>FA-UA-UI-new</b>: ISP of users during file activity |
| process-created        | <b>T1003 - OS Credential Dumping</b><br> ↳ <b>A-CP-Sensitive-Files</b>: Copying sensitive files with credential data on this asset<br> ↳ <b>CP-Sensitive-Files</b>: Copying sensitive files with credential data    |    |
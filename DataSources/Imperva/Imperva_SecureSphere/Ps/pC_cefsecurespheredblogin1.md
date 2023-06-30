#### Parser Content
```Java
{
Name = cef-securesphere-db-login-1
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF""", """|Imperva Inc.|""", """SecureSphere""", """|Database|""", """' logged in to '""" ]
  Fields = [
    """start=({time}\w{3}\s\d{1,100}\s\d\d\d\d\s\d\d:\d\d:\d\d)""",
    """({host}[\w.\-]{1,2000})\s{1,100}CEF:""",
    """suser=(|(({domain}[^\\"=]{1,2000})\\+)?({user}[^\\"]{1,2000}?)){1,100}\w+?=""",
    """CEF:([^\|]{1,2000}\|){7}({severity}[^\|]{1,2000})\|""",
    """src=(0.0.0.0|({src_ip}[a-fA-F\d.:]{1,2000}))""",
    """dst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """dhost=({dest_host}[\w.-]{1,2000})""",
    """msg=({additional_info}[^=]{1,2000}?)\s\w+=."""
  ]
  DupFields = [ "user->db_user" ]


}
```
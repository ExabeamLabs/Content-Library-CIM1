#### Parser Content
```Java
{
Name = f5-vpn-user-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-user"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:Common:""", """Username """ ]
  Fields = [
    """:Common:({session_id}[^\s:]{1,2000}): Username""",
    """\sUsername\s{1,100}'(?:[^'\\]{1,2000}\\{1,20})?({user}[^'\\]{1,2000})'"""
  ]


}
```
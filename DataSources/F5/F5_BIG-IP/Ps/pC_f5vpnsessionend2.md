#### Parser Content
```Java
{
Name = f5-vpn-session-end-2
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-end"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """/Common/""", """:Common:""", """Session deleted""" ]
  Fields = [
    """:Common:({session_id}[^\s:]{1,2000}): Session deleted""",
  ]


}
```
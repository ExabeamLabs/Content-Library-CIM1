#### Parser Content
```Java
{
Name = f5-vpn-additional-info-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:Common:""", """/Common/""", """Session statistics -""" ]
  Fields = [
    """:Common:({session_id}[^:]{1,2000})""",
    """Session statistics - bytes in:\s{0,100}({bytes_in}\d{1,100}),\s{1,100}bytes out:\s{0,100}({bytes_out}\d{1,100})"""
  ]


}
```
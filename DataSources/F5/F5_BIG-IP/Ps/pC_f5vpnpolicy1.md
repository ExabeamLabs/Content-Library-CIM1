#### Parser Content
```Java
{
Name = f5-vpn-policy-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:Common:""", """Access policy result:""" ]
  Fields = [
    """:Common:({session_id}[^\s:]{1,2000}): Access policy result""",
    """\sAccess policy result:\s{0,100}({policy}[^"]{1,2000}?)\s{0,100}("|$)"""
  ]


}
```
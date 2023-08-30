#### Parser Content
```Java
{
Name = f5-vpn-srchost-1
    Vendor = F5
    Product = F5 BIG-IP
    Lms = Splunk
    DataType = "vpn-start"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ """:Common:""", """Received client info""", """Hostname:""" ]
    Fields = [
      """:Common:({session_id}[^:]{1,2000})""",
      """Hostname:\s{0,100}({src_host}[\w\-.]{1,2000})\s{1,100}\w+:""",
      """Platform:\s{0,100}({os}[^\s]{1,2000})\s"""
    ]


}
```
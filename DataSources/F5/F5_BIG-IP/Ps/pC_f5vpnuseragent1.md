#### Parser Content
```Java
{
Name = f5-vpn-user-agent-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-start"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """/Common/""", """:Common:""", """Received User-Agent header:""" ]
  Fields = [
    """:Common:({session_id}[^\s:]{1,2000}): Received User-Agent header:""",
    """Received User-Agent header:\s{0,100}({user_agent}.+?)\s{0,100}$""",
  ]


}
```
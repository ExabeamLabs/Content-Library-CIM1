#### Parser Content
```Java
{
Name = f5-vpn-login-failed-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """:Common:""", """AD Agent:""" ]
  Fields = [
    """:Common:({session_id}[^\s:]{1,2000}): AD Agent:""",
    """AD Agent:\s{0,100}({failure_reason}[^"]{1,2000}?)\s{0,100}("|$)""",
  ]


}
```
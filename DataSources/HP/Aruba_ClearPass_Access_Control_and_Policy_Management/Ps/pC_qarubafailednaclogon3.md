#### Parser Content
```Java
{
Name = q-aruba-failed-nac-logon-3
  Vendor = HP
  Product = Aruba ClearPass Access Control and Policy Management
  Lms = Direct
  TimeFormat = "yyyy-MM-dd HH:mm:ssZ"
  DataType = "nac-failed-logon"
  Conditions = [ """RADIUS.Auth-Method=""", """Common.Error-Code=""", """Common.Alerts=""" ]
  Fields = [
    """Common\.Request-Timestamp=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d(\.\d{1,100})?[\+\-]\d{1,100})""",
    """\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d,\d{1,100} ({host}[\w\-.]{1,2000})""",
    """Common\.Service=({network}[^,]{1,2000})""",
    """Common\.Host-MAC-Address=({src_mac}\w+)""",
    """Common\.NAS-IP-Address=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """Common\.Username=(?:({user_type}host)/)(({src_domain}[^\\\s,]{1,2000})\\+)?(anonymous|({src_host}[^\\\s,@]{1,2000}))""",
    """Common\.Username=(?!(host)/)(({domain}[^\\\s,]{1,2000})\\+)?(anonymous|({user}[^\\\s,@]{1,2000}))""",
    """RADIUS\.Auth-Method=({auth_method}[^=]{1,2000}?),[\w.-]+=""",
    """Common\.Alerts=({failure_reason}[^=]{1,2000}?),[\w.-]+=""",
    """Common\.Error-Code=({event_code}[^=]{1,2000}?),[\w.-]+="""
   ]
   DupFields = [ "host->auth_server" ]


}
```
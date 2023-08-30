#### Parser Content
```Java
{
Name = f5-vpn-assign-ip-1
  Vendor = F5
  Product = F5 BIG-IP
  Lms = Splunk
  DataType = "vpn-set-ip"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """:Common:""", """ client IP """, """/Common/""" ]
  Fields = [
    """:Common:({session_id}[^:]{1,2000})""",
    """\s(?i)Client IP\s{1,100}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"""
    """Listener \/Common\/({host}[\w\-\.]{1,2000})_({dest_port}\d{1,5})\s"""
  ]
  DupFields = ["host->dest_host"]


}
```
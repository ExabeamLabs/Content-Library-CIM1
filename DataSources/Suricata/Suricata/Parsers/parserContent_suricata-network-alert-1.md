#### Parser Content
```Java
{
Name = suricata-network-alert-1
  Vendor = Suricata
  Product = Suricata
  Lms = Syslog
  DataType = "network-alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = ["""pdsuricata""","""suricata""","""event_type""" ]
  Fields = [
    """"{1,20}timestamp"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[^\s]{1,2000})""",
    """"{1,20}event_type"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})"{1,20}""",
    """"{1,20}src_ip"{1,20}:\s{0,100}"{1,20}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"{1,20}""",
    """"{1,20}src_port"{1,20}:\s{0,100}({src_port}[^,]{1,2000})""",
    """"{1,20}dest_ip"{1,20}:\s{0,100}"{1,20}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"{1,20}""",
    """"{1,20}dest_port"{1,20}:\s{0,100}({dest_port}[^,]{1,2000})""",
    """"{1,20}proto"{1,20}:\s{0,100}"{1,20}({protocol}[^"]{1,2000})"{1,20}""",
    """"{1,20}app_proto"{1,20}:\s{0,100}"{1,20}({app_protocol}[^"]{1,2000})"{1,20}""",
    """"{1,20}bytes_toserver"{1,20}:\s{0,100}({bytes_in}[^,]{1,2000})""",
    """"{1,20}bytes_toclient"{1,20}:\s{0,100}({bytes_out}[^,]{1,2000})""",
    """"{1,20}state"{1,20}:\s{0,100}"{1,20}({outcome}[^"]{1,2000})"{1,20}""",
    """"{1,20}reason"{1,20}:\s{0,100}"{1,20}({failure_reason}[^"]{1,2000})"{1,20}""",
    """"{1,20}http_user_agent"{1,20}:\s{0,100}"{1,20}({user_agent}[^"]{1,2000})"{1,20}""",
    """"{1,20}http_method"{1,20}:\s{0,100}"{1,20}({method}[^"]{1,2000})"{1,20}""",
    """"{1,20}filename"{1,20}:\s{0,100}"{1,20}({file_name}[^"]{1,2000})"{1,20}""",
    """"{1,20}status"{1,20}:\s{0,100}"{1,20}({event_code}[^,"]{1,2000})""",
    """"{1,20}url"{1,20}:\s{0,100}"{1,20}({uri_path}[^"]{1,2000})"{1,20}""",
    """"{1,20}hostname"{1,20}:\s{0,100}"{1,20}({host}[^"]{1,2000})"{1,20}""",
    """"{1,20}http_content_type"{1,20}:\s{0,100}"{1,20}({mime}[^"]{1,2000})"{1,20}""",
    """\s({alert_name}suricata)""",
    """"{1,20}category"{1,20}:\s{0,100}"{1,20}({category}[^"]{1,2000})""",
    """"{1,20}severity"{1,20}:\s{0,100}({alert_severity}\d{1,100})""",
    """"{1,20}signature"{1,20}:\s{0,100}"{1,20}({signature}[^"]{1,2000})""",
    """"{1,20}signature_id"{1,20}:\s{0,100}({signature_id}\d{1,100})""",
    """"{1,20}action"{1,20}:\s{0,100}"{1,20}({action}[^"]{1,2000})"""
 ]
}
```
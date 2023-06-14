#### Parser Content
```Java
{
Name = s-bit9-epp-alert
  Vendor = VMware
  Product = Carbon Black App Control
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "MM/dd/yyyy HH:mm:ss a"
  Conditions = [ """"Bit9Server"""", """"ProcessHashType"""" ]
  Fields = [
    """Timestamp":\s{1,100}"({time}[^"]{1,2000})""",
    """Bit9Server":\s{1,100}"({host}[^"]{1,2000})""",
    """EventType":\s{1,100}"({alert_type}[^"]{1,2000})""",
    """EventSubType":\s{1,100}"({alert_name}[^"]{1,2000})""",
    """HostName":\s{1,100}"(({domain}[^\\"]{1,2000})\\{1,20})?({src_host}[^"]{1,2000})""",
    """HostIP":\s{1,100}"({src_ip}[^"]{1,2000})""",
    """Priority":\s{1,100}"({alert_severity}[^"]{1,2000})""",
    """ABId":\s{1,100}"({alert_id}[^"]{1,2000})""",
    """Message":\s{1,100}"({additional_info}[^"]{1,2000})""",
    """PathName":\s{1,100}"({malware_url}[^"]{1,2000})""",
    """UserName":\s{1,100}"({user}[^"]{1,2000})""",
    """c:\\+users\\+({user}[^"\\]{1,2000})""",
  ]


}
```
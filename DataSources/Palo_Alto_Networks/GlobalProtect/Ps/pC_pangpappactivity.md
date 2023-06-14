#### Parser Content
```Java
{
Name = pan-gp-app-activity
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"EventStatus":"success"""", """"AuthMethod":""", """Stage":"tunnel"""", """LogType":"GLOBALPROTECT""", """"EventIDValue":"""" ]
  Fields = [
  """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)"""
  """"DeviceName":"({host}[\w\-\.]{1,2000})"""
  """"PrivateIPv(4|6)":"({dest_ip}[a-fA-F\d:.]{1,2000})""",
  """"PublicIPv(4|6)":"({src_ip}[a-fA-F\d.:]{1,2000})"""
  """"LogType":"({app}[^"]{1,2000})""""
  """"EventStatus":"({outcome}[^"]{1,2000})""""
  """"EndpointDeviceName":"?(null|({src_host}[\w\-\.]{1,2000}))""""
  """"SourceRegion":"(\d\.\d\.\d\.\d|({src_country}[^"]{1,2000}))""""
  """"(Source)?User(Name)?":"?((?i)null|pre-logon|(({user_email}[^\@,"]{1,2000}@[^\.,"]{1,2000}\.[^,"]{1,2000})|({user}[^,"]{1,2000})))""""
  """"EndpointOSType":"({os}[^"]{1,2000})""""
  """"EventIDValue":"({event_name}[^"]{1,2000})""""
  """"AuthMethod":"?((?i)null|({auth_method}[^,"]{1,2000}))"""
  """"Description":"({additional_info}[^"]{1,2000})""""  
  ]
  DupFields = [ "event_name->activity" ]


}
```
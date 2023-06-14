#### Parser Content
```Java
{
Name = json-pan-vpn-login
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Direct
  DataType = "vpn-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"LogType":"GLOBALPROTECT"""", """"EventStatus":"success"""", """"AuthMethod":""", """"Stage":"connected"""" ]
  Fields = [
  """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)"""
  """"DeviceName":"({host}[\w\-\.]{1,2000})"""
  """"PrivateIPv(4|6)":"({src_translated_ip}[a-fA-F\d:.]{1,2000})""",
  """"PublicIPv(4|6)":"({src_ip}[a-fA-F\d.:]{1,2000})"""
  """"LogType":"({app}[^"]{1,2000})""""
  """"EventStatus":"({outcome}[^"]{1,2000})""""
  """"EndpointDeviceName":"({src_host}[\w\-\.]{1,2000})""""
  """"SourceRegion":"({src_country}[^"]{1,2000})""""
  """"(Source)?User(Name)?":"(({user_email}[^\@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(pre-logon|({user}[^"]{1,2000})))""""
  """"EndpointOSType":"({os}[^"]{1,2000})""""
  """"EventIDValue":"({event_name}[^"]{1,2000})""""
  """"AuthMethod":"?((?i)null|({auth_method}[^,"]{1,2000}))"""
  """"Description":"({additional_info}[^"]{1,2000}:\s{0,100}({dest_ip}[a-fA-F\d.:]{1,2000}))""""
  ]


}
```
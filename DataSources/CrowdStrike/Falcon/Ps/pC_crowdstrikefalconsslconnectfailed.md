#### Parser Content
```Java
{
Name = crowdstrike-falcon-ssl-connect-failed
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "network-connection-failed"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CrowdStrike""" ,"""SslConnect: Unable to connect""", """falcon-sensor""", """via Application Proxy:""" ]
  Fields = [
    """\d\d:\d\d\s({host}[\w\-\.]{1,2000})\s({log_source}[^\[]{1,2000})(\[\d{1,100}\]):\sCrowdStrike[^"]{0,2000}SslConnect: ({additional_info}Unable to connect to\s({dest_host}[\w\-\.]{1,2000}))"""
  ]


}
```
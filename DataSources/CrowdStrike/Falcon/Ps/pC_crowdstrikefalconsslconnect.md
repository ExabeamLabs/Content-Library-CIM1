#### Parser Content
```Java
{
Name = crowdstrike-falcon-ssl-connect
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "network-connection-successful"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """CrowdStrike""" ,"""SslConnect: """, """falcon-sensor""" ]
  Fields = [
    """\d\d:\d\d\s({host}[\w\-\.]{1,2000})\s({log_source}[^\[]{1,2000})(\[\d{1,100}\]):\sCrowdStrike[^"]{0,2000}SslConnect:\s({dest_host}[\w\-\.]{1,2000})"""
  ]


}
```
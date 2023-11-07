#### Parser Content
```Java
{
Name = sailpoint-auth-1
  Vendor = Sailpoint
  Product = IdentityNow
  Lms = Splunk
  DataType = "authentication-successful"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"type":"AUTH"""", """"stack":""", """"attributes":""", """"info":"LOGIN_""" ]
  Fields = [
     """"created":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3})"""
     """"hostName":"(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({src_host}[\w\-\.]{1,2000}))""""
     """"actor":[^\}]{1,2000}?"name":\s{0,100}"((?i)Not Available|unknown|({user_email}[^\@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(({user_fullname}[^\s"]{1,2000}\s[^"]{1,2000})|({user}[^"]{1,2000})))""""
     """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
     """"info":"(NONE|({additional_info}[^",]{1,2000}))""""
     """"operation":"({activity}[^"]{1,2000})""""
     """"status":"({outcome}[^"]{1,2000})"""",
     """"sourceName":"({app}[^"]{1,2000})""""
     """"name":"({event_name}[^"]{1,2000}?)\s{0,100}",""""
  ]


}
```
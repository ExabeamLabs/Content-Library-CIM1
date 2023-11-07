#### Parser Content
```Java
{
Name = firemon-auth-successful
 Vendor = FireMon
 Product = FireMon
 Lms = Direct
 DataType = "authentication-successful"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
 Conditions = [ """Login Success """, """"username":"""", """ [FireMon] """ ]
 Fields = [
   """\d{1,2}:\d{1,2}:\d{1,2} ({host}[\w\-\.]{1,2000})"""
   """Date:\s{0,100}({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,6})"""
   """Event Name:\s{0,100}({event_name}[^:]{1,2000}) User:\s{0,100}({user}[^:]{1,2000})\s\w+:"""
   """({activity}Login)"""
   """({outcome}Success)"""
   """"username":"\s{0,100}(({user}[^\@"]{1,2000})@({domain}[^"]{1,2000}))""""
   """"username":"\s{0,100}(({domain}[^"\\]{1,2000})\\{1,100})({user}[^"]{1,2000})""""
 ]


}
```
#### Parser Content
```Java
{
Name = extrahop-network-sec-1
  Vendor = Extrahop
  Product = Reveal(x)
  Lms = Direct
  DataType = "alert"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """categories""", """sec.""", """"extrahop"""", """"event":""", """title"""]
  Fields = [
     """"start_time":"({time}\w+ \d\d \d\d\d\d \d\d:\d\d:\d\d)""",
     """"detection_id":({alert_id}\d{1,2000})""",
     """"title":"({alert_name}[^"]{1,2000})""",
     """"categories":"({alert_type}[^"]{1,2000})""",
     """"risk_score":({alert_severity}\d{1,100})""",
     """"object":"({src_ip}[A-Fa-f\d.:]{1,2000})",[^,]{1,2000}?ipaddr""",
     """"hostname":"({src_host}[\w.-]{1,2000})""",
  ]


}
```
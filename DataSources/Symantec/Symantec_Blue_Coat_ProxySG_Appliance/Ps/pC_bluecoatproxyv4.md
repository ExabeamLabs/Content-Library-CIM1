#### Parser Content
```Java
{
Name = bluecoat-proxy-v4
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "epoch_sec"
  Conditions = [ """|^~|""", """Source=Logstash_ProxySGServer""" ]  
  Fields = [
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){39}({proxy_action}([^_|]{1,2000}_)?({action}[^|]{1,2000}))""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){45}"{0,20}(-|({additional_info}[^|"]{1,2000}))"{0,20}""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|)({bytes_in}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){3}({bytes_out}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){4}({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){6}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){7}({dest_port}\d{1,100})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){13}"{0,20}({host}[^|"]{1,2000})"{0,20}""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){24}"{0,20}(-|({mime}[^|"]{1,2000}))"{0,20}""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){25}(unknown|({method}[^|]{1,2000}))""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){26}({protocol}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){27}({result_code}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){43}(none|({category}[^|]{1,2000}))""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){55}({time}[^|.]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){82}({full_url}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){83}({web_domain}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){84}({uri_path}[^|]{1,2000})""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){86}(-|({uri_query}[^|]{1,2000}))""",
     """^[^|]{1,2000}?\|([^|]{1,2000}\|){23}(-|({user_agent}[^|]{1,2000}))"""
  ]


}
```
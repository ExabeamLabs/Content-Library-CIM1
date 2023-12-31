#### Parser Content
```Java
{
Name = cef-symantec-web-activity
  Conditions = [ """|Symantec|Symantec Secure Web Gateway""", """"device_time":""" ]

cef-symantec-web-activity = {
  Vendor = Symantec
  Product = Symantec Secure Web Gateway
  Lms = ArcSight
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Fields = [
    """"device_time":"({time}\d{1,100}\-\d{1,100}\-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}Z)""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\Wdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"sc-filter-result":"({action}[^"]{1,2000})"""",
    """"cs-uri-scheme":"({protocol}[^"]{1,2000})"""",
    """"src_ip":"({src_ip}[^"]{1,2000})"""",
    """"bytes_download":({bytes_in}\d{1,100})""",
    """"bytes_upload":({bytes_out}\d{1,100})""",
    """"http_status":({result_code}\d{1,100})""",
    """"url":\{.*?"path":"({uri_path}[^"]{1,2000})"""",
    """"url":\{.*?"method":"(?:unknown|({method}[^"]{1,2000}))"""",
    """"url":\{.*?"port":({dest_port}\d{1,100})""",
    """"url":\{.*?"host":"({web_domain}[^"]{1,2000})"""",
    """"product_name":"({product_name}[^"]{1,2000})"""",
  ]
  DupFields = [ "web_domain->full_url" 
}
```
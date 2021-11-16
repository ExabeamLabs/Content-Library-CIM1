#### Parser Content
```Java
{
Name = microsoft-dns-renew-jp-2
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """,DNS の更新は成功しました,""" ]

microsoft-dns-renew-jp = {
  Vendor = Microsoft
  Product = Windows
  Lms = Direct
  DataType = "dhcp"
  Fields = [ 
    """({time}\d\d/\d\d/\d\d,\d\d:\d\d:\d\d),""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100})[\+\-]\d{1,100}:\d{1,100}\s{1,100}({host}[\w\-.]{1,2000})\s{1,100}\[""",
    """({time}\d{1,100}\/\d{1,100}\/\d{1,100},\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})""",
    """<Identifier>({host}[^<]{1,2000})<\/Identifier>""",
    """,(DNS.*)?(更新|要求|成功|更新成功)([^,]{1,2000})?,({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}),({dest_host}[^,]{1,2000}),(|({mac_address}[^,]{1,2000}))?,"""
  ]
  DupFields = [ "dest_host->user" 
}
```
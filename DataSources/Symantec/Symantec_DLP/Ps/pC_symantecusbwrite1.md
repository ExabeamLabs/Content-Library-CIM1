#### Parser Content
```Java
{
Name = symantec-usb-write-1
  Vendor = Symantec
  Product = Symantec DLP
  Lms = Direct
  DataType = "usb-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """USB Transfer""", """Endpoint """ ]
  Fields = [
    """exabeam_host=({host}[^,\s]{1,2000})""",
    """exabeam_time=({time}\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+?)\s{1,100}\S+\s{0,100}(?:;|,)[^;,]{0,2000}(?:;|,)\s{0,100}({dest_host}[^;,]{1,2000}?)\s{0,100}(?:;|,)\s{0,100}({process_name}[^;,]{1,2000}?)\s{0,100}(?:;|,)[^;,]{0,2000}?(?:;|,)\s{0,100}({file_name}[^;,]{1,2000}?)\s{0,100}(;|,)\s{0,100}({device_type}Endpoint[^;,]{1,2000}?)\s{0,100}(?:;|,)([^;,]{0,2000}(?:;|,)){2}\s{0,100}(?:({domain}[^;,\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^;,\\\/]{0,2000}?)\s{0,100}(?:;|,)""",
    """>\w+ \d\d \d\d:\d\d:\d\d\s{1,100}({host}\S+?)\s{1,100}\S+\s{0,100}(?:;|,)\s{0,100}({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s{0,100}(?:;|,)\s{0,100}({process_name}[^;,]{1,2000}?)\s{0,100}(?:;|,)[^;,]{0,2000}?(?:;|,)\s{0,100}({file_name}[^;,]{1,2000}?)\s{0,100}(;|,)\s{0,100}({device_type}Endpoint[^;,]{1,2000}?)\s{0,100}(?:;|,)\s{0,100}({severity}[^;,]{1,2000}?)\s{0,100}(?:;|,)\s{0,100}[^;,]{0,2000}(?:;|,)\s{0,100}(?:({domain}[^;,\\\/]{1,2000}?)[\\\/]{1,2000})?({user}[^;,\\\/]{0,2000}?)\s{0,100}(?:;|,)"""
  ]


}
```
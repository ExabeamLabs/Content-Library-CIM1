#### Parser Content
```Java
{
Name = skyhigh-web-activity-denied
  Vendor = Skyhigh Security
  Product = Skyhigh Security Cloud
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """Logging-Client """, """DENIED""" ]
  Fields = [
  """({action}DENIED)"""
  """Logging-Client\s"[^"]{1,2000}","({user}[^"]{1,2000})","({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))","({method}[^"]{1,2000})""""
  """Logging-Client\s"(([^"]{1,2000})","){6}({url}[^"]{1,2000})""""
  """Logging-Client.{0,2000}?DENIED","{0,100

}
```
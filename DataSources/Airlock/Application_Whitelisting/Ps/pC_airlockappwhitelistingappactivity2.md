#### Parser Content
```Java
{
Name = airlock-appwhitelisting-app-activity-2
  Vendor = Airlock
  Product = Application Whitelisting
  Lms = Syslog
  DataType = "app-activity"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"event":"FileActivityMessage"""", """"username":"""", """"datetime":"""",  ]
  Fields = [
    """"datetime":"({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\w{2})"""",
    """"hostname":"({host}[\w\-\.]{1,2000})""",
    """"username":"(SYSTEM|LOCAL SERVICE|(({user_email}[^\@"]{1,2000}\@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000})))"""",
    """"path":"({file_parent}[^"]{1,2000})""",
    """filename":"({file_name}[^"]{1,2000}?(\.(\d{1,5}|({file_ext}[^\."]{1,2000})))?)""""
    """({event_name}FileActivityMessage)""",
    """"sha256":"({sha256}[^"]{1,2000})""""
    """"md5":"({md5}[^"]{1,2000})""",
    """"parentprocess":"({process_name}[^"]{1,2000})""""
  ]


}
```
#### Parser Content
```Java
{
Name = airlock-appwhitelisting-app-activity-3
  Vendor = Airlock
  Product = Application Whitelisting
  Lms = Syslog
  DataType = "app-activity"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = [ """"event":"ServerActivityMessage"""", """"user":"""", """"datetime":"""", """"task":"""" ]
  Fields = [
    """"datetime":"({time}\d\d\/\d\d\/\d\d\d\d\s\d\d:\d\d:\d\d\s\w{2})"""",
    """"user":"(SYSTEM|LOCAL SERVICE|(({user_email}[^\@"]{1,2000}\@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000})))"""",
    """({event_name}ServerActivityMessage)""",
    """"task":"({activity}[^"]{1,2000})""",
    """"description":"({additional_info}[^"]{1,2000})""""
  ]


}
```
#### Parser Content
```Java
{
Name = airwatch-admin-app-activity
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
  Conditions = [ """AirWatch""", """Event Timestamp:""", """Event:""", """Event Category: Device""" ]
  Fields = ${AirWatchParserTemplates.airwatch-app-activity.Fields}[
    """Timestamp: ({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,6})"""
  ]


airwatch-app-activity = {
    Vendor = VMware
    Product = AirWatch
    Lms = Splunk
    TimeFormat = "MMMM dd, yyyy HH:mm:ss"
    Fields = [
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """Timestamp: ({time}\w+\s\d{1,2},\s\d{4}\s(\d{2}:){2}\d{2})""",
      """Timestamp: ({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,6})""" 
      """Event Type:\s{0,100}({event_name}[^=]{1,2000}?)\s{0,100}User:""",
      """User:\s{0,100}((({domain}[^\\]{1,2000}?)\\+)?({user}[^:]{1,2000}?))\s{0,100}Event Source:"""
      """"Application=({app}[^;=]{1,2000});\w+="""
    ]
     DupFields = ["event_name->activity"
}
```
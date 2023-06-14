#### Parser Content
```Java
{
Name = json-o365-graph-audit-app-activity
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"destinationServiceName":"Office 365"""", """"dproc":"Graph Directory Audit logs"""", """"activityDisplayName":""" ]
  Fields = [
   """"activityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\dZ)"""",
   """"activityDisplayName":"({activity}[^"]{1,2000})""",
   """"userPrincipalName":"(({user_email}([A-Za-z0-9]{1,2000}[!#$%&'+-\/=?^_`~]){0,2000}[A-Za-z0-9]{1,2000}@[^\]\s"\\,\|]{1,2000}\.[^\]\s"\\,\|]{1,2000})|({user}[^"]{1,2000}))"""",
   """"category":"({category}[^"]{1,2000})""",
   """"destinationServiceName":"({app}[^"]{1,2000})""",
   """"result":"({result}[^"]{1,2000})""",
   """"resultReason":"({reason}[^"]{1,2000})""",
   """"value":"({user_agent}[^"]{1,2000})","key":"User-Agent"""",
   """"dproc":"({dproc}[^"]{1,2000})""",
   """"operationType":"({activity_type}[^"]{1,2000})"""",   
   """"loggedByService":"({service_name}[^"]{1,2000})""""
  ]
  DupFields = ["activity->event_name"]


}
```
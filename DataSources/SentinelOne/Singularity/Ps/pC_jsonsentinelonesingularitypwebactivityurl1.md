#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-web-activity-url-1
  Product = Singularity
  Vendor = SentinelOne
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Lms = Direct
  DataType = "web-activity"
  Conditions = [ """"dataSource.name\":\"SentinelOne\"""", """"event.category\":\"url\"""", """"i.scheme\":\"edr\"""" ]
  Fields = [
    """"timestamp\\{0,20}":\\{0,20}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)""",
    
    """"endpoint\.name\\{0,20}":\\{0,20}"({host}[^\\"]{1,2000})""",
    
    """"endpoint\.os\\{0,20}":\\{0,20}"({os}[^\\"]{1,2000})""",
    """"agent\.version\\{0,20}":\s*\\{0,20}"({user_agent}[^\\"]{1,2000})""",
    """"src\.process\.user\\{0,20}":\\{0,20}"((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))""",
    """"event\.url\.action\\{0,20}":\\{0,20}"({method}[^"\\]{1,2000})""",
    """"event\.id\\{0,20}":\\{0,20}"({event_code}[^"\\]{1,2000})""",	""""url\.address\\{0,20}":\\{0,20}"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]{1,2000})|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^"\\]{1,2000})?)\\{0,20}""""
    """"src\.process\.activeContentType":"({mime}[^"\\]{1,2000})"""
  ]
  DupFields = [ "host->dest_host"]


}
```
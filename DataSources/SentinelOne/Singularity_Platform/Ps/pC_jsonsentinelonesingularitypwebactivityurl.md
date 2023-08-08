#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-web-activity-url
  Product = Singularity Platform
  Vendor = SentinelOne
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Lms = Direct
  DataType = "web-activity"
  Conditions = [ """"dataSource.name":"SentinelOne"""", """"event.category":"url"""", """"i.scheme":"edr"""" ]
  Fields = [
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)"""
    """"endpoint\.name":"({host}[^"]{1,2000})"""
    """"endpoint\.os":"({os}[^"]{1,2000})"""
    """"agent\.version":\s*"+({user_agent}[^"]{1,2000})""""
    """"src\.process\.user":"*((NT AUTHORITY|({domain}[^\\"]{1,2000}))[\\\/]{1,2000})?(SYSTEM|NETWORK SERVICE|LOCAL SERVICE|({user}[^\\"]{1,2000}))""" 
    """"event\.id":"({event_code}[^"]{1,2000})""",
    """"event\.url\.action":"({method}[^"]{1,2000})""",
    """"url\.address":"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]{1,2000})|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^"]{1,2000})?)""""
    """"src\.process\.activeContentType":"({mime}[^"]+)"""",
    """"src.process.parent.image.path":"{1,20}\s{0,100}({parent_process}({parent_process_directory}[^@]+?)[\\\/]{0,2000}({parent_process_name}[^"\\\/]{1,2000}))""""
    """"src.process.image.path":"({process_path}({process_directory}(:?[\w:]{1,2000})?[^"]{0,2000}\\)({process_name}[^"]{1,2000}))""""
  ]
  DupFields = [ "host->dest_host"]


}
```
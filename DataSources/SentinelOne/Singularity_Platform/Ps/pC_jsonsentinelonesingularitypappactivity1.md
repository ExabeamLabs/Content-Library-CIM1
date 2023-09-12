#### Parser Content
```Java
{
Name = json-sentinelone-singularityp-app-activity-1
  Lms = Direct
  DataType = "app-activity"
  Conditions = [ """"dataSource.name":"SentinelOne"""", """"event.category":"indicators"""", """"event.type":"Behavioral Indicators"""",""""src.process.integrityLevel":"SYSTEM"""" ]
  Fields = ${SentinelOneParserTemplates.json-sentinelone-edr-events.Fields} [
    """({app}SentinelOne)"""
  ]
  DupFields = [ "host->dest_host" ]

json-sentinelone-edr-events = {
    Vendor = SentinelOne
    Product = "Singularity Platform"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """"timestamp\\{0,20}":\\{0,20}"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\\{0,20}"""",
      """"event\.type\\{0,20}":\\{0,20}"({event_name}[^"\\]{1,2000})""",
      """"endpoint\.name\\{0,20}":\\{0,20}"({host}[^"\\]{1,2000})""",
      """"task\.path\\{0,20}":\\{0,20}"({file_path}({file_dir}[^"]{0,2000}?)({file_name}[^\\"]{1,2000}?(\.({file_ext}[^\\."]{1,2000}?))?))\\{0,20}"""",
      """process\.name\\{0,20}":\\{0,20}"({process_name}[^"\\]{1,2000})""",
      """"endpoint\.os\\{0,20}":\\{0,20}"({os}[^"\\]{1,2000})""",
      """"endpoint\.type\\{0,20}":\\{0,20}"({host_type}[^"\\]{1,2000})"""
    
}
```
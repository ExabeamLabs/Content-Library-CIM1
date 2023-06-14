#### Parser Content
```Java
{
Name = json-box-file-download
  Vendor = Box
  Product = Box
  Lms = Syslog
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"eventType":"DOWNLOADED"""", """"trustReason":"Download to a managed device"""", """"sourceName":"Box"""", """"fileName":"""", """"fileType":"FILE"""" ]
  Fields = [
    """"createTimestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,3}Z)"""",
    """"fileName":"({file_name}[^"]{1,2000}?(\.({file_ext}[^"\.]{1,2000}))?)"""",
    """"filePath":"({file_path}[^"]{1,2000})"""",
    """"fileType":"({file_type}[^"]{1,2000})"""",
    """"mimeTypeByBytes":"({mime}[^"]{1,2000})"""",
    """"eventType":"({activity}[^"]{1,2000})"""",
    """"deviceUserName":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
    """"operatingSystemUser":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"fileSize":({bytes}\d{1,20}),""",
    """"destinationName":"({dest_host}[\w\-\.]{1,2000})"""",
    """"privateIpAddresses":\["({dest_ip}[a-fa-d\d:\.]{1,2000})%[^"]{1,2000}"""",
    """"publicIpAddress":"({src_ip}[a-fa-d\d:\.]{1,2000})"""",
    """"md5Checksum":"({md5}[^"]{1,2000})"""",
    """"sha256Checksum":"({sha256}[^"]{1,2000})"""",
    """"trustReason":"({event_name}[^"]{1,2000})"""",
    """"title":"({additional_info}[^"]{1,2000})"""",
    """"tabUrl":"({full_url}[^"]{1,2000})"""",
    """"deviceUid":"({device_id}[^"]{1,2000})""""
  ]
  DupFields = [ "activity->access_type", "file_path->file_parent", "dest_host->device_name"]


}
```
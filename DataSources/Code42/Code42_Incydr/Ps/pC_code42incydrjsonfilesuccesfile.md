#### Parser Content
```Java
{
Name = code42-incydr-json-file-succes-file
  Vendor = Code42
  Product = Code42 Incydr
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions= [ """"action":""", """"file":{""", """Code42""",""""source":{""",""""destination":{""" ]
  Fields = [
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
    """"action":"({event_name}[^"]{1,2000})"""",
    """"user":\s{0,100}\{"email":\s*"({user_email}([A-Za-z0-9]+[!#$%&'+-\/=?^_`~])*[A-Za-z0-9]+@[^\]\s"\\,\|]+\.[^\]\s"\\,\|]+)"""",
    """"file":\s{0,100}\{"name":"({file_name}[^"]{1,2000}?(\.({file_ext}[^"\.]{1,2000}))?)"""",
    """"file"[^\}]{1,2000}?"directory":"({file_dir}[^"]{1,2000})"""",
    """"file":\s{0,100}\{.{1,2000}?"originalDirectory":"({src_file_dir}[^"]{1,2000})""""
    """"file"[^\}]{1,2000}?"category":"({file_type}[^"]{1,2000})"""",
    """"file":\s{0,100}\{.{1,2000}?"originalName":"({src_file_name}[^"\.]{1,2000}(\.({src_file_ext}[^"]{1,2000}))?)"""",
    """"file"[^\}]{1,2000}?"sizeInBytes":(({bytes}\d{1,20}))""",
    """"source":[^\}]{1,2000}?"name":\s*"({src_host}[\w\-.]{1,2000})"""",
    """"source":\{.{1,2000}?"ip":"({src_ip}((([0-9a-fA-F.]{0,4}):{1,2}){1,7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({src_port}\d{1,10}))?"""",
    """"domain":"({domain}[^"]{1,2000})"""",
    """"busType":"({device_type}[^"]{1,2000})"""",
    """"mediaName":"({device_name}[^"]{1,2000})"""",
    """"serialNumber":"({removable_media_serial_number}[^"]{1,2000})"""",
    """"changeType":"(NONE|({operation}[^"]{1,2000}))"""",
    """"hash":\s{0,100}[^\}]{1,2000}?"md5":"({md5}[^"]{1,2000})"""",
    """"hash":\s{0,100}[^\}]{1,2000}?"sha256":"({sha256}[^"]{1,2000})"""",
    """"repositoryUri":"([^:]{1,2000}:)?({repository_name}[^"]{1,2000})"""",
    """"printerName":"({printer_name}[^"]{1,2000})""""
    """"printJobName":"({object}[^"]{1,2000})""""
    """"severity":"({alert_severity}[^"]{1,2000})"""",
    """"operatingSystem":"({os}[^"]{1,2000})"""
  ]


}
```
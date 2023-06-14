#### Parser Content
```Java
{
Name = s-duo-auth-json-2
  Vendor = Cisco
  Product = Duo Access Security
  Lms = Splunk
  DataType = "authentication-attempt"
  TimeFormat = "epoch_sec"
  Conditions = [ """"eventtype":"authentication"""",""""result""""]
  Fields = [
    """"timestamp":({time}\d{10})""",
    """"host":"{1,20}({host}[\w\-\.]{1,2000})"""",
    """"ip":"{1,20}(0.0.0.0|null|({src_ip}[a-fA-F:\.\d]{1,2000}))"""",
    """"result":"({outcome}[^"]{1,2000})"""",
    """"reason":"({failure_reason}[^"]{1,2000})"[^=]{1,2000}?"result":"(denied|fraud)"""",
    """"result":"(denied|fraud)"[^=]{1,2000}?"reason":"({failure_reason}[^"]{1,2000})"""",
    """"os":"({os}[^"]{1,2000})"""",
    """"os_version":"({os_version}[^"]{1,2000})"""",
    """"browser":"(Unknown|({browser}[^"]{1,2000}))"""",
    """"browser_version":"({browser_version}[^"]{1,2000})"""",
    """"email":"({user_email}[^@"]{1,2000}@[^"]{1,2000})"""",
    """"factor":"(?:n\/a|({auth_method}[^"]{1,2000}))"""",
    """"user":[^\}]{1,2000}?"name":"({user}[^"]{1,2000})""""
    """"new_enrollment"\s{0,100}:\s{0,100}({new_enrollment}true|false)""",
    """"application".{1,2000}?"name":\s{0,100}"({service_name}[^"]{1,2000})"""
    """"location":.{1,2000}?"country":\s{0,100}"({src_country}[^"]{1,2000})"""
  ]


}
```
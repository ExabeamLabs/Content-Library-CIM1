#### Parser Content
```Java
{
Name = cef-sophos-security-alert-10
  Conditions = [ """CEF:""", """"type":"Event::Endpoint::CoreCleanFailed"""" ]

cef-sophos-security-alert-1 {
  Vendor = Sophos
  Product = Sophos Endpoint Protection
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"when":"({time}\d\d\d\d\-\d\d\-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """"location":"({host}[\w\-.]{1,2000})"""",
    """"id":"({alert_id}[^"]{1,2000})""",
    """"severity":"({alert_severity}[^"]{1,2000})""",
    """"name":\s{0,100}"(n\/a|({alert_name}[^\:\"\']{1,2000}(\:\s{0,100}\'({target}[^\"\']{1,2000}))?\'))""",
    """"name":\s{0,100}"(n\/a|[^"]{0,2000}? at \'({additional_info}({malware_url}[^"\']{1,2000})))""",
    """"name":\s{0,100}"(n\/a|[^"]{0,2000}? at \'({additional_info}({process}[^']{1,2000}\\({process_name}[^']{1,2000}))))""",
    """"type":"({alert_name}Event::Endpoint::[^"]{1,2000})""",
    """"name":"({alert_name}[^"]{1,2000})""",
    """"threat":"?(null|({alert_name}[^",]{1,2000}))""",
    """"type":"({alert_type}Event::Endpoint::[^"]{1,2000})""",
    """"source":"(n\/a|({user_fullname}[^"\\\(\),]{1,2000}))"""",
    """"source":"(n\/a|({user_lastname}[^",\s]{1,2000}),\s{0,100}({user_firstname}[^,"\s]{1,2000}))""",
    """"source":"(n\/a|(([^\\\s"]{0,2000}\s{1,100}[^\\"]{0,2000}|({domain}[^\\"]{1,2000}))\\+)?({user}[^\\\s"]{1,2000}))"""",
    """"ip":"({src_ip}[A-Fa-f:\d.]{1,2000})""""
    """"source":"(n\/a|([\w\-.]{1,2000})\s{0,100}(\(({src_ip}[A-Fa-f:\d.]{1,2000})\))?)"""",
    """"description":"({additional_info}[^:"]{1,2000}:?([^"]{1,2000}? at '({malware_url}[^"]{1,2000})')?)"""",
    """"descriptor":"({process}[^"]{1,2000}\\({process_name}[^"]{1,2000}))"""",
  ]
  DupFields = ["host->src_host"
}
```
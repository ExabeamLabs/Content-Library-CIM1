#### Parser Content
```Java
{
Name = q-microsoft-asc-security-alert-4
  Product = Azure Security Center
  Conditions = [ """""category"":""AppServices_ScanSensitivePage"""", """"title"":""""", """"vendor"":""Microsoft"""", """"provider"":""ASC"""" ]

q-microsoft-security-events = {
    Vendor = Microsoft
    Product = Azure Security Center
    Lms = QRadar
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """"id"{1,20}:\s{0,100}"{1,20}({alert_id}[^"]{1,2000})"""",
      """"title"{1,20}:\s{0,100}"{1,20}({alert_name}[^"]{1,2000})"""",
      """"severity"{1,20}:\s{0,100}"{1,20}({alert_severity}[^"]{1,2000})"""",
      """"category"{1,20}:\s{0,100}"{1,20}({alert_type}[^"]{1,2000})"""",
      """"description"{1,20}:\s{0,100}"{1,20}(\\"{1,20})?({additional_info_1}[^"\]\}]{1,2000}?)\s{0,100}\\?"{1,20}[,\]\}]""",
      """"sourceMaterials"{1,20}:\["{1,20}({additional_info}[^"]{1,2000})"""",
      """"eventDateTime"{1,20}:\s{0,100}"{1,20}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
      """"accountName"{1,20}:\s{0,100}"{1,20}\s{0,100}(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
      """aadUserId[^}\]]{1,2000}?"{1,20}accountName"{1,20}:\s{0,100}"{1,20}\s{0,100}(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"\.]{1,2000}\.[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
      """"logonIp"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F:\d.]{1,2000})"""",
      """"sourceAddress"{1,20}:"{1,20}({src_ip}[a-fA-F:\d.]{1,2000})"""",
      """"destinationAddress"{1,20}:"{1,20}({dest_ip}[a-fA-F:\d.]{1,2000})"""",
      """"userPrincipalName"{1,20}:\s{0,100}"{1,20}(-|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))"""",
      """"userPrincipalName"{1,20}:\s{0,100}"{1,20}\s{0,100}({user_upn}[^"]{1,2000}?)"""",
      """"domainName"{1,20}:\s{0,100}"{1,20}\s{0,100}(-|({domain}[^"]{1,2000}))"""",
      """"netBiosName"{1,20}:\s{0,100}"{1,20}({src_host}[\w\-\.]{1,2000})""",
      """"hostStates"{1,20}:[^}\]]{1,2000}?privateIpAddress"{1,20}:\s{0,100}"{1,20}({src_ip}[a-fA-F:\d.]{1,2000})""",
      """"hostStates"{1,20}:[^}\]]{1,2000}?publicIpAddress"{1,20}:\s{0,100}"{1,20}({dest_ip}[a-fA-F:\d.]{1,2000})""",
      """"fileStates"{1,20}:[^]]{1,2000}?"{1,20}name"{1,20}:\s{0,100}"{1,20}({file_name}[^."]{1,2000}([\.\w]{1,100})?)"""",
      """"status"{1,20}:"{1,20}({outcome}[^"]{1,2000})"""",
      """"logonLocation"{1,20}:\s{0,100}"{1,20}({location}[^"]{1,2000})""""
    
}
```
#### Parser Content
```Java
{
Name = json-defender-atp-security-alert-7
    Conditions = [ """"category":""", """"InitialAccess"""", """"title":""", """"incidentId":""",  """"detectionSource":""", """"threatFamilyName":""" ]
  
json-microsoft-security-events-1 = {
     Vendor = Microsoft
     Product = Defender ATP
     DataType = "alert"
     Lms = Splunk
     TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSz"
     Fields = [
     """"alertId":\s{0,100}"({alert_id}[^"]{1,2000})"""",
     """"title":\s{0,100}"({alert_name}[^"]{1,2000})"""",
     """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
     """"category":\s{0,100}"({alert_type}[^"]{1,2000})"""",
     """"description":\s{0,100}"({additional_info}[^}\]]{1,2000}?)\s{0,100}"[,\]}]""",
     """"createdDateTime":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,7}Z)"""",
     """"firstActivity":\s{0,100}"({time}[^"]{1,2000})"""",
     """"accountName":\s{0,100}"(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
     """aadUserId[^}\]]{1,2000}?"accountName":\s{0,100}"(-|({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user_email}[^"@]{1,2000}@[^"]{1,2000})|({user}[^\s"]{1,2000}))"""",
     """"userPrincipalName":\s{0,100}"(-|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))"""",
     """"userPrincipalName":\s{0,100}"({user_upn}[^"]{1,2000}?)"""",
     """"domainName"{1,20}:\s{0,100}"{1,20}(-|({domain}[^",]{1,2000}))"""",
     """"domainName"{1,20}:\s{0,100}"{1,20}(-|({domain}[^",]{1,2000}))[^}\]]{1,2000}?userPrincipalName""",
     """"deviceDnsName":\s{0,100}"{1,20}({src_host}[\w.-]{1,2000})"""",
     """"status":\s{0,100}"({outcome}[^"]{1,2000})"""",
     """"threatFamilyName":\s{0,100}"({malware_category}[^"]{1,2000})"""",
     """"entityType":\s{0,100}"Process"[^\}]{1,2000}?"fileName":\s{0,100}"({process_name}[^"]{1,2000})"""",
     """"entityType":\s{0,100}"Process"[^\}]{1,2000}?"processId":\s{0,100}"({pid}[^"]{1,2000})"""",
     """"entityType":\s{0,100}"File"[^\}]{1,2000}?"fileName":\s{0,100}"({file_name}[^"]{1,2000}?(\.({file_ext}[^".]{1,2000}?)?))"""",
     """"entityType":\s{0,100}"File"[^\}]{1,2000}?"filePath":\s{0,100}"({file_path}[^"]{1,2000})"""",
     """"ipAddress":"({src_ip}[a-fA-F:\d.]{1,2000})"""
    
}
```
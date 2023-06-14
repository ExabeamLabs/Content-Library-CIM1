#### Parser Content
```Java
{
Name = json-azure-ad-security-alert-2
  Vendor = Microsoft
  Product = Azure AD Identity Protection
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"category":""", """"Exfiltration"""", """"title":""", """"detectionSource"""", """"serviceSource"""", """"microsoftDataLossPrevention"""", """"Graph Security Alerts"""", """"Azure"""" ]
  Fields = [
    """"id":\s{0,100}"({alert_id}[^"]{1,2000})"""",
    """"title":\s{0,100}"({alert_name}[^"]{1,2000})"""",
    """"severity":\s{0,100}"({alert_severity}[^"]{1,2000})"""",
    """"category":\s{0,100}"({alert_type}[^"]{1,2000})"""",
    """"description":\s{0,100}"({additional_info}[^"]{1,2000})"""",
    """"createdDateTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)"""",
    """"accountName":\s{0,100}"(({user_fullname}[^"\s]{1,2000}\s[^"]{1,2000})|({user}[^"]{1,2000}))"""",
    """"userPrincipalName":\s{0,100}"(-|({user_email}[^@"]{1,2000}@[^".]{1,2000}\.[^"]{1,2000})|(({user}[^\s"@]{1,2000})(@[^"]{1,2000})?))"""",
    """"domainName"{1,20}:\s{0,100}"{1,20}({domain}[^"]{1,2000})"""",
    """"userPrincipalName":\s{0,100}"({user_upn}[^"]{1,2000}?)"""",
    """"userAccount":\{[^\}]{1,2000}?displayName":"({user_fullname}[^\s"]{1,2000}\s[^"\(\s]{1,2000})\s\([^)"]{1,2000}\)"""",
    """"userSid":"({user_sid}[^"]{1,2000})""""
  ]


}
```
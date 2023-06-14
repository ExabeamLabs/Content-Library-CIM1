#### Parser Content
```Java
{
Name = json-o365-graph-identity-alert
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """"destinationServiceName":"Office 365"""", """"detectedDateTime":"""", """"dproc":"graph-identity-protection-risk-detection"""" ]
  Fields = [
    """"activityDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\dZ)"""",
   """"userPrincipalName":"(({user_email}([A-Za-z0-9]{1,2000}[!#$%&'+-\/=?^_`~]){0,2000}[A-Za-z0-9]{1,2000}@[^\]\s"\\,\|]{1,2000}\.[^\]\s"\\,\|]{1,2000})|({user}[^"]{1,2000}))"""",
    """"tokenIssuerType":"({token_issuer_type}[^"]{1,2000})""",
    """({alert_type}({alert_name}graph-identity-protection-risk-detection))""",
    """"riskLevel":"({alert_severity}[^"]{1,2000})""",
    """"activity":"({operation}[^"]{1,2000})""",
    """"destinationServiceName":"({app}Office 365)"""",
    """"userId":"({user_id}[^"]{1,2000})""",
    """"riskEventType":"({alert_name}[^"]{1,2000})""",
    """"id":"({alert_id}[^"]{1,2000})"""",
    """"riskState":"({action}[^"]{1,2000})""",
    """"riskDetail":"({additional_info}[^"]{1,2000})"""
  ]


}
```
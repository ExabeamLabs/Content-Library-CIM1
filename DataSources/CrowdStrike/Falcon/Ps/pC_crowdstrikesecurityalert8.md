#### Parser Content
```Java
{
Name = crowdstrike-security-alert-8
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Direct
  DataType = "alert"
  TimeFormat = "epoch_sec"
  Conditions = [ """"eventType":"IdentityProtectionEvent"""", """"Severity":""", """"FalconHostLink":"""", """"IncidentType":"""", """"destinationServiceName":"CrowdStrike"""" ]
  Fields = [
  """"eventCreationTime":({time}\d{13}),""",
  """"Severity":({alert_severity}\d{1,5}),""",
  """"IncidentType":"({alert_name}[^"]{1,2000})"""",
  """"eventType":"({alert_type}[^"]{1,2000})"""",
  """"UserName":"(({user_email}[^@]{1,2000}@[^\.]{1,2000}\.[^"]{1,2000})|(({domain}[^\\]{1,2000})\\{1,20})?({user}[^"]{1,2000}))""""
  """"SeverityName":"({alert_severity}[^"]{1,2000}?)""""
  """"FalconHostLink":"({falcon_host_link}[^"]{1,2000})""""
  """"Category":"({category}[^"]{1,2000})"""
  """"EndpointName":"(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({src_host}[\w\-\.]{1,2000}))"""
  ]


}
```
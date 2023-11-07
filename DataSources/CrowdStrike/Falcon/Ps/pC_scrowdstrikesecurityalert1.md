#### Parser Content
```Java
{
Name = s-crowdstrike-security-alert-1
  Vendor = CrowdStrike
  Product = Falcon
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """destinationServiceName =CrowdStrike""", """"DetectName":""", """dproc=endpoint-streaming-api""", """"eventType":"MobileDetectionSummaryEvent"""" ]
  Fields = [
    """"eventCreationTime":\s{0,100}({time}\d{1,100})""",
	""""ComputerName":\s{0,100}"({src_host}[\w\-\.]{1,2000})""",
	""""UserName":\s{0,100}"{0,100}(({user_email}[^\@<",]{1,2000}\@[^\.<",]{1,2000}\.[^<,"]{1,2000})|({user}[^<",]{1,2000}))"""
	""""DetectId":\s{0,100}"({alert_id}[^"]{1,2000})""",
	""""DetectName":\s{0,100}"({alert_type}[^"]{1,2000})""",
	""""DetectDescription":\s{0,100}"\s{0,100}({detect_description}[^"]{1,2000}?)\s{0,100}"""",
	""""Technique":"({alert_name}[^"]{1,2000})"""",
	""""Severity":\s{0,100}({alert_severity}[^",]{1,2000})""",
	""""FalconHostLink":\s{0,100}"({falcon_host_link}[^"]{1,2000})"""",
  ]


}
```
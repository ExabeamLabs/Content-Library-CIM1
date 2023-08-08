#### Parser Content
```Java
{
Name = genetec-physical-access
 Vendor = Genetec
 Product = Genetec Badge
 Lms = Splunk
 DataType = "physical-access"
 TimeFormat = "MM/dd/yyyy HH:mm:ss.SSSS a"
 Conditions = ["""AccessGranted""","""Genetec"""]
 Fields = [
  """({time}\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{1,2}:\d{1,2}\.\d{1,4}\s(AM|PM|pm|am));({outcome}[^;]{1,2000});[^;]{1,2000};({user_fullname}({user_lastname}[^\s]{1,2000})\s{1,2000}({user_firstname}[^\s]{1,2000}))\s{1,2000};""",
  """;({location_door}[^;]{1,2000})\s{1,2000};$"""
    ]
 DupFields = [ "outcome->event_name" ]


}
```
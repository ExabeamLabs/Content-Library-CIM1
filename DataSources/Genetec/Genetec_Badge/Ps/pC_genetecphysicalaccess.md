#### Parser Content
```Java
{
Name = genetec-physical-access
 Vendor = Genetec
 Product = Genetec Badge
 Lms = Splunk
 DataType = "physical-access"
 TimeFormat = "MM/dd/yyyy HH:mm:ss.SSSS a"
 Conditions = [""";AccessGranted;""","""Genetec;"""]
 Fields = [
  """({time}\d{1,2}\/\d{1,2}\/\d{4} \d{1,2}:\d{1,2}:\d{1,2}\.\d{1,4}\s((?i)am|pm));({outcome}[^;]{1,2000});([^;]{0,2000};){4}({location_door}[^;]{1,2000}?)\:?\s{0,20};""",
  """;AccessGranted\;([^\;]{0,2000}\;)\s{0,20}(|None|EMS|EVS|UNKNOWN|[^\;]{1,2000}\d{1,100}|(((?i)Dr|ER)\.?\s{0,20})?((({first_name}\S{1,200})\s{1,20}(((?i)Dr|ER)\.\s{1,2000})?({last_name}[^;\s]{1,2000}?))|({user_fullname}[^;]{1,2000}?)))\s{0,20};"""
    ]
 DupFields = [ "outcome->event_name" ]


}
```
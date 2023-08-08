#### Parser Content
```Java
{
Name = jumpcloud-app-login
  Vendor = Jumpcloud
  Product = Jumpcloud
  Lms = Splunk
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
  Conditions = [ """User """, """ logged in """, """, process name: """, """, time: """ ]
  Fields = [
    """time:\s{1,100}({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{1,7}Z)""",
    """User\s{1,100}(-|(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000}?)|({user}[^"\s]{1,200}?)|({user_fullname}[^~"]{1,200}?)))\s{1,100}({event_name}logged in)""",
    """process name:\s{1,100}(-|({process}[^,]{1,2000}?)),\s""",
  ]


}
```
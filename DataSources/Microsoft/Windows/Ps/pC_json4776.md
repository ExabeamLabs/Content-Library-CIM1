#### Parser Content
```Java
{
Name = json-4776
    Vendor = Microsoft
    Product = Windows
    Lms = Direct
    DataType = "windows-4776"
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = ["""4776""", """"PackageName":"""", """attempted to validate the credentials for an account"""]
    Fields = [
      """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,3})?Z)"""",
      """({event_name}The (computer|domain controller) attempted to validate the credentials for an account)""",
      """"EventTime":({time}\d{1,100})""",
      """"EventTime":\s{0,100}"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
      """"(Hostname|MachineName)":"({host}[^"]{0,2000})""",
      """"Computer"{1,20}:"{1,20}({dest_host}({host}[^"]{1,2000}))"""",
      """({event_code}4776)""",
      """"TargetUserName":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{0,2000}))""",
      """The ({login_type}computer|domain)(\s\w+)? attempted to validate the credentials""",
      """"(Hostname|MachineName)":"(?!(?:[A-Fa-f:\d.]{1,2000}))[^."]{0,2000}\.({domain}[^.]{0,2000})""",
      """"TargetUserName":"[^"@]{1,2000}(?:@({domain}[^"@\s]{1,2000})[^"]{0,2000})?""",
      """"Status":"({result_code}[^"]{0,2000})""",
      """"Workstation":"\\*({src_host}[^"]{1,2000})""",
    ]
  

}
```
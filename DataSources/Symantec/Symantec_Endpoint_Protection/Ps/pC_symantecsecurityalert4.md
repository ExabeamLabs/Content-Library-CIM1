#### Parser Content
```Java
{
Name = symantec-security-alert-4
  Vendor = Symantec
  Product = Symantec Endpoint Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """ SymantecServer: """, """"Event Description:""", """,Local Host IP: """, """,Intensive Protection Level: """ ]
  Fields = [
    """Begin:\s({time}\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2})""",
    """\d\d:\d\d:\d\d\s({host}[\w.\-]{1,2000})\s{1,100}SymantecServer:\s{0,100}({src_host}[^,]{1,2000})""",
    """"Event Description:\s{0,100}({alert_name}[^"]{1,2000})"""",
    """,\s{0,100}Event Type:\s{0,100}({alert_type}[^,]{1,2000})""",
    """,\s{0,100}User( Name)?:\s{0,100}(none|({user}[^,]{1,2000}))""",
    """,\s{0,100}Local Host MAC:\s{0,100}({local_host_mac}[^,]{1,2000})""",
    """,\s{0,100}Local Host IP:\s{0,100}(0.0.0.0|({local_host_ip}((([0-9a-fA-F.]{0,4}):{1,2}){1,7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4})))""",
    """,\s{0,100}Remote Host IP:\s{0,100}(0.0.0.0|({dest_ip}((([0-9a-fA-F.]{0,4}):{1,2}){1,7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4})))""",
    """,\s{0,100}Remote Host MAC:\s{0,100}({dest_mac}[^,]{1,2000})""",
    """,\s{0,100}Occurrences:\s{0,100}({occurrences}[^,]{1,2000})""",
    """,\s{0,100}Application:\s{0,100}({process}({directory}[^,]{0,2000}?[\\\/]{1,2000})({process_name}[^,\\\/]{1,2000})),""",
    """,\s{0,100}Location:\s{0,100}({location}[^,]{1,2000})""",
    """,\s{0,100}Domain( Name)?:\s{0,100}({domain}[^\s,]{1,2000})""",
    """,\s{0,100}Local Port:\s{0,100}(0|({src_port}\d{1,100}))""",
    """,\s{0,100}Remote Port:\s{0,100}(0|({dest_port}\d{1,100}))"""
  ]


}
```
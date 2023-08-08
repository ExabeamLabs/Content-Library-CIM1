#### Parser Content
```Java
{
Name = reveal-file-download
  Vendor = NextDLP
  DataType = "file-download"
  Conditions = [ """reveal""", """file downloaded""", """"tags":""", """cyberhygiene""", """"name":""", """"sensor_type": "AGENT_POLICY"""" ]
  Fields = ${QUSHRevealParserTemplates.json-qush-reveal.Fields} [
    """({activity}file downloaded)""",
    """"target_file_name":\s{0,100}\["({dest_file}[^"]{1,2000})""""
    """"target_file_path":\s{0,100}\["({dest_path}[^"]{1,2000})""""
  ]

json-qush-reveal = {
    Product = Reveal
    Lms = Direct
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
    Fields = [
      """"timestamp"{1,10}:\s{0,100}"{1,10}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)""""
      """"host":\s{0,100}\["({dest_host}[\w\-\.]{1,2000})"""
      """"agent_hostname":\s{0,100}"({host}[\w\-\.]{1,2000})""""
      """"description"{1,10}:\s{0,100}"{1,10}({additional_info}[^\n]{1,2000}?)\s{0,100}","""
      """"username"{1,10}:\s{0,100}"{1,10}(({user_fullname}[^\\\s"]{1,2000}\s[^"\\]{1,2000})|(({domain}[^"\s\\]{1,2000})\\{1,20})?({user}[^"\s]{1,2000}))","""
      """"user_name":\s{0,100}"(({user_fullname}({first_name}[^\s"]{1,2000})\s({last_name}[^\s"]{1,2000}))|({user}[^"\(]{1,2000}))"""
      """"account_name"{1,10}:\s{0,100}\["{1,10}([^,\]]{1,2000},\s{0,100}")?((({domain}[^\\",]{1,1000})\\{1,10})?({user}[^",]{1,2000}))"\]"""
      """"user_email":\s{0,100}"({user_email}[^\@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""""
      """"binary_path"{1,10}:\s{0,100}"{1,10}[\\]{0,100}({process}({process_directory}[^"]{1,2000}?)\\{1,20}({process_name}[^"\\]{1,2000}))""""
      """"file_name":\s{0,100}\["({file_path}({file_parent}\w:([^"]{1,2000})?[\\\/]))?({file_name}[^"\\\/]{1,2000}?(\.(\.\.|({file_ext}[^"\\\/\.]{1,2000}))))""""
      """"file_path":\s{0,100}\["[\\]{0,100}({file_path}[^"]{1,2000})""""
      """"created_by":"policy:[^"]{1,2000}?name=({event_name}[^"]{1,2000})""""
      """"tags":\s{0,100}\[[^\]]{0,2000}?"({tag}[^"\]]{1,2000})"\]"""
      """"name":\s{0,100}"\s{0,100}({event_name}[^"]{1,2000}?)\s{0,100}""""
      """"application_name":\s{0,100}\["({app}[^"]{1,2000})""""
      """"destination_ip":\s{0,100}\["({dest_ip}[a-fA-F\d:\.]{1,2000})"\]""",
      """"destination_port":\s{0,100}\["({dest_port}\d{1,5})"\]""",
      """"source_ip":\s{0,100}\["({src_ip}[a-fA-F\d:\.]{1,2000})"\]""",
      """"source_port":\s{0,100}\["({src_port}\d{1,5})"\]"""
      """"url":\s{0,100}\["({url}[^"\]]{1,2000})"(,|\])"""
   
}
```
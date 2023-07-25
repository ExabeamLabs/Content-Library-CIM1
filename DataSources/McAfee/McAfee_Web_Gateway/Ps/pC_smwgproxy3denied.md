#### Parser Content
```Java
{
Name = s-mwg-proxy-3-denied
    Vendor = McAfee
    Product = McAfee Web Gateway
    Lms = Splunk
    DataType = "web-activity"
    IsHVF = true
    TimeFormat = "dd/MMM/yyyy:HH:mm:ss Z"
    Conditions = [ """mwg: Acces Denied [""" ]
    Fields = [
      """exabeam_host=({host}[^\s]{1,2000})""",
      """\s{1,100}({host}[^\s]{1,2000})\s{1,100}mwg:""",
      """({failure_reason}Acces Denied)""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[({time}[^\]]{1,2000})\]""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}".*?"\s{1,100}"(?:|-|({user}[^"]{1,2000}))"""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}(".*?"\s{1,100}){2}({src_ip}[^\s]{1,2000})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}(".*?"\s{1,100}){2}[^\s]{1,2000}\s{1,100}({dest_ip}[^\s]{1,2000})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"(?:"|-"|({web_domain}[^\s"]{1,2000})")""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}({result_code}\d{1,100})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}({bytes_out}\d{1,100})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}({bytes_in}\d{1,100})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"({method}[^\s]{1,2000})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"\w+\s{1,100}(?:({protocol}\w+):\/+)?""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"\w+\s{1,100}(\w+:\/+)?[^\/:]{1,2000}:({dest_port}\d{1,100})""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"\w+\s{1,100}({full_url}\S+)""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"\w+\s{1,100}(\w+:\/+)?[^\/:]{1,2000}(:\d{1,100})?({uri_path}\/.*?)(\?|\s{1,100}[^\s]{1,2000}")""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}"\w+\s{1,100}(\w+:\/+)?[^\/:]{1,2000}(:\d{1,100})?\/[^?]{1,2000}({uri_query}\?.*?)\s{1,100}[^\s]{1,2000}"""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}("[^"]{0,2000}?"\s{1,100}){3}\d{1,100}\s{1,100}"(?:-|({category}[^,"]{1,2000}))"""
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}("[^"]{0,2000}?"\s{1,100}){3}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"(?:-|({action}[^"]{1,2000}))"""",
      """mwg:\s{1,100}Acces Denied\s{1,100}\[.+?\]\s{1,100}("[^"]{0,2000}?"\s{1,100}){2}([^\s]{1,2000}\s{1,100}){2}"[^"]{0,2000}?"\s{1,100}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\d{1,100}\s{1,100}){2}("[^"]{0,2000}?"\s{1,100}){3}\d{1,100}\s{1,100}"[^"]{0,2000}?"\s{1,100}(\w+\s{1,100}"[^"]{0,2000}?"\s{1,100}){3}("[^"]{0,2000}?"\s{1,100}){2}"(?:|-|({user_agent}[^"]{1,2000}?)\s{0,100})("|$)"""
    ]
  

}
```
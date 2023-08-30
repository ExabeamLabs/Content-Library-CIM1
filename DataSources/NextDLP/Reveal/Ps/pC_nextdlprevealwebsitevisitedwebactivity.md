#### Parser Content
```Java
{
Name = nextdlp-reveal-website-visited-web-activity
  Vendor = NextDLP
  Product = Reveal
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """reveal""", """"tags": ["""", """"sensor_type": """", """name": """", """website visited""" ]
  Fields = [
    """"timestamp"{1,10}:\s{0,100}"{1,10}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)""""
    """"agent_hostname":\s{0,100}"({host}[\w\-\.]{1,2000})""""
    """"description"{1,10}:\s{0,100}"{1,10}({additional_info}[^\n]{1,2000}?)\s{0,100}","""
    """"username"{1,10}:\s{0,100}"{1,10}(({user_fullname}[^\\\s"]{1,2000}\s[^"\\]{1,2000})|(({domain}[^"\s\\]{1,2000})\\{1,20})?({user}[^"\s]{1,2000}))","""
    """"user_name":\s{0,100}"(({user_fullname}({first_name}[^\s"]{1,2000})\s({last_name}[^\s"]{1,2000}))|({user}[^"\(]{1,2000}))"""
    """"account_name"{1,10}:\s{0,100}\["{1,10}([^,\]]{1,2000

}
```
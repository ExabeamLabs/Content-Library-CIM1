#### Parser Content
```Java
{
Name = cc-pulsesecure-failed-vpn-login-1
  DataType = "failed-vpn-login"
  Conditions = [ """"host":""", """"PulseSecure:"""", """Login failed.""", """Reason:""" ]
  Fields = ${JuniperParserTemplates.cef-pulsesecure-vpn-events.Fields} [
    """Reason:\s{1,100}({failure_reason}[^"]{1,2000})""""
  ]

cef-pulsesecure-vpn-events = {
  Vendor = Juniper Networks
  Product = Juniper Networks Pulse Secure
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """"host":"({host}[^"]{1,2000})"""",
    """"timestamp":"({time}\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
    """\- \[({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s{1,100}(?:Default Network|Root)::(({domain}[^\\\(]{1,2000})\\)?(System|({user}[^\(]{1,2000}))\(({realm}[^\)]{1,2000})?\)\[({resource}[^\]]{1,2000})?\]""",
    """\d\d\d\d\-\d\d\-\d\d \d\d:\d\d:\d\d\s{1,100}\-\s{1,100}({dest_host}[\w\-.]{1,2000})"""
  
}
```
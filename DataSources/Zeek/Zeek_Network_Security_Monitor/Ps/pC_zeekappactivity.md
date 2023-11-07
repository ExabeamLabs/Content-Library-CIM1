#### Parser Content
```Java
{
Name = zeek-app-activity
  DataType = "app-activity"
  Conditions = [ """"id.orig_h""", """"id.resp_h""", """"opcode":["""", """"_path":"ldap"""", """["unbind"]""" ]
  Fields = ${BroParserTemplates.zeek-ldap-events.Fields}[
    """"_path":"({app}[^"]{1,2000})""""
  ]

zeek-ldap-events = {
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Fields = [
    """"_system_name":"({host}[^"]{1,2000})""",
    """"ts":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,6}Z)""",
    """"id\.orig_h":"({src_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.orig_p":({src_port}\d{1,5})""",
    """"id\.resp_h":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"id\.resp_p":({dest_port}\d{1,5})""",
    """"proto":"({protocol}[^"]{1,2000})""",
    """"opcode":\["({activity}[^"]{1,2000})"""",
    """"uid":"({uid}[^"]{1,2000})"""",
    """"result":\["({outcome}[^"]{1,2000})""""
  
}
```
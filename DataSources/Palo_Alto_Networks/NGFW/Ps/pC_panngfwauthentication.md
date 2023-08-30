#### Parser Content
```Java
{
Name = pan-ngfw-authentication
  DataType = "authentication-successful"
  Conditions = [ """"LogType":"AUTH"""", """"AuthEvent":""", """"AuthenticatedUserName":""" ]
  Fields = ${PaloAltoParserTemplates.paloalto-vpn.Fields}[
    """"AuthEvent":"({event_name}[^"]{1,2000})"""",
    """"AuthenticationDescription":"(\s|({additional_info}[^"]{1,2000}))"""",
    """"AuthenticatedUserName":"({user}[^"]{1,2000})"""",
    """"AuthenticatedUserDomain":"({domain}[^"]{1,2000})"""",
    """"AuthenticationProtocol":"({auth_type}[^"]{1,2000})""""
  ]

paloalto-vpn = {
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,9}Z)""",
    """"host":"({host}[^"]{1,2000})"""",
    """"DeviceName":"({host}[^"\s]{1,2000})"""",
    """"PrivateIPv(4|6)":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"PublicIPv(4|6)":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """"Source(Address|IP)":"({src_ip}[a-fA-F\d:.]{1,2000})""",
    """"DestinationAddress":"({dest_ip}[a-fA-F\d:.]{1,2000})""",
    """"(Source)?User(Name)?":"((na|NA|({domain}[^"\\]{1,2000}))\\{1,20})?(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|(pre-logon|({user_fullname}([^\s"]{1,2000})\s([^"]{1,2000}?))|({user}[^"]{1,2000}?)))\\?"""", 
    """"SourcePort":({src_port}\d{1,100})""",
    """"DestinationPort":({dest_port}\d{1,100})""",
    """"Protocol":"({protocol}[^"]{1,2000})"""",
    """"LogType":"({log_type}[^"]{1,2000})"""",
    """"AuthMethod":"({auth_method}[^"]{1,2000})"""",
    """"EventIDValue":"({event_name}[^"]{1,2000})""""
  
}
```
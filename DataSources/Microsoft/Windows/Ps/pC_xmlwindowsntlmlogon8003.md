#### Parser Content
```Java
{
Name = xml-windows-ntlm-logon-8003
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  DataType = "ntlm-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>8003<""", """security policy Network Security:""", """: Restrict NTLM:""", """<Channel>Microsoft-Windows-NTLM/Operational<""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\d\d\d\d\d\d\dZ)"""
    """<Computer>({host}[^<]{1,2000}?)<\/Computer>"""
    """Security UserID='({user_sid}[^'\/>]{1,2000})"""
    """({event_code}8003)"""
    """<EventData><Data Name ='UserName'>({user}[^<>]{1,2000})<\/Data>"""
    """<Data Name ='DomainName'>({domain}[^<]{1,2000})<"""
    """({event_name}NTLM server blocked in the domain audit)"""
    """<Message>({additional_info}[^<]{1,2000})<"""
    """<Data Name ='Workstation'>(({src_ip}(((\d{1,3}\.){1,3}\d{1,3})|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:.]{1,2000})))|(?:(?!NULL)(Unknown|({src_host}[^\s.]{1,2000}))(\.[^\s]{1,2000})?))<\/Data>"""
    """<Data Name ='LogonType'>({logon_type}\d{1,100})<\/Data>"""
    """<Data Name ='ProcessName'>({process}({process_directory}[^<\/]{1,2000}?)\\{1,20}({process_name}[^<\\]{1,2000}))<"""
   ]


}
```
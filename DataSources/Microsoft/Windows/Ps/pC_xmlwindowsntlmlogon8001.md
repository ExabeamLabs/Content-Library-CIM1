#### Parser Content
```Java
{
Name = xml-windows-ntlm-logon-8001
  Vendor = Microsoft
  Product = Windows
  Lms = Syslog
  DataType = "ntlm-logon"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSZ"
  Conditions = [ """<EventID>8001<""", """<Message>NTLM client blocked audit: Audit outgoing NTLM authentication traffic that would be blocked""", """<Channel>Microsoft-Windows-NTLM/Operational<""" ]
  Fields = [
    """SystemTime='({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d{1,10}Z)"""
    """<Computer>({host}[^<]{1,2000}?)<\/Computer>"""
    """Security UserID='({user_sid}[^'\/>]{1,2000})"""
    """({event_code}8001)"""
    """<Data Name ='ClientUserName'>(\((?i)NULL\)|({user}[^<>]{1,2000}))<\/Data>"""
    """<Data Name ='ClientDomainName'>(\((?i)NULL\)|({domain}[^<]{1,2000}))<"""
    """({event_name}NTLM client blocked)"""
    """<Message>({additional_info}[^<]{1,2000})<"""
    """<Data Name ='Workstation'>(({src_ip}(((\d{1,3}\.){1,3}\d{1,3})|([A-Fa-f0-9]{0,2000}:[A-Fa-f0-9:.]{1,2000})))|(?:(?!NULL)(Unknown|({src_host}[^\s.]{1,2000}))(\.[^\s]{1,2000})?))<\/Data>"""
    """<Data Name ='LogonType'>({logon_type}\d{1,100})<\/Data>"""
    """<Data Name ='ProcessName'>({process}({process_directory}[^<\/]{1,2000}?)\\{1,20}({process_name}[^<\\]{1,2000}))<"""
   ]


}
```
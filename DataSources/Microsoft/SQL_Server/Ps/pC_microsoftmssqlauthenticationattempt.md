#### Parser Content
```Java
{
Name = microsoft-mssql-authentication-attempt
 Vendor = Microsoft
 Product = SQL Server
 Lms = Direct
 DataType = "authentication-attempt"
 TimeFormat = "yyyy-MM-dd HH:mm:ss.SS"
 Conditions = [ """Logon """, """ [CLIENT: """, """ Login """, """ for user '""" ]
 Fields = [
   """({time}\d{4}-\d{1,2}-\d{1,2} \d{1,2}:\d{1,2}:\d{1,2}\.\d{1,2})\s{1,100}Logon"""
   """({activity}Logon)"""
   """Login\s{1,100}({outcome}[^\s]{1,2000})"""
   """Reason:\s({failure_reason}[^\[]{1,2000})\s\["""
   """for user '(((NT \w+|({domain}[^\\']{1,2000}))\\{1,100})?(ANONYMOUS LOGON|({user}[^']{1,2000})))"""
   """\[CLIENT:\s({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))\]"""
   """Logon\s{1,100}({event_name}[^']{1,2000}?)\s{0,100}'"""
 ]


}
```
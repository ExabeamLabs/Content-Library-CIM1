#### Parser Content
```Java
{
Name = unix-account-switch-1
  DataType = "unix-account-switch"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"type":"USER_START"""", """res\=success""", """PAM:session_open""", """Cloud Apps Security|""", """|audit-event|""" ]

unix-template = {
    Vendor = Unix
    Product = Unix Auditd
    Lms = Direct
    TimeFormat = epoch
    Fields = [
      """\Wrt=({time}\d{1,100})""",
      """\Wdvc=({host}[^\s]{1,2000})""",
      """\Wdvchost=({host}[^\s]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){4}({additional_info}[^\|]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){5}({event_code}[^\|]{1,2000})""",
      """CEF:([^\|]{0,2000}\|){6}({alert_severity}[^\|]{1,2000})""",
      """\WeventId=({alert_id}\d{1,100})""",
      """\Wsuser=({user}[^\s]{1,2000})""",
      """\Wdhost=({dest_host}[\w\-.]{1,2000})""",
    
}
```
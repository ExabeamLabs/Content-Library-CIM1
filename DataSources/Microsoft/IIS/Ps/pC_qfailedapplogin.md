#### Parser Content
```Java
{
Name = q-failed-app-login
  Vendor = Microsoft
  Product = IIS
  Lms = QRadar
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'\ttime='HH:mm:ss"
  Conditions = [ "AgentDevice=MSIIS", "sc-status=" ]
  Fields = [
    """date=({time}\d\d\d\d\-\d\d\-\d\d\s{0,100}time\=\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """SourceIp=({host}\S+)""",
    """s-ip=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """c-ip=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """cs-username=(({domain}[^\\\/\s]{1,2000})[\/\\]{1,20})?(-|({user}[^\\\/\s]{1,2000}))\s""",
    """cs\(User-Agent\)=({user_agent}.+?)\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
    """sc-bytes=({bytes_out}\d{1,100})""",
    """cs-bytes=({bytes_in}\d{1,100})""",
    """sc-status=({result_code}\d{1,3})\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
    """s-port=({protocol}.+?)\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
  ]


}
```
#### Parser Content
```Java
{
Name = cef-trendmicro-security-alert
  Lms = ArcSight
  Conditions = [ """|Trend Micro|Deep Security Manager|""","cat=" ]

trendmicro-security-alert = {
  Vendor = Trend Micro
  Product = OfficeScan
  DataType = "alert"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_endTime=({time}\d{1,100})""",
    """exabeam_EventTime=({eventtime}\d{1,100})""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-]\d\d:\d\d)\s\S+""",
    """\Wcat=({threat_category}.+?)\s{0,100}(\w+=|$)""",
    """\Wname=({alert_name}.+?)\s{0,100}(\w+=|$)""",
    """\Wsev=({alert_severity}\d{1,100})""",
    """\d\d:\d\d:\d\d\S+\s({host}[\w\-\.]{1,2000})""",
    """\Wdvchost=({host}.+?)\s{0,100}(\w+=|$)""",
    """\WfilePath=({malware_url}.+?)\s{0,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[a-fA-F\d:\.]{1,2000})\s{0,100}(\w+=|$)""",
    """target=(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))|({dest_host}[\w\-\.]{1,2000}))\s{0,100}(\w+=|$)"""
	]
  DupFields = [ "threat_category->alert_type", "host->src_host" 
}
```
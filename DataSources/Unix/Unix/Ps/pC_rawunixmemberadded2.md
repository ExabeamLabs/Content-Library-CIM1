#### Parser Content
```Java
{
Name = raw-unix-member-added-2
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "unix-member-added"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ "to group", "add", "usermod", """]:""" ]
  Fields = [
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d[\+\-][^\s]{1,2000})""",
    """(T|\s)\d\d:\d\d:\d\d(\.?\S+)? ({host}[\w.\-]{1,2000})(\s\S+)?\susermod\[""",
    """add \'({account_name}[^']{1,2000})\' to group \'({group_name}[^']{1,2000})\'""",
  ]
  DupFields=["host->dest_host"]


}
```
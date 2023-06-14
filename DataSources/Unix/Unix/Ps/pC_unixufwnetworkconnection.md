#### Parser Content
```Java
{
Name = unix-ufw-network-connection
  Vendor = Unix
  Product = Unix
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """UFW""", """IN=""", """DST=""", """LEN=""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s{1,100}({log_type}[^:]{1,2000}):\s{1,100}""",
    """IN=({src_interface}[^=]{1,2000}?)\s+\w+=""",
    """OUT=({dest_interface}[^=]{1,2000}?)\s+\w+=""",
    """MAC=({src_mac}([a-fA-F\d]{2}[-:]){5}[a-fA-F\d]{2})""",
    """SPT=({src_port}\d{1,5})""",
    """DPT=({dest_port}\d{1,5})""",
    """SRC=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """DST=({dest_ip}[A-Fa-f:\d.]{1,2000})""",
    """LEN=({bytes}\d{1,2000})""",
    """PROTO=({protocol}\d{1,2000})""",
    """\[UFW ({action}[^\]]{1,2000})\]"""
  ]


}
```
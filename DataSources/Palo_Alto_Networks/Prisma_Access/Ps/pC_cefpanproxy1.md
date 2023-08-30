#### Parser Content
```Java
{
Name = cef-pan-proxy-1
  Vendor = Palo Alto Networks
  Product = Prisma Access
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|Palo Alto Networks|LF|""", """|THREAT|url|""" ]
  Fields = [
    """\srt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s""",
    """\sdvchost=({host}[\w\-\.]{1,2000})""",
    """({log_type}THREAT)""",
    """\sact=({action}[^\s]{1,2000})""",
    """\sproto=({protocol}[^\s]{1,2000})""",
    """\ssrc=({src_ip}[^\s]{1,2000})""",
    """\ssuser=(|({user_email}[^@\s=]{1,2000}@[^\s=\.]{1,2000}\.[^\s=]{1,2000})|(({domain}[^\s=\\]{1,2000})[\\]{1,20})?({user}[^\s=]{1,2000}?))\s\w+=""",
    """\sdst=({dest_ip}[A-Fa-f\d:\.]{1,2000})\s{1,100}\w+=""",
    """\sdpt=({dest_port}\d{1,5})""",
    """\sspt=({src_port}\d{1,5})""",
    """\scs2=({category}[^=]{1,2000}?)\scs2Label=URLCategory""",
    """\srequestContext=(|({mime}[^=]{1,2000}))\s{1,100}\w+=""",
    """\srequest="?({full_url}(\w+\\{0,20}:\/{1,20})?({web_domain}[^\/:"\s]{1,2000})?({uri_path}\/[^\?\s"]{0,2000})?({uri_query}\?[^\s"]{1,2000})?)"?\s\w+=""",
    """\sflexString2=({direction}[^=]{1,2000}?)\s\w+="""
  ]


}
```
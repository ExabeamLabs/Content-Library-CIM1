#### Parser Content
```Java
{
Name = cef-pan-dns-query
  Vendor = Palo Alto Networks
  Product = Prisma Access
  Lms = Direct
  DataType = "dns-query"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """CEF:""", """|palo alto networks|LF|""", """|DNS|realtime_dns_query|""" ]
  Fields = [
    """\srt=({time}\w{3}\s\d\d\s\d\d\d\d\s\d\d:\d\d:\d\d)\s""",
    """\sPanOSDNSResolverIP=({dest_ip}[a-fA-F\d:\.]{1,2000})"""
  ]


}
```
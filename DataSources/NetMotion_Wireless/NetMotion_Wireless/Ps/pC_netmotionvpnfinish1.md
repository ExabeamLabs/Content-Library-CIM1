#### Parser Content
```Java
{
Name = netmotion-vpn-finish-1
  DataType = "vpn-end"
  Conditions = [ """MobilityAnalytics""", """ m_pid="""", """ m_user="""", """ prot="""", """ plat="""", """event="Finish"""" ]

netmotion-vpn = {
  Vendor = NetMotion Wireless
  Product = NetMotion Wireless
  Lms = Direct
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
     """\ssrv_name="{0,20}({host}[^\s"]{1,2000})""",
     """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)""",
     """\splat="{0,20}({os}[^\s"]{1,2000})""",
     """\sd_name="{0,20}({dest_host}[^\s"]{0,2000})""",
     """\sdest_ip="{0,20}({dest_ip}[A-Fa-f:\d.]{1,2000})""",
     """\sdest_port="{0,20}({dest_port}\d{1,100})""",
     """if_ip="{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """\svip="{0,20}({src_translated_ip}[A-Fa-f:\d.]{1,2000})""",
     """\ssrc_ip="{0,20}({src_ip}[A-Fa-f:\d.]{1,2000})""",
     """\ssrc_port="{0,20}({src_port}\d{1,100})""",
     """\sm_user="{0,20}(\[None\\*\]|({domain}[^\\"]{1,2000}?)\\+({user}[^\s"]{1,2000}))"""",
     """prot="{0,20}({protocol}[^"=]{1,2000})""",
     """event="{0,20}({event_name}[^"]{1,2000})"""
  
}
```
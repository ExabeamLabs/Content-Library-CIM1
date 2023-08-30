#### Parser Content
```Java
{
Name = cef-paloalto-vpn-login
 DataType = "vpn-login"
 Conditions = [ """CEF:""", """|Palo Alto Networks|PAN-OS|""", """|GLOBALPROTECT|""", """msg=login""" ]

cef-paloalto-vpn-event = {
  Vendor = Palo Alto Networks
  Product = GlobalProtect
  Lms = Splunk
  TimeFormat = "epoch"
  Fields = [
      """\srt=({time}\d{1,100})""",
      """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
      """\sdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """\ssuser=(({domain}[^\\=]{1,2000}?)\\{1,20})?({user}[^\s=]{1,2000})\s{1,100}\w+=""",
      """\sdvchost=({host}[\w\-.]{1,2000}?)\s{1,100}\w+=""",
      """\scs2=({outcome}[^=]{1,2000})\s{1,100}\w+=""",
      """\smsg=({event_name}[^=]{1,2000}?)\s{1,100}\w+=""",
      """cs6=({os}[^=]{1,2000}?)\s{1,100}\w+=""",
      """sourceGeoCountryCode=({src_country}[^=]{1,2000}?)\s{1,100}\w+=""",
      """({app}GLOBALPROTECT)"""
    
}
```
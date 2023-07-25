#### Parser Content
```Java
{
Name = cef-netskope-web-policy-1
  Conditions = [ """"alert_type":"policy"""", """"action":"block"""", """"traffic_type":"CloudApp"""" ]

cef-netskope-web = {
  Vendor = Netskope
  Product = Netskope Security Cloud
  Lms = Direct
  TimeFormat = "epoch_sec"
  DataType = "web-activity"
  Fields = [
    """"timestamp":({time}\d{1,100})""",
    """"hostname":"({src_host}[^"]{1,2000})""",
    """"userip":"({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """"appcategory":"({category}[^"]{1,2000})""",
    """"other_categories":\[({categories}[^\]]{1,2000}?)\]"""
    """"action":"({action}[^"]{1,2000})""",
    """"page":"({full_url}(\w+:\/\/)?(({dest_ip}[A-Fa-f.:\d]{1,2000})|({web_domain}[^\/]{1,2000}?))({uri_path}\/[^\?]{0,2000}?)?({uri_query}\?[^"]{1,2000})?)"""",
    """"policy":"({additional_info}[^"]{1,2000})""",
    """"page":"(\w+:\/\/)?({web_domain}[^\\\/"]{1,2000})""",
    """"user":"\s{0,100}({user_email}[^\s"@]{1,2000}?@[^\s"]{1,2000}\.[^\s"]{1,2000})"""",
    """"dstip":"({dest_ip}[A-Fa-f.:\d]{1,2000})""",
    """"browser":"(unknown|({browser}[^"]{1,2000}))""",
    """"src_location":"({src_location}[^"]{1,2000})""",
    """"src_country":"({src_country}[^"]{1,2000})""",
    """"os":"({os}[^"]{1,2000})""",
    """"referer":"({referrer}[^"]{1,2000})"""
    """"url":"(\w+\\*:\/+)?(((\d{1,100}\.){3}\d{1,100}[^\s"]{1,2000})|(www\.)?[^"\/]{0,2000}?({top_domain}[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}\.[0-9A-Za-z]{2,3}|[0-9A-Za-z]{2,255}\.[0-9A-Za-z]{2,3}))("|\/|\?)"""
    """"url":"([^"\/]{0,2000}?)({top_domain}[^.\s\/:]{1,2000}(?=(?:\.(?:com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za))+))("|\/)""",
  
}
```
#### Parser Content
```Java
{
Name = leef-paloalto-firewall-allow
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Direct
  DataType = "network-connection"
  IsHVF = true
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = ["""LEEF:""","""|Palo Alto Networks|PAN-OS Syslog Integration|""","""|allow|"""]
  Fields = [
    """\s({host}[\w\.-]{1,2000})\s{1,100}LEEF:""",
    """ReceiveTime=({time}\d\d\d\d\/\d\d\/\d\d\s\d\d:\d\d:\d\d)""",
    """\|devTime=({time}\w{3}\s{1,100}\d{1,100} \d\d\d\d \d\d:\d\d:\d\d)""",
    """\|Type=({log_type}\w+)\|""",
    """\|Subtype=({subtype}\w+)\|""",
    """\|src=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|dst=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\|""",
    """\|srcPostNAT=(0\.0\.0\.0|({src_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|dstPostNAT=(0\.0\.0\.0|({dest_translated_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))\|""",
    """\|RuleName=({rule}[^\|].*?)\|""",
    """\|usrName=(|((({domain}[^\|\\]{1,2000})\\)?({user}[^\|\\]{1,2000})))\|""",
    """\|SourceUser=(|((({src_domain}[^\|\\]{1,2000})\\)?({src_user}[^\|\\]{1,2000})))\|""",
    """\|DestinationUser=(|((({dest_domain}[^\|\\]{1,2000})\\)?({dest_user}[^\|\\]{1,2000})))\|""",
    """\|Application=({network_app}[^\|].*?)\|""",
    """\|SourceZone=({src_network_zone}[^\|].*?)\|""",
    """\|DestinationZone=({dest_network_zone}[^\|].*?)\|""",
    """\|LogForwardingProfile=({profile}[^\|].*?)\|""",
    """\|srcPort=(0|({src_port}\d{1,100}))\|""",
    """\|dstPort=(0|({dest_port}\d{1,100}))\|""",
    """\|srcPostNATPort=(0|({src_translated_port}\d{1,100}))\|""",
    """\|dstPostNATPort=(0|({dest_translated_port}\d{1,100}))\|""",
    """\|proto=({protocol}.*?)\|""",
    """\|totalBytes=({bytes}[\d.]{1,2000})\|""",
    """\|srcBytes=({bytes_out}[\d.]{1,2000})\|""",
    """\|dstBytes=({bytes_in}[\d.]{1,2000})\|""",
    """\|Miscellaneous="(|({miscellaneous}.+?))("|\s{0,100}$)""",
    """\|URLCategory=({category}.*?)\|""",
    """\|Severity=({severity}informational)\|""",
    """\|Direction=({direction}[\w-]{1,2000})\|""",
    """\|sequence=({sequence}\d{1,100})\|""",
    """\|SessionEndReason=({outcome}.*?)\|""",
    """\|action=({action}\w+)\|""",
    """\|SourceLocation=({src_location}[^\|]{1,2000})\|""",
  ]
}
```
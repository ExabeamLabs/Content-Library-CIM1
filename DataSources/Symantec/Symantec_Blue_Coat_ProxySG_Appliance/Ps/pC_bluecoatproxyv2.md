#### Parser Content
```Java
{
Name = bluecoat-proxy-v2
  Vendor = Symantec
  Product = Symantec Blue Coat ProxySG Appliance
  Lms = Direct
  DataType = "web-activity"
  IsHVF = true
  TimeFormat = "dd/MM/yyyy:HH:mm:ss z"
  Conditions = [ """filter-result=""", """cs-host=""" ]
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w.-]{1,2000})""",
    """\tcs-userdn=(?:-|(({domain}[^\\\t]{1,2000})\\)?({user}[^\s\t]{1,2000}))""",
    """\Ws-ip="?(-|({host}[^"|\s]{1,2000}))("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Ws-computername="?(-|({host}[^"|\s]))("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """"@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """"timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)"""",
    """date="?({time}\d\d\d\d-\d\d-\d\d"?(,|\t|\s)time="?\d\d:\d\d:\d\d)""",
    """\Wdevicetime=\[({time}\d{1,100}\/\d{1,100}\/\d{1,100}:\s{0,100}\d{1,100}:\d{1,100}:\d{1,100} [^\]]{1,2000})""", 
    """date="({time}\d\d\/\d\d\/\d\d\d\d:\s\d\d:\d\d:\d\d[^"]{1,2000})"""",
    """\W(c-ip|src)="?(-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\tr-ip=(-|({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wsrcport=(-|({src_port}\d{1,100}))""",
    """\Wdst=(-|({external_dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))""",
    """\Wdstport=(?:-|({dest_port}\d{1,100}))""",
    """\W(cs-username|username)="?(-|({user}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Ws-action="?(-|({proxy_action}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc|cs)-status="?(-|({result_code}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-method="?((?i)(unknown)|-|({method}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc|rs)-bytes="?(-|({bytes_out}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-bytes="?(-|({bytes_in}\d{1,100}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-scheme="?(-|({protocol}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-host="?(-|({web_domain}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri="?(-|({full_url}[^"|\s]{1,2000}))\s{0,100}(?:"|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-path="?(\/|-|({uri_path}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-query="?(-|({uri_query}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-uri-extension="?(-|({mime}[^;"|\s]{1,2000}))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wrs\(\s?Content\-Type\)="?(-|({mime}[^;"|\s]{1,2000}))\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs\(User-Agent\)="?(-|({user_agent}[^"|=]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc-)?filter-result="?(-|({action}[^"|\s]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\W(sc-)?filter-category="?((?i)none|-|({category}[^"|]{1,2000}))\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-categories="?((?i)none|-|({category}[^"|\s]{1,2000}))"?\s{0,100}("|\||$|\t|;|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs-categories="?((?i)none|-|({categories}[^"|\s]{1,2000}))"?\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wcs\(Referer\)"?=("?-"?|"?({referrer}[^"\|\t\s]{1,2000}?)"?)\s{0,100}("|\||$|\t|\s{1,100}[\w\-\(\)]{1,2000}=)""",
    """\Wreference_id="{0,10}(-|({reference_id}[^"]{1,2000}))"{0,10}"""
  ]
  DupFields = [ "external_dest_ip->dest_ip" ]


}
```
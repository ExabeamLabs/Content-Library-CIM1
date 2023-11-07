#### Parser Content
```Java
{
Name = tessian-dlp-email-alert-out
  Conditions = [ """.tessian-platform.""", """"recipients":{""", """"transmitter":"""", """"from":"""", """"to":[""", """::outbound-""" ]
  Fields = ${TessianParserTemplates.tessian-dlp-email-alert.Fields} [
    """::({direction}outbound)\-"""
  ]

tessian-dlp-email-alert {
    Vendor = Tessian
    Product = Tessian Cloud Email Security
    Lms = Splunk
    DataType = "dlp-email-alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
    Fields = [
      """"created_at":"({time}\d{4}-\d{1,2}-\d{1,2}T\d\d:\d\d:\d\d\.\d{1,6}Z)"""",	
      """"tessian_action":"({alert_name}[^"]{1,2000})"""",
      """"threat_types":\["({alert_name}[^"]{1,2000})"\]""",
      """"tessian_id":"({alert_id}[^"]{1,2000})"""",
      """"confidence":"({alert_severity}[^"]{1,2000})"""",
      """"message_id":"({message_id}[^"]{1,2000})"""",
      """"transmitter":"({sender}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
      """"from":"({sender}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
      """"recipients":\{"all":\[({recipients}"'?({recipient}[^"@]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})'?[^\]]{1,2000})""",
      """"to":\["({recipient}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})"""",
      """"subject":"\s{0,20}({subject}[^"]{1,2000}?)\s{0,20}"""",
      """"final_outcome":"({outcome}[^"]{1,2000})"""",
      """"attachments":\{"names":\[({attachments}"({attachment}[^"]{1,2000})[^\]\}]{1,2000})""",
      """"cc":\[({cc}[^\]]{1,2000})\]""",
      """"bcc":\[({bcc}[^\]]{1,2000})\]""",
      """"bytes":({bytes}\d{1,20}),"""
    ]
    DupFields = ["alert_name->alert_type"
}
```
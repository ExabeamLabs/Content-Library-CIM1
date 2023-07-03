#### Parser Content
```Java
{
Name = json-nozomi-guardian-security-alert
    Vendor = Nozomi Networks
    Product = Guardian
    Lms = Splunk
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
    Conditions = [""""vendor_product":"Nozomi_Networks_N2OS"""", """"nozomi_source":"alerts"""", """"category":"""]
    Fields = [
      """"_time":"({time}\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\+|-)\d{2}:\d{2})""",
      """"dvc_host":"({host}[\w.-])",""",
      """"nozomi_type_id":"({alert_type}[^"]{1,2000})"""",
      """"category":"({alert_name}[^"]{1,2000})"""",
      """"nozomi_id":"({alert_id}[^"]{1,2000})"""",
      """"severity":"({alert_severity}[^"]{1,2000})"""",
      """"description":"({additional_info}[^"]{1,2000})"""",
      """"src_ip":"({src_ip}[a-fA-F\d.:]{1,2000})""",
      """"dest_ip":"({dest_ip}[a-fA-F\d.:]{1,2000})""",
      """"src_mac":"({src_mac}[a-fA-F\d:]{1,2000})""",
      """"dest_mac":"({dest_mac}[a-fA-F\d:]{1,2000})""",
      """"src_port":({src_port}\d{1,100})""",
      """"dest_port":({dest_port}\d{1,100})""",
      """"dest_host":"({dest_host}[\w.-]{1,2000})""",
     ]


}
```
#### Parser Content
```Java
{
Name = cef-netskope-security-alert
  Vendor = Netskope
  Product = Security Cloud
  Lms = ArcSight
  TimeFormat = "epoch_sec"
  DataType = "alert"
  Conditions = [ """"type":"""", """destinationServiceName =Netskope""", """"alert":"yes"""", """"action":"useralert"""" ]
  Fields = [
  """"timestamp":({time}\d{1,10})"""
  """"hostname":"({src_host}[\w\-\.]{1,2000})"""
  """"app":"({app}[^"]{1,2000})"""
  """"user":"(unknown|(({user_email}[^\@"]{1,2000}@[^\@"]{1,2000}\.[^\@"]{1,2000})|(({domain}[^"@\\\/]{1,2000})[\\\/]{1,2000})?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|({user}[^"@\\\/]{1,2000}))))""""
  """"object":"(((?i)(Unknown( Unknown)?)|null)|({object}[^"]{1,2000}?))\s{0,100}""""
  """"activity":"({activity}[^"]{1,2000})""""
  """"os":"((?i)unknown|({os}[^"]{1,2000}))"""",
  """"browser":"((?i)unknown|({browser}[^"]{1,2000}))"""",
  """"url":"({full_url}[^"]{1,2000})""""
  """"file_size":({bytes}\d{1,100})""",
  """"file_type":"(Unknown|({file_type}[^"]{1,2000}))"""",
  """"page_site":"({app}[^"]{1,2000})"""",
  """"action":"({action}[^"]{1,2000})"""
  """"alert_name":"({alert_name}[^"]{1,2000})""""
  """"alert_type":"({alert_type}[^"]{1,2000})""""
  """"severity":"({alert_severity}[^"]{1,2000})""""
  """"_id":"{0,100}({alert_id}[^",]{1,2000})"""
  """"userip":"({src_ip}[A-Fa-f\d:.]{1,2000})"""
  """"srcip":"({src_ip}[A-Fa-f\d:.]{1,2000})"""
  """"src_location":"({src_location}[^"]{1,2000})"""
  """"src_country":"({src_country}[^"]{1,2000})"""
  ]
  DupFields = [ "object->file_name" ]


}
```
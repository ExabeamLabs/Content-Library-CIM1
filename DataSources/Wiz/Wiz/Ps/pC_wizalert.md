#### Parser Content
```Java
{
Name = wiz-alert
  Vendor = Wiz
  Product = Wiz
  Lms = Splunk
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"type":"Created"""", """"severity":"""", """"name":"""", """"trigger":{"""", """"cloudPlatform":"""" ]
  Fields = [
    """"created":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,6}Z)"""",
    """"control":\{[^\}]{1,2000}?"id":"({alert_id}[^"]{1,2000})"""",
    """"control":\{[^\}]{1,2000}?"name":"({alert_name}[^"]{1,2000})"""",
    """"resource":\{[^\}]{1,2000}?"type":"({alert_type}[^"]{1,2000})"""",
    """"control":\{"severity":"({alert_severity}[^"]{1,2000})"""",
    """({app}wiz)""",
    """"ruleName":"({rule}[^"]{1,2000})"""",
    """"ruleId":"({rule_id}[^"]{1,2000})"""",
    """"region":"({region}[^"]{1,2000})"""",
    """"trigger":\{[^\}]{1,2000}?"type":"({activity}[^"]{1,2000})"""",
    """"description":"({additional_info}[^"]{1,2000})""""
 ]


}
```
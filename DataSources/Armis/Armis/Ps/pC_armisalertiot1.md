#### Parser Content
```Java
{
Name = armis-alert-iot-1
  Vendor = Armis
  Product = Armis
  Lms = Splunk
  DataType = "alert-iot"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
  Conditions = [ """"alertId": """, """"activities": """, """"status": """, """"type": "System Policy Violation""""  ]
  Fields = [
    """"time"\s{0,100}:\s{0,100}"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)"""
    """({alert_type}System Policy Violation)""",
    """title"\s{0,100}:\s{0,100}"({alert_name}[^"]{1,2000})""",
    """severity"\s{0,100}:\s{0,100}"({alert_severity}[^"]{1,2000})""",
    """status"\s{0,100}:\s{0,100}"({alert_status}[^"]{1,2000})""",
    """description"\s{0,100}:\s{0,100}"({additional_info}[^"]{1,2000})""",
    """alertId"\s{0,100}:\s{0,100}({alert_id}\d{1,2000})""",
    """"deviceIds"\s{0,100}:\s{0,100}\[({device_id_list}[^\]]{1,2000})"""
    ]


}
```
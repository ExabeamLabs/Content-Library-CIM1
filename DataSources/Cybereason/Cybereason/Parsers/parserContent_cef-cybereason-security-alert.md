#### Parser Content
```Java
{
Name = cef-cybereason-security-alert
  Vendor = Cybereason
  Product = Cybereason
  Lms = ArcSight
  DataType = "alert"
  TimeFormat = "epoch"
  Conditions = [ """destinationServiceName=Cybereason""", """security-threat-detected""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\Wact=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_simpleValues_detectionType_values_0_=(|({alert_type}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wdhost=(|({dest_host}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wduser=(|(({domain}[^\\\/=]{1,2000})[\\\/]{1,2000})?({user}[^=\\\/]{1,2000}?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_simpleValues_creationTime_values_0_=({time}\d{1,100})""",
    """\Wmsg=(|({additional_info}({alert_name}[^\.]{1,2000}).+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wext_simpleValues_malopActivityTypes_values_0_=(|({threat_category}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
  ]
}
```
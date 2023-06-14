#### Parser Content
```Java
{
Name = vmware-vcenter-app-login
  Vendor = VMware
  Product = VMware VCenter
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSZ"
  Conditions = [ """"Message":""" , """"EventTime":""", """logged in""", """"UserName":""" ]
  Fields = [
  """"EventTime":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}(\.\d{1,6}Z)?)"""
  """"Message":"({additional_info}(User.*?@({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9]{1,2000}:[A-Fa-f0-9:]{1,2000}))\s{0,100})?[^"]{1,2000})"""
  """"UserName":"((({domain}[^\\"]{1,2000})\\{1,20})?({user}[^"]{1,2000}))"""
  """({activity}logged in)"""
  ]


}
```
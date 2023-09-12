#### Parser Content
```Java
{
Name = beyondtrust-process-created-1
  Vendor = BeyondTrust
  Product = BeyondTrust Privilege Management
  Lms = Direct
  DataType = "process-created"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """"process_name":"""",""""vendor_product":"Beyondtrust Privilege Management"""", """"process_start_time":"""" ]
  Fields = [
  """"process_start_time":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,3}Z)"""
  """"process_id":"?({process_id}\d{1,10})"""
  """process_path":"({process}({directory}[^"]{1,2000}(\\|\/){1,2000})?({process_name}[^"]{1,2000}))""""
  """"process":"({command_line}[^,]{1,2000})",""""
  """"action":"({action}[^"]{1,2000})""""
  """"user":"({user}[^"]{1,2000})""""
  """"dest":"({dest_host}[\w\-\.]{1,2000})"""
  """"user_id":"({user_sid}S-[^"]{1,2000})"""
  """"description":"({additional_info}[^"]{1,2000})"""
  """"parent_process":"({parent_process}({parent_directory}[^"]{1,2000}(\\|\/){1,2000})?({parent_process_name}[^"]{1,2000}))""""
  """"parent_process_id":"?({parent_process_id}\d{1,10})"""
  ]
  DupFields = [ "directory->process_directory" ]


}
```
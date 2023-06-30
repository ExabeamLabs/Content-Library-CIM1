#### Parser Content
```Java
{
Name = json-amazon-rds-database-operation
  Vendor = Amazon
  Product = Amazon RDS
  Lms = Splunk
  DataType = "database-operation"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSSSSSS"
  Conditions = [ """"type":"DatabaseActivityMonitoringRecord"""", """"instanceId":"""", """"databaseName":"""", """"dbUserName":"""" ]
  Fields = [
    """"logTime":"({time}\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})""",
    """"command":"({db_operation}[^"]{1,2000})"""",
    """"commandText":"({db_query}[^"]{1,2000})"""",
    """"databaseName":"({database_name}[^"]{1,2000})"""",
    """"dbUserName":"({db_user}[^"]{1,2000})"""",
    """"objectName":"({database_object}[^"]{1,2000})"""",
    """"schema_name":"({database_schema}[^"]{1,2000})"""",
    """"objectName":"({table_name}[^"]{1,2000})","objectType":"TABLE"""",
    """"serviceName":"({service_name}[^"]{1,2000})"""",
    """"serverHost":"({src_ip}[A-Fa-f\d.:]{1,2000})""""
  ]
  DupFields = [ "db_user->user" ]


}
```
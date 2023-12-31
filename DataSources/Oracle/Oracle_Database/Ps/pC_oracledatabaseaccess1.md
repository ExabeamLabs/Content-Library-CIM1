#### Parser Content
```Java
{
Name = oracle-database-access-1
  DataType = "database-access"
  Conditions = [ """action_name":"CREATE USER""", """os_username""", """userhost""", """priv_used""", """db_name""", """extended_timestamp""" ]

oracle-database-event = {
    Vendor = Oracle
    Product = Oracle Database
    Lms = Splunk
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
    Fields = [
      """timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{1,100}Z)"""",
      """exabeam_host=({host}[^\s]{1,2000})""",
      """"userhost":"(({domain}[^\\"]{1,2000})[\\]{1,20})?({src_host}[^"]{1,2000})"""",
      """"os_username":"({user}[^"]{1,2000})"""",
      """"username":"({db_user}[^"]{1,2000})"""",
      """"db_name":"({database_name}[^"]{1,2000})"""",
      """"action_name":"({db_operation}[^"]{1,2000})"""",
      """"sessionid":"({session_id}[^"]{1,2000})"""",
      """"priv_used":"({additional_info}[^"]{1,2000})"""",
    ]
    DupFields = [ "db_operation->activity" 
}
```
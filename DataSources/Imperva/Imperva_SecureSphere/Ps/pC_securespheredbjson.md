#### Parser Content
```Java
{
Name = securesphere-db-json
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-operation"
  IsHVF = true
  TimeFormat = "dd MMMM yyyy HH:mm:ss z"
  Conditions = [ """"Imperva Inc.|SecureSphere|""", """|Audit|Audit.DAM|""", "\"db-user\"", "\"event-type\"", "\"sql-error\"" ]
  Fields = [
    """"{1,20}real-time"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({time}.[^"]{1,2000}))"{1,20}(,|})""",
    """"audit-policy":\s{0,100}\[\s{0,100}"(|({policy}[^\]"]{1,2000}))"\s{0,100}\]""",
    """exabeam_host=(.+?@\s{0,100})?({host}[^\s]{1,2000})""",
    """"{1,20}gw-ip"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({host}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}dest-ip"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({dest_ip}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}source-ip"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({src_ip}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}db-user"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({domain}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}db-user"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({user}[^"\\@]{1,2000}?)(@({domain}[^"]{1,2000}))?)"{1,20}(,|})""",
    """"{1,20}db-user"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({domain}[^"\\@]{1,2000}?)(\\+({user}[^"]{1,2000}))?)"{1,20}(,|})""",
    """"{1,20}event-type"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({log_type}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}application-name"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({app}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}service-name"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({service_name}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}server-group"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({server_group}[^"]{1,2000}))"{1,20}(,|})""",
    """({database_name}db)"{1,20}(,|})""",
    """"{1,20}db-name"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({database_name}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}schema-name"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({database_schema}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}sql-error"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:|({sql_error}[^"]{1,2000}))"{1,20}(,|})""",
    """"{1,20}raw-query"{1,20}\s{0,100}:\s{0,100}"{1,20}[\\r\s]{0,2000}(?:|({db_query}[^",].+?[^\\]))\s{0,100}"{1,20}(,\s{0,100}"{1,20}|})""",
    """"{1,20}parsed-query"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:(N\\\/A \((logout|login)\))|(?:|({db_query}.*?[^\\])))\s{0,100}"{1,20}(,\s{0,100}"{1,20}|})""",
    """"{1,20}raw-query"{1,20}\s{0,100}:\s{0,100}"{1,20}[\\r\s]{0,2000}(?:|({db_operation}[^,"]\S+).*?[^\\])\s{0,100}"{1,20}(,\s{0,100}"|})""",
    """"{1,20}parsed-query"{1,20}\s{0,100}:\s{0,100}"{1,20}(?:(N\\\/A)|({db_operation}\S+)).+?[^\\]\s{0,100}"{1,20}(,\s{0,100}"{1,20}|})""",
    """"user-group"\s{0,100}:\s{0,100}"(|({user_group}[^"]{1,2000}))"""",
    """"application-user"\s{0,100}:\s{0,100}"(|({application_user}[^"]{1,2000}))"""",
    """"host-name"\s{0,100}:\s{0,100}"({host}[\w\-.]{1,2000})"""",
    """"policy-id"\s{0,100}:\s{0,100}\[\s{0,100}"({policy_id}[^"]{1,2000})"""",
  ]
  DupFields = [ "user->account", "user->db_user" ]


}
```
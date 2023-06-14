#### Parser Content
```Java
{
Name = s-oracle-db-query-1
    Vendor = Oracle
    Product = Oracle Database
    Lms = Splunk
    DataType = "database-query"
    IsHVF = true
    TimeFormat = "MMM dd HH:mm:ss yyyy z"
    Conditions = [ """CLIENT USER:""", """PRIVILEGE :""", """ACTION :""", """'SYSDBA'""" ]
    Fields = [ 
      """\s({time}\w{3} \d\d \d\d:\d\d:\d\d \d\d\d\d [+-]\d\d:\d\d)""",
      """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
      """ACTION\s{1,100}:\[\d{1,100}\]\s{1,100}'\s{0,100}({db_query}({db_operation}\w+).*?)\s{0,100}'([\w\s]{1,2000}\w+\s{0,100}:|$)""",
      """\sCLIENT USER:\[\d{1,100}\]\s{0,100}'({user}[^']{1,2000})'""",
      """\sDBID:\[\d{1,100}\]\s{0,100}'(|({database_name}[^']{1,2000}))'""",
      """\sDATABASE USER:\[\d{1,100}\]\s{0,100}'(\/|({account}[^'\\\/\s]{1,2000}))'""",
      """\sPRIVILEGE :\[\d{1,100}\]\s{0,100}'({privilege}[^']{1,2000})'""",
    ]
    DupFields = [ "user->os_user", "account->db_user" ]
 

}
```
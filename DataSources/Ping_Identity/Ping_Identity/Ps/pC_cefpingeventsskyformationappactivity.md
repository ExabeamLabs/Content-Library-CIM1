#### Parser Content
```Java
{
Name = cef-ping-events-skyformation-app-activity
  DataType = "app-activity"
  Conditions = [ """CEF:""", """destinationServiceName =ping""", """action""", """suser=""", """"status":""" ]

cef-ping-events-skyformation = {
  Vendor = Ping Identity
  Product = Ping Identity
  Lms = Direct
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """end=({time}\d{1,100})""", 
    """cat=(N\/A|({category}[^\s]{1,2000}))""",
    """destinationServiceName =({app}[^\s]{1,2000})""",
    """suser=(anonymous|({user_email}[^\s]{1,2000}))""",
    """"ipAddress":"({src_ip}[A-Fa-f:\d.]{1,2000})"""",
    """"source":"({alert_name}[^"]{1,2000})"""",
    """"action"{0,20}:\{"{0,20}type"{0,20}:"{0,20}({event_name}[^"}]{1,2000})"""",
    """"result"{0,20}:\{"{0,20}status"{0,20}:"{0,20}({outcome}[^",]{1,2000})""",
    """"message"{0,20}:"{0,20}({event_name}[^"]{1,2000})"""",
    """"idpEntityId"{0,20}:"{0,20}({url}[^"]{1,2000})"""",
    """"client"{0,20}:\{"{0,20}id"{0,20}:"{0,20}({user_agent}[^"]{1,2000})"""",
    """msg=({additional_info}.+?)\soldFile=""",
  
}
```
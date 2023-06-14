#### Parser Content
```Java
{
Name = skybox-app-login
  Vendor = Skybox
  Product = Skybox
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """skybox_syslog""", """User_Management Login""", """logged in""" ]
  Fields = [
    """\w+\s{1,100}\d{1,2}\s\d{1,2}:\d{1,2}:\d{1,2}\s{1,100}({host}[\w\-.]{1,2000})""",
    """({activity}logged in)""",
    """\}@({dest_ip}[A-Fa-f\d.:]{1,2000}?):""",
    """User\s{1,100}({user}[^\s]{1,200})\s{1,100}logged in""",
    """\s({severity}\w{1,2000})\s{1,100}({app}skybox)""",
    """({event_name}User_Management Login)""",
  ]


}
```
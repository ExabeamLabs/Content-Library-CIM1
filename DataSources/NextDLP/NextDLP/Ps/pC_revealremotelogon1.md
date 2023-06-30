#### Parser Content
```Java
{
Name = reveal-remote-logon-1
  Vendor = NextDLP
  DataType = "remote-logon"
  Conditions = [ """reveal""", """SSH connection""", """"tags":""", """"attackindicator"""", """"name":""", """"sensor_type": "AGENT_POLICY"""" ]
  DupFields = [ "event_name->activity"]


}
```
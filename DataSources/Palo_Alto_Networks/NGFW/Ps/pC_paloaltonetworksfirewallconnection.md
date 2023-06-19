#### Parser Content
```Java
{
Name = palo-alto-networks-firewall-connection
  Vendor = Palo Alto Networks
  Product = NGFW
  Lms = Splunk
  DataType = "network-connection"
  TimeFormat = "MMM dd yyyy HH:mm:ss"
  Conditions = [ """,DECRYPTION,""", """,web-browsing,""" ]
  Fields = [
   """:\d\d:\d\d\s{1,100}({host}[\w\-\.]{1,2000})\s"""
   """({log_type}DECRYPTION)"""
   """,DECRYPTION,([^,]{0,2000

}
```
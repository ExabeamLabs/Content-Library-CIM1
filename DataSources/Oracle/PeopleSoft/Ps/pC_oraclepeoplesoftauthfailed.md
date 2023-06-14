#### Parser Content
```Java
{
Name = oracle-peoplesoft-auth-failed
  Vendor = Oracle
  Product = PeopleSoft
  Lms = Splunk
  DataType = "authentication-failed"
  TimeFormat = "MMM dd, yyyy HH:mm:ss"
  Conditions = [ """Authentication Failure for user : """, """AuthenticationException: """, """, for idstore """ ]
  Fields = [
    """<({time}\w{3}\s\d{1,2

}
```
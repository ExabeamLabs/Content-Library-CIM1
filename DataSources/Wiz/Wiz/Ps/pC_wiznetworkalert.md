#### Parser Content
```Java
{
Name = wiz-network-alert
 Vendor = Wiz
 Product = Wiz
 Lms = Splunk
 DataType = "network-alert"
 TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSZ"
 Conditions = [ """"category":"Detection"""", """DDoS Attack""", """"name":""", """"CLOUD_EVENTS"""" ]
 Fields = [
   """"timestamp":"({time}\d{4}-\d{1,2}-\d{1,2}T\d{1,2}:\d{1,2}:\d{1,2}\.\d{1,7}Z)"""
   """"IP":"({src_ip}[a-fA-F\d.:]{1,2000})"""
   """actor":.*?"name":"(({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})|({user}[^"]{1,2000}))""""
   """"eventURL":"({url}[^"]{1,2000})"""
   """({app}wiz)"""
   """ruleName:\s{0,100}({rule}[^,]{1,2000})","""
   """"ruleId:\s{0,100}({rule_id}[^";,]{1,2000})""",
   """"region":"({region}[^"]{1,2000})""""
   """"id":"({alert_id}[^"]{1,2000})"""
 ]
 DupFields = [ "rule->alert_name" ]


}
```
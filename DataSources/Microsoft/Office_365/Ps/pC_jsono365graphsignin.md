#### Parser Content
```Java
{
Name = json-o365-graph-sign-in
  Vendor = Microsoft
  Product = Office 365
  Lms = Direct
  DataType = "app-login"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = [ """"destinationServiceName":"Office 365"""", """"dproc":"Graph Sign-In logs"""", """failureReason":""" ]
  Fields = [
    """"createdDateTime":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ)"""",
    """({event_name}Sign-In)""",
    """"userDisplayName":"(({user_fullname}[^\s"]{1,2000}\s{1,20}[^"]{1,2000})|({user}[^"]{1,2000}))""",
   """"userPrincipalName":"(({user_email}([A-Za-z0-9]{1,2000}[!#$%&'+-\/=?^_`~]){0,2000}[A-Za-z0-9]{1,2000}@[^\]\s"\\,\|]{1,2000}\.[^\]\s"\\,\|]{1,2000})|({user}[^"]{1,2000}))"""",
    """"userId":"({user_id}[^"]{1,2000})"""
    """"appDisplayName":"({app}[^"]{1,2000})"""
    """"ipAddress":"({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({src_port}\d{1,20}))?"""
    """"clientAppUsed":"({object}[^"]{1,2000})"""
    """"resourceDisplayName":"({resource}[^",]{1,2000})"""
    """"additionalDetails":"({additional_info}[^"]{1,2000})"""
    """"deviceDetail".+?operatingSystem":"({os}[^"]{1,2000})"""
    """"location".+?city":"({location_city}[^",]{1,2000})"""
    """"location".+?state":"({location_state}[^",]{1,2000})"""
    """"location".+?countryOrRegion":"({location_country}[^",]{1,2000})"""
    """"failureReason":"(Other|({failure_reason}[^"]{1,2000}))"""
    """"errorCode":({error_code}\d{1,2000})"""
  ]


}
```
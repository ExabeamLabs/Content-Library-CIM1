#### Parser Content
```Java
{
Name = json-4723-1
  DataType = "windows-password-change"
  Conditions = [ """"event_id":4723""", """An attempt was made to change an account's password""" ]
  Fields = ${WinParserTemplates.json-windows-events-1.Fields}[
    """({event_name}An attempt was made to change an account's password)""",
    """"TargetSid"+:"+({target_user_sid}[^"]+)""",
  ]
}
json-windows-events-1 = {
  Vendor = Microsoft
  Product = Microsoft Windows
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Fields = [
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d.\d\d\dZ)\s({host}[^\s]+)\sSkyformation""",
    """requestClientApplication=({app}.+?)\s\w+=""",
    """({event_name}An account was logged off)""",
    """"keywords"+:\["+({outcome}[^"]+)""",
    """"pid"+:({pid}\d+)""",
    """thread"+:.+?"+id"+:({thread_id}\d+)""",
    """"TargetUserName"+:"+({target_user}[^"]+)""",
    """"TargetDomainName"+:"+({domain}[^"]+)""",
    """"TargetLogonId"+:"+({logon_id}[^"]+)""",
    """"LogonType"+:"+({logon_type}[^"]+)""",
    """"TargetUserSid"+:"+({user_sid}[^"]+)""",
    """"record_id"+:({record_id}\d+)""",
    """"task"+:"+({task_name}[^"]+)""",
    """"event_id"+:({event_code}\d+)""",
    """"computer_name"+:"+({src_host}[^"]+)""",
    """"hostname"+:"+({host}[^"]+)""",
    """"action"+:"+({action}[^"]+)""",
    """"os"+:.+?"name"+:"+({os}[^"]+)""",
    """"SubjectLogonId"+:"+({logon_id}[^"]+)""",
    """"+activity_id"+:"+\{({activity_id}[^}]+)""",
    """"+ProviderName"+:"+({provider_name}[^"]+)""",
    """"+SubjectUserSid"+:"+({user_sid}[^"]+)""",
    """"+SubjectDomainName"+:"+({domain}[^"]+)""",
    """"user"+:"+(SYSTEM|-|({user}[^@"]+))""",
    """"+SubjectUserName"+:"+(SYSTEM|-|({user}[^"]+))""",
  ]

```
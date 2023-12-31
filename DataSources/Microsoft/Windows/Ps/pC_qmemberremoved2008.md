#### Parser Content
```Java
{
Name = q-member-removed-2008
  Vendor = Microsoft
  Product = Windows
  Lms = QRadar
  DataType = "windows-member-removed"
  TimeFormat = "epoch_sec"
  Conditions = [ "A member was removed from a security-enabled", "EventID=" ]
  Fields = [
    """({event_name}A member was removed from a security-enabled ({group_type}[\w\s]{1,2000}) group)""",
    """EventID="{0,20}({event_code}\d{1,100})""",
    """({host}[^\s]{1,2000})\sMicrosoft-Windows-Security-Auditing""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\d\d\d\d[+-]\d\d:\d\d)\s{1,100}({host}[\w.-]{1,2000})\s""",
    """TimeGenerated=({time}\d{1,100})\s""",
    """"TimeGenerated":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,10})?Z)"""",
    """Computer=({host}[^\s]{1,2000})""",
    """"SubjectDomainName":"({domain}[^"]{1,2000})"""",
    """"SubjectUserName":"({user}[^"]{1,2000})"""",
    """"SubjectLogonId":"({logon_id}[^"]{1,2000})"""",
    """"SubjectUserSid":"({user_sid}[^"]{1,2000})"""",
    """"TargetDomainName":"({group_domain}[^"]{1,2000})"""",
    """"TargetUserName":"({group_name}[^"]{1,2000})"""",
    """"TargetSid":"({group_id}[^"]{1,2000})"""",
    """"MemberSid":"({sid_user}[^"]{1,2000})"""",
    """"MemberName":"(-|({account_dn}({account_id}[^"]{1,2000})))"""",
    """A member was removed from a security-enabled ({group_type}[^\s]{1,2000}) group.+?Account Name:\s{1,100}({user}[^\s]{1,2000}).+?Account Domain:\s{1,100}({domain}[^\s]{1,2000}).+?Logon ID:\s{1,100}({logon_id}[^\s]{1,2000})\s{1,100}""",
    """Member:\s{1,100}Security ID:\s{1,100}({account_id}(?=[^\\]{1,2000}\\)({sid_domain}[^\\]{1,2000})\\({sid_user}[^:]{1,2000}?)|(?:[^:]{1,2000}?))\s{1,100}Account Name:\s{1,100}({account_dn}CN=.+?,({account_ou}OU.+?DC=[\w-]{1,2000}))?[\w-]{0,2000}\s{1,100}Group:\s{1,100}Security ID:\s{1,100}({group_id}[^\s]{1,2000}).+?\s{1,100}(Group|Account) Name:\s{1,100}({group_name}[^\s]{1,2000})?.+?\s{1,100}(Group|Account) Domain:\s{1,100}({group_domain}[^\s]{1,2000})"""
  ]
  DupFields = [ "host->dest_host" ]


}
```
#### Parser Content
```Java
{
Name = exabeam-cr-kv-alert-trigger-success-correlationrule
Vendor = Exabeam
Product = Correlation Rule
Lms = Exabeam
DataType = "exabeam-security-alert"
TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
Conditions = [ """operation="alert-trigger"""" , """alert_source="correlation"""" ]
Fields = [
"""alert_severity=\\*"({alert_severity}[^"\\]+)\\*"""",
"""rule_severity=\\*"({rule_severity}[^"\\]+)\\*"""",
"""alert_source=\\*"({alert_source}correlation)\\*"""",
"""alert_name=\\*"({alert_name}[^"\\]+)\\*"""",
"""alert_type=\\*"({alert_type}[^"\\]+)\\*"""",
"""dest_host=\\*"({dest_host}[^"\\]+)\\*"""",
"""dest_ip=\\*"({dest_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({dest_port}\d+))?\\*"""",
"""operation=\\*"({activity}[^"\\]+)\\*"""",
"""rule_description=\\*"({rule_description}[^"\\]+)\\*"""",
"""rule_id=\\*"({rule_id}[^"\\]+)\\*"""",
"""rule=\\*"({rule}[^"\\]+)\\*"""",
"""rule_reason=\\*"({rule_reason}[^"\\]+)\\*"""",
"""rule_type=\\*"({rule_type}[^"\\]+)\\*"""",
"""src_host=\\*"({src_host}[^"\\]+)\\*"""",
"""src_ip=\\*"({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({src_port}\d+))?\\*"""",
"""trigger_time=\\*"({time}\d{10})\\*"""",
"""timestamp=\\*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
"""url=\\*"({url}[^"\\]+)\\*"""",
"""user=\\*"({user}[^"\\]+)\\*""""
"""src_ip=\\*"({src_ip}((([0-9a-fA-F.]{1,4}):{1,2}){7}([0-9a-fA-F]){1,4})|(((25[0-5]|(2[0-4]|1\d|[0-9]|)\d)\.?\b){4}))(:({src_port}\d+))?\\*""""
"""score=\\*"({risk_score}[^"\\]+)\\*""""

#parsed from corr rule section
"""usecases="({rule_usecases}[^"]+)"""",
"""mitre_labels="({mitre_labels}[^"]+)"""",
"""exa_rule_severity="({alert_severity}[^"]+)"""",
"""exa_rule_category="({alert_type}[^"]+)"""",
"""exa_rule_name="({alert_name}.+?)"\s\w+="""",
"""exa_rule_id="({alert_id}[^"]+)"""",
"""exa_link_logs="({dl_exa_link_logs}[^"]+)""""
#exa_link_alert?
"""exa_rule_description="({rule_description}[^"]+)"""",
#exa_risk_score?

]


}
```
|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  app-activity<br> ↳[googlecloud-app-activity](Ps/pC_googlecloudappactivity.md)<br><br> gcp-disk-attach<br> ↳[gcp-instancesattachdisk-json](Ps/pC_gcpinstancesattachdiskjson.md)<br><br> gcp-disk-create<br> ↳[gcp-disksinsert-json](Ps/pC_gcpdisksinsertjson.md)<br><br> gcp-image-create<br> ↳[gcp-imagesinsert-json](Ps/pC_gcpimagesinsertjson.md)<br><br> gcp-instance-create<br> ↳[gcp-instancesinsert-json](Ps/pC_gcpinstancesinsertjson.md)<br><br> gcp-instance-setmachinetype<br> ↳[gcp-instancessetmachinetype-json](Ps/pC_gcpinstancessetmachinetypejson.md)<br><br> gcp-instance-setmetadata<br> ↳[gcp-instancessetmetadata-json](Ps/pC_gcpinstancessetmetadatajson.md)<br> ↳[gcp-projectssetinstancemetadata-json](Ps/pC_gcpprojectssetinstancemetadatajson.md)<br><br> gcp-policy-write<br> ↳[gcp-disksetiampolicy-json](Ps/pC_gcpdisksetiampolicyjson.md)<br> ↳[gcp-instancesetiampolicy-json](Ps/pC_gcpinstancesetiampolicyjson.md)<br> ↳[gcp-storagesetiampermissions-json](Ps/pC_gcpstoragesetiampermissionsjson.md)<br> ↳[gcp-imagesetiampolicy-json](Ps/pC_gcpimagesetiampolicyjson.md)<br> ↳[gcp-projectsetiampolicy-json](Ps/pC_gcpprojectsetiampolicyjson.md)<br> ↳[gcp-snapshotsetiampolicy-json](Ps/pC_gcpsnapshotsetiampolicyjson.md)<br> ↳[gcp-accountsetiampolicy-json](Ps/pC_gcpaccountsetiampolicyjson.md)<br><br> gcp-role-write<br> ↳[gcp-createrole-json](Ps/pC_gcpcreaterolejson.md)<br> ↳[gcp-updaterole-json](Ps/pC_gcpupdaterolejson.md)<br><br> gcp-serviceaccount-creds-write<br> ↳[gcp-createserviceaccountkey-json](Ps/pC_gcpcreateserviceaccountkeyjson.md)<br><br> gcp-serviceaccount-write<br> ↳[gcp-createserviceaccount-json](Ps/pC_gcpcreateserviceaccountjson.md)<br><br> gcp-snapshot-create<br> ↳[gcp-diskscreatesnapshot-json](Ps/pC_gcpdiskscreatesnapshotjson.md)<br><br> gcp-storageobject-acl<br> ↳[gcp-objectsupdate-json](Ps/pC_gcpobjectsupdatejson.md)<br><br> netflow-connection<br> ↳[gcpvpc-netflow-connection](Ps/pC_gcpvpcnetflowconnection.md)<br><br> network-alert<br> ↳[gcp-ids-network-alert](Ps/pC_gcpidsnetworkalert.md)<br><br> web-activity-allowed<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br><br> web-activity-denied<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br> | T1027.005 - Obfuscated Files or Information: Indicator Removal from Tools<br>T1046 - Network Service Scanning<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.004 - Valid Accounts: Cloud Accounts<br>T1102 - Web Service<br>T1133 - External Remote Services<br>T1189 - Drive-by Compromise<br>T1190 - Exploit Public Fasing Application<br>T1204.001 - T1204.001<br>T1535 - Unused/Unsupported Cloud Regions<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br> | [<ul><li>109 Rules</li></ul><ul><li>62 Models</li></ul>](RM/r_m_google_cloud_platform_Compromised_Credentials.md) |
|    [Malware](../../../UseCases/uc_malware.md)    |  app-activity<br> ↳[googlecloud-app-activity](Ps/pC_googlecloudappactivity.md)<br><br> gcp-image-create<br> ↳[gcp-imagesinsert-json](Ps/pC_gcpimagesinsertjson.md)<br><br> gcp-instance-setmetadata<br> ↳[gcp-instancessetmetadata-json](Ps/pC_gcpinstancessetmetadatajson.md)<br> ↳[gcp-projectssetinstancemetadata-json](Ps/pC_gcpprojectssetinstancemetadatajson.md)<br><br> netflow-connection<br> ↳[gcpvpc-netflow-connection](Ps/pC_gcpvpcnetflowconnection.md)<br><br> network-alert<br> ↳[gcp-ids-network-alert](Ps/pC_gcpidsnetworkalert.md)<br><br> web-activity-allowed<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br><br> web-activity-denied<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br>    | T1037 - Boot or Logon Initialization Scripts<br>T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1189 - Drive-by Compromise<br>T1190 - Exploit Public Fasing Application<br>T1204.001 - T1204.001<br>T1204.003 - T1204.003<br>T1566.002 - Phishing: Spearphishing Link<br>T1568.002 - Dynamic Resolution: Domain Generation Algorithms<br>TA0002 - TA0002<br>TA0011 - TA0011<br>    | [<ul><li>36 Rules</li></ul><ul><li>10 Models</li></ul>](RM/r_m_google_cloud_platform_Malware.md)    |
|         [Privilege Abuse](../../../UseCases/uc_privilege_abuse.md)         |  app-activity<br> ↳[googlecloud-app-activity](Ps/pC_googlecloudappactivity.md)<br><br> cloud-admin-activity<br> ↳[googlecloud-iam-activity](Ps/pC_googlecloudiamactivity.md)<br> ↳[googlecloud-cloudresourcemanager-activity](Ps/pC_googlecloudcloudresourcemanageractivity.md)<br><br> cloud-admin-activity-failed<br> ↳[googlecloud-iam-activity](Ps/pC_googlecloudiamactivity.md)<br> ↳[googlecloud-cloudresourcemanager-activity](Ps/pC_googlecloudcloudresourcemanageractivity.md)<br><br> gcp-serviceaccount-write<br> ↳[gcp-createserviceaccount-json](Ps/pC_gcpcreateserviceaccountjson.md)<br><br> web-activity-allowed<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br><br> web-activity-denied<br> ↳[googlecloud-web-activity](Ps/pC_googlecloudwebactivity.md)<br>    | T1071.001 - Application Layer Protocol: Web Protocols<br>T1078 - Valid Accounts<br>T1078.004 - Valid Accounts: Cloud Accounts<br>T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1136.003 - Create Account: Create: Cloud Account<br>T1530 - Data from Cloud Storage Object<br>    | [<ul><li>11 Rules</li></ul><ul><li>5 Models</li></ul>](RM/r_m_google_cloud_platform_Privilege_Abuse.md)    |
|    [Privilege Escalation](../../../UseCases/uc_privilege_escalation.md)    |  app-activity<br> ↳[googlecloud-app-activity](Ps/pC_googlecloudappactivity.md)<br><br> gcp-instance-setmetadata<br> ↳[gcp-instancessetmetadata-json](Ps/pC_gcpinstancessetmetadatajson.md)<br> ↳[gcp-projectssetinstancemetadata-json](Ps/pC_gcpprojectssetinstancemetadatajson.md)<br><br> gcp-policy-write<br> ↳[gcp-disksetiampolicy-json](Ps/pC_gcpdisksetiampolicyjson.md)<br> ↳[gcp-instancesetiampolicy-json](Ps/pC_gcpinstancesetiampolicyjson.md)<br> ↳[gcp-storagesetiampermissions-json](Ps/pC_gcpstoragesetiampermissionsjson.md)<br> ↳[gcp-imagesetiampolicy-json](Ps/pC_gcpimagesetiampolicyjson.md)<br> ↳[gcp-projectsetiampolicy-json](Ps/pC_gcpprojectsetiampolicyjson.md)<br> ↳[gcp-snapshotsetiampolicy-json](Ps/pC_gcpsnapshotsetiampolicyjson.md)<br> ↳[gcp-accountsetiampolicy-json](Ps/pC_gcpaccountsetiampolicyjson.md)<br><br> gcp-role-write<br> ↳[gcp-createrole-json](Ps/pC_gcpcreaterolejson.md)<br> ↳[gcp-updaterole-json](Ps/pC_gcpupdaterolejson.md)<br><br> gcp-serviceaccount-creds-write<br> ↳[gcp-createserviceaccountkey-json](Ps/pC_gcpcreateserviceaccountkeyjson.md)<br>    | T1098.002 - Account Manipulation: Exchange Email Delegate Permissions<br>T1530 - Data from Cloud Storage Object<br>TA0004 - TA0004<br>    | [<ul><li>16 Rules</li></ul><ul><li>11 Models</li></ul>](RM/r_m_google_cloud_platform_Privilege_Escalation.md)     |
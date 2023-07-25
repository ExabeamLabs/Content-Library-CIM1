|    Use-Case    | Event Types/Parsers    | MITRE ATT&CK® TTP    | Content    |
|:----:| ---- | ---- | ---- |
| [Compromised Credentials](../../../UseCases/uc_compromised_credentials.md) |  authentication-successful<br> ↳[fortinet-auth-successful](Ps/pC_fortinetauthsuccessful.md)<br> ↳[fortinet-0102043039](Ps/pC_fortinet0102043039.md)<br><br> failed-vpn-login<br> ↳[fortinet-ssl-failed-vpn-login](Ps/pC_fortinetsslfailedvpnlogin.md)<br><br> vpn-login<br> ↳[fortinet-ipsec-vpn-start](Ps/pC_fortinetipsecvpnstart.md)<br> ↳[fortinet-ssl-vpn-start-1](Ps/pC_fortinetsslvpnstart1.md)<br> ↳[fortinet-ssl-vpn-start](Ps/pC_fortinetsslvpnstart.md)<br><br> vpn-logout<br> ↳[fortinet-ipsec-vpn-end](Ps/pC_fortinetipsecvpnend.md)<br> ↳[fortinet-ssl-vpn-end-3](Ps/pC_fortinetsslvpnend3.md)<br> | T1078 - Valid Accounts<br>T1110 - Brute Force<br>T1133 - External Remote Services<br>    | [<ul><li>26 Rules</li></ul><ul><li>12 Models</li></ul>](RM/r_m_fortinet_fortinet_vpn_Compromised_Credentials.md) |
|        [Lateral Movement](../../../UseCases/uc_lateral_movement.md)        |  authentication-successful<br> ↳[fortinet-auth-successful](Ps/pC_fortinetauthsuccessful.md)<br> ↳[fortinet-0102043039](Ps/pC_fortinet0102043039.md)<br><br> failed-vpn-login<br> ↳[fortinet-ssl-failed-vpn-login](Ps/pC_fortinetsslfailedvpnlogin.md)<br><br> vpn-login<br> ↳[fortinet-ipsec-vpn-start](Ps/pC_fortinetipsecvpnstart.md)<br> ↳[fortinet-ssl-vpn-start-1](Ps/pC_fortinetsslvpnstart1.md)<br> ↳[fortinet-ssl-vpn-start](Ps/pC_fortinetsslvpnstart.md)<br><br> vpn-logout<br> ↳[fortinet-ipsec-vpn-end](Ps/pC_fortinetipsecvpnend.md)<br> ↳[fortinet-ssl-vpn-end-3](Ps/pC_fortinetsslvpnend3.md)<br> | T1021 - Remote Services<br>T1078 - Valid Accounts<br>T1090.003 - Proxy: Multi-hop Proxy<br>T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting<br> | [<ul><li>9 Rules</li></ul><ul><li>3 Models</li></ul>](RM/r_m_fortinet_fortinet_vpn_Lateral_Movement.md)          |
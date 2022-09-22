# RedTeam-Tools

*Tools and Techniques for Red Team / Penetration Testing

---------------
# Table of Contents

1. [Reconnaissance](#reconnaissance)
    - dnsrecon
    - Shodan.io
2. [Resource Development](#resourcedevelopment)
    - .
3. [Initial Access](#initialaccess)
    - EvilGoPhish
    - The Social-Engineer Toolkit
4. [Execution](#execution)
    - .
5. [Persistence](#persistence)
    - .
6. [Privilege Escalation](#privilegeescalation)
    - .
7. [Defense Evasion](#defenseevasion)
    - .
8. [Credential Access](#credentialaccess)
    - .
9. [Discovery](#discovery)
    - PCredz
    - PingCastle
10. [Lateral Movement](#lateralmovement)
    - .
11. [Collection](#collection)
    - .
12. [Command and Control](#commandandcontrol)
    - .
13. [Exfiltration](#exfiltration)
    - .
14. [Impact](#impact)
    - .
    
Reconnaissance
====================

* [dnsrecon](https://www.kali.org/tools/dnsrecon/#dnsrecon)

	dnsrecon is a pyhton tool for enumerating DNS records (MX, SOA, NS, A, AAAA, SPF and TXT) and can provide a number of new associated victim hosts to pivot into from a single domain search.
	
	![image](https://user-images.githubusercontent.com/100603074/191689049-624db340-8adb-4a97-be8d-b7177f409a8b.png)

* [shodan.io](https://www.shodan.io/dashboard)

	Shodan crawls public infrastructure and displays it in a searchable format. Using a company name, domain name, IP address it is possible to discover potentially vulnerable systems relating to your target via shodan.
	
	![image](https://user-images.githubusercontent.com/100603074/191689282-70f99fe9-aa08-4cd3-b881-764eface8546.png)


InitialAccess
====================

* [EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish)

	evilginx2 + gophish. (GoPhish) Gophish is a powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing. (evilginx2) Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
    
	![image](https://user-images.githubusercontent.com/100603074/191007680-890acda1-72ec-429e-9c91-b2cae55d7189.png)
    
* [Social Engineer Toolkit (SET)](https://github.com/IO1337/social-engineering-toolkit)

	This framework is great for creating campaigns for initial access, 'SET has a number of custom attack vectors that allow you to make a believable attack quickly'.

	![image](https://user-images.githubusercontent.com/100603074/191690233-e1f4255a-514e-4887-94da-b8a3396025f0.png)


Discovery
====================

* [PCredz](https://github.com/lgandx/PCredz)

	This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

    ![image](https://user-images.githubusercontent.com/100603074/191007004-a0fd01f3-e01f-4bdb-b89e-887c85a7be91.png)

* [PingCastle](https://github.com/vletoux/pingcastle)

	Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.

	![image](https://user-images.githubusercontent.com/100603074/191008405-39bab2dc-54ce-43d1-aed7-53956776a9ef.png)

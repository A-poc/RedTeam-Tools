# RedTeam-Tools

*Tools and Techniques for Red Team / Penetration Testing

---------------
# Table of Contents

1. [Reconnaissance](#reconnaissance)
    - dnsrecon
    - Shodan.io
    - AORT (All in One Recon Tool)
2. [Resource Development](#resource-development)
    - .
3. [Initial Access](#initial-access)
    - EvilGoPhish
    - The Social-Engineer Toolkit
4. [Execution](#execution)
    - .
5. [Persistence](#persistence)
    - .
6. [Privilege Escalation](#privilege-escalation)
    - LinPEAS
    - linux-smart-enumeration
    - WinPEAS
7. [Defense Evasion](#defense-evasion)
    - .
8. [Credential Access](#credential-access)
    - .
9. [Discovery](#discovery)
    - PCredz
    - PingCastle
10. [Lateral Movement](#lateral-movement)
    - .
11. [Collection](#collection)
    - .
12. [Command and Control](#command-and-control)
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

* [AORT](https://github.com/D3Ext/AORT)

	Tool for enumerating subdomains, enumerating DNS, WAF detection, WHOIS, port scan, wayback machine, email harvesting.
	
	![image](https://user-images.githubusercontent.com/100603074/192070398-aae0217d-69c4-460b-ae4c-51b045551268.png)


Initial Access
====================

* [EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish)

	evilginx2 + gophish. (GoPhish) Gophish is a powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing. (evilginx2) Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
    
	![image](https://user-images.githubusercontent.com/100603074/191007680-890acda1-72ec-429e-9c91-b2cae55d7189.png)
    
* [Social Engineer Toolkit (SET)](https://github.com/IO1337/social-engineering-toolkit)

	This framework is great for creating campaigns for initial access, 'SET has a number of custom attack vectors that allow you to make a believable attack quickly'.

	![image](https://user-images.githubusercontent.com/100603074/191690233-e1f4255a-514e-4887-94da-b8a3396025f0.png)

Privilege Escalation
====================

* [LinPEAS](https://github.com/carlospolop/PEASS-ng)

	LinPEAS is a nice verbose privilege escalation for finding local privesc routes on Linux endpoints. 
	
	![image](https://user-images.githubusercontent.com/100603074/192070104-8a121544-5c88-4c24-8b2e-590700b345e7.png)

* [linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

	Linux smart enumeration is another good, less verbose, linux privesc tool for Linux.
	
	![image](https://user-images.githubusercontent.com/100603074/192070258-2fe8727a-4b75-430d-a84e-da6605750de9.png)


* [WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

	WinPEAS is a nice verbose privilege escalation for finding local privesc routes on Windows endpoints. 

	![image](https://user-images.githubusercontent.com/100603074/192070193-fed8a0e8-b82a-4338-9209-6352f33ab6b8.png)


Discovery
====================

* [PCredz](https://github.com/lgandx/PCredz)

	This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

    ![image](https://user-images.githubusercontent.com/100603074/191007004-a0fd01f3-e01f-4bdb-b89e-887c85a7be91.png)

* [PingCastle](https://github.com/vletoux/pingcastle)

	Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.

	![image](https://user-images.githubusercontent.com/100603074/191008405-39bab2dc-54ce-43d1-aed7-53956776a9ef.png)

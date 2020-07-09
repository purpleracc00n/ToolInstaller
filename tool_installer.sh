#!/bin/bash
red='\033[0;31m'
green='\033[0;32m'
white='\033[1;37m'
blue='\033[0;34m'
yellow='\033[1;33m'
current_user=$(whoami)


#git hub and from repos
ToolInstaller(){

### Essential tools/libraries
echo -e ${blue} "[*]" ${white} "------------------Preparing essentials------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "pip & pip3" ${white}
	sudo apt-get install python-pip 1> /dev/null
	sudo apt-get install python3-pip 1> /dev/null
	sudo pip3 install --upgrade pip 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "npm" ${white}
	sudo apt-get -y install npm 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "powershell" ${white}
	sudo apt-get install powershell 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "wine" ${white}
	sudo apt-get install wine 1> /dev/null
echo -e ${green} "[+]" ${white} "Adding 32-bit architectures" ${white}
	sudo dpkg --add-architecture i386 1> /dev/null && sudo apt-get install wine32 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "mingw-w64" ${white}
	sudo apt-get install mingw-w64 1> /dev/null # cross compilation for windows exploits

### OSINT
echo -e ${blue} "[*]" ${white} "------------------Preparing OSINT tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "Shodan" ${white}
	sudo pip3 install shodan 1> /dev/null

### PasswordCracking
echo -e ${blue} "[*]" ${white} "------------------Preparing Password Cracking tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "Hashcat" ${white}
	sudo apt-get -y install -y ocl-icd-libopencl1 nvidia-driver nvidia-cuda-toolkit 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "SecLists" ${white}
	sudo apt-get install seclists 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "asleap" ${white}
	sudo apt-get -y install asleap 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "eapmd5pass" ${white}
	sudo apt-get -y install eapmd5pass 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "msoffcrypto-tool" ${white}
	sudo pip3 install msoffcrypto-tool 1> /dev/null # crack MS Office encrypted files
            

### Crypto
echo -e ${blue} "[*]" ${white} "------------------Preparing Crypto tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "testssl" ${white}
	git clone https://github.com/drwetter/testssl.sh.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "RsaCtfTool" ${white}
	git clone https://github.com/Ganapati/RsaCtfTool.git 1> /dev/null
	cd RsaCtfTool
	pwd
	ls -la
	sudo apt-get -y install libgmp3-dev libmpc-dev python3-venv 1> /dev/null
	python3 -m venv .
	. bin/activate
	sudo pip3 install -r "requirements.txt"
	cd ..
echo -e ${green} "[+]" ${white} "Downloading" ${red} "NetNTLM-Hashcat" ${white}
	git clone https://github.com/ins1gn1a/NetNTLM-Hashcat.git 1> /dev/null
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
echo -e ${green} "[+]" ${white} "Downloading" ${red} "CMSMap" ${white}
	git clone https://github.com/Dionach/CMSmap.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "WPscan" ${white}
	sudo apt-get -y install wpscan 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Nikto" ${white}
	sudo apt-get -y install nikto 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "API_Fuzzer" ${white}
	sudo gem install API_Fuzzer 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "gobuster" ${white}
	sudo apt-get -y install gobuster 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "bruteforce-http-auth" ${white}
	git clone https://github.com/erforschr/bruteforce-http-auth
echo -e ${green} "[+]" ${white} "Downloading" ${red} "BlindElephant" ${white}
	git clone https://github.com/lokifer/BlindElephant # Web App fingerprinter
	cd BlindElephant/src && sudo python setup.py install 1> /dev/null
	cd ../../
echo -e ${green} "[+]" ${white} "Installing" ${red} "jwt-cracker" ${white}
	sudo npm install --global jwt-cracker 1> /dev/null


### Windows/AD
echo -e ${blue} "[*]" ${white} "------------------Preparing Windows and AD tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "adXtract" ${white}
	git clone https://github.com/LordNem/adXtract 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "CombineHarvester" ${white}
	git clone https://github.com/LordNem/CombineHarvester.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "Empire" ${white}
	sudo apt-get -y install powershell-empire 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "DeathStar" ${white}	
	git clone https://github.com/byt3bl33d3r/DeathStar.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "DeathStar" ${white}
	cd DeathStar
	sudo pip3 install -r requirements.txt 1> /dev/null
	cd ..
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
	git clone https://github.com/ropnop/kerbrute
echo -e ${green} "[+]" ${white} "Installing" ${red} "jxplorer" ${white}
	sudo apt-get -y install jxplorer 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "kerberos_enum_userlists" ${white}
	git clone https://github.com/attackdebris/kerberos_enum_userlists
echo -e ${green} "[+]" ${white} "Installing" ${red} "powercat" ${white}
	sudo apt-get -y install powercat 1> /dev/null

### Privesc scripts - Windows
echo -e ${blue} "[*]" ${white} "------------------Preparing Windows Privilege Escalation scripts------------------" ${white}
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
	git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester

### Privesc scripts - Linux
echo -e ${blue} "[*]" ${white} "------------------Preparing Linux Privilege Escalation scripts------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "LSE - linux smart enumeration" ${white}
	git clone https://github.com/diego-treitos/linux-smart-enumeration 1>/dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "LinEnum" ${white}
	git clone https://github.com/rebootuser/LinEnum 1>/dev/null

### Networking
echo -e ${blue} "[*]" ${white} "------------------Preparing Networking & Protocol specific tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading & Installing" ${red} "bettercap" ${white}
	git clone https://github.com/evilsocket/bettercap.git 1> /dev/null
	sudo apt-get -y install bettercap
echo -e ${green} "[+]" ${white} "Downloading" ${red} "routersploit" ${white}
	git clone https://github.com/reverse-shell/routersploit.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "routersploit" ${white}
	cd routersploit && sudo python3 -m pip install -r requirements.txt && cd ..
echo -e ${green} "[+]" ${white} "Installing" ${red} "dsniff" ${white}
	sudo apt-get -y install dsniff  # for macof
echo -e ${green} "[+]" ${white} "Installing" ${red} "yersinia" ${white}
	sudo apt-get -y install bc validators yersinia # for frogger
echo -e ${green} "[+]" ${white} "Downloading" ${red} "Frogger" ${white}
	git clone https://github.com/nccgroup/vlan-hopping---frogger.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "hostapd-wpe" ${white}
	sudo apt-get -y install hostapd-wpe
echo -e ${green} "[+]" ${white} "Installing" ${red} "rstat-client" ${white}
	sudo apt-get -y install rstat-client # RPC service enumeration
echo -e ${green} "[+]" ${white} "Installing" ${red} "nis" ${white}
	sudo apt-get -y install nis # network information system tools
echo -e ${green} "[+]" ${white} "Downloading" ${red} "WatchGuard-Config-Parser" ${white}
	git clone https://github.com/ins1gn1a/WatchGuard-Config-Parser # Firewall config examiner
echo -e ${green} "[+]" ${white} "Downloading" ${red} "eapeak" ${white}
	git clone https://github.com/securestate/eapeak # Enterprise WiFi Cracking
echo -e ${green} "[+]" ${white} "Installing" ${red} "rinetd" ${white}
	sudo apt-get -y install rinetd # tunneling
echo -e ${green} "[+]" ${white} "Installing" ${red} "httptunnel" ${white}
	sudo apt-get -y install httptunnel # http tunneling
echo -e ${green} "[+]" ${white} "Installing" ${red} "crowbar" ${white}
	sudo apt-get -y install crowbar # rdp attack
echo -e ${green} "[+]" ${white} "Installing" ${red} "atftp" ${white}
	sudo apt-get -y install atftp

### Wireless
echo -e ${blue} "[*]" ${white} "------------------Preparing Wireless tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "wifiPwn" ${white}
	git clone https://github.com/LordNem/wifiPwn.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "r00kie-kr00kie" ${white}
	git clone https://github.com/hexway/r00kie-kr00kie.git
	cd ./r00kie-kr00kie
	sudo pip3 install -r requirements.txt
	cd ..

### VPN
echo -e ${blue} "[*]" ${white} "------------------Preparing VPN tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ike-scan" ${white}
	sudo apt-get -y install ike-scan 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "iker" ${white}
	git clone https://github.com/libcrack/iker.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "ikeforce" ${white}
	git clone https://github.com/SpiderLabs/ikeforce 1> /dev/null
	sudo pip3 install pyip pycrypto pyopenssl 1> /dev/null


### AV bypass
echo -e ${blue} "[*]" ${white} "------------------Preparing AV bypass tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "shellter" ${white}
	sudo apt-get -y install shellter # antivirus bypass - Dynamic shellcode injection tool and dynamic PE infector 

### Others
echo -e ${blue} "[*]" ${white} "------------------Preparing other tools------------------" ${white}
echo -e ${green} "[+]" ${white} "Installing" ${red} "sshfs" ${white}
	sudo apt-get -y install sshfs -y 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "ElasticSearch-Dump" ${white}
	sudo npm install elasticdump 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "FiercePhish" ${white}
	git clone https://github.com/Raikia/FiercePhish 1> /dev/null
echo -e ${green} "[+]" ${white} "Downloading" ${red} "dnsrecon" ${white}
	git clone https://github.com/darkoperator/dnsrecon.git 1> /dev/null
echo -e ${green} "[+]" ${white} "Installing" ${red} "tessaract" ${white}
	sudo apt -y install tesseract-ocr libtesseract-dev 1> /dev/null # Text recognition tool from images.
echo -e ${green} "[+]" ${white} "Downloading" ${red} "snmpv3enum" ${white}
	wget https://raw.githubusercontent.com/raesene/TestingScripts/master/snmpv3enum.rb
echo -e ${green} "[+]" ${white} "Installing" ${red} "libmemcached-tools" ${white}
	sudo apt-get -y install libmemcached-tools 1> /dev/null

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
	read -e  tools
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



# other stuff to add 
# tool for .NET C# and VB decompilation / reverse engineering: dnSpy - download from Softpedia
# wget https://c0decafe.de/tools/snmpattack-1.8.tar.gz

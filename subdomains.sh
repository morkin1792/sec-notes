## the following variables needed to be filled in
SecurityTrails="Fe26..."
cf_clearance="..."
userAgent="Mozilla..."
microsoftAuthorization="eyJhb..."

## DNS resolver to be used 
dnsServer="1.1.1.1"

function checkConfigs() {

    if [ -z "$(which amass)" ]; then
        printf "[-] amass is missing...\n"
        return 1
    fi

    if [ -z "$(which subfinder)" ]; then
        printf "[-] subfinder is missing...\n"
        return 1
    fi
    
    if [ ${#userAgent} -le 17 ]; then
        printf "[-] missing set your user-agent, you can get it with:\n\n"
        printf "console.log(window.navigator.userAgent)\n"
        return 1
    fi

    if [ ${#microsoftAuthorization} -lt 10 ]; then
        cat <<EOF
[-] missing set microsoft authorization token, to get it you can access ti.defender.microsoft.com and then run it in the browser console:
for (var key in localStorage) {
    if (key.indexOf("api") > 0) {
        console.log(JSON.parse(localStorage.getItem(key)).secret)
    }
} 
EOF
        return 1
    fi

    if [ ${#cf_clearance} -lt 10 ] || [ ${#SecurityTrails} -lt 10 ]; then
        printf "[-] log in to securitytrails.com, then get the cookies SecurityTrails and cf_clearance"
        return 1
    fi
}

function getSubdomains() {
    checkConfigs
    if [ $? = 1 ]; then
        return
    fi
    domainsFile="${1:?missing domains file}"
    subdomainsFile="${2:=subdomains.txt}"

    mkdir -p subdomains
    for domain in $(cat $domainsFile); do
        crt $domain >> subdomains/crt.txt
        securityTrails $domain >> subdomains/securityTrails.txt
        microsoftIntel $domain >> subdomains/microsoftIntel.txt
    done
    amass enum -df $domainsFile -o subdomains/amass_passive.log
    subfinder -all -dL $domainsFile -o subdomains/subfinder.txt

    cat subdomains/amass_passive.log | sed -e 's/\x1b\[[0-9;]*m//g' | grep -E "$(cat $domainsFile | tr '\n' '|' && printf "nonexistzzzzz")" | awk '{print $1}' > subdomains/amass_subdomains.txt 
    cat subdomains/*.txt | sort -u >> $subdomainsFile
}

function crt() {
    domain="${1:?missing domain}"
    curl -s "https://crt.sh/?q=$domain" -H "User-Agent: $userAgent" | grep -iEo "<TD>[^<>]+?$domain|<BR>[^<>]+?$domain" | sed 's/^<..>//g' | sed 's/^\*[.]//g' | sort -u
}

# function theharvester() {
#     domain="${1:?missing domain}"
#     rm -f /tmp/harvester.json
#     cd ~/Tools/theHarvester
#     ./theHarvester.py -d $domain -b binaryedge,censys,rapiddns -f /tmp/harvester >/dev/null
#     cat /tmp/harvester.json | jq -r '.hosts[]' | cut -d: -f1 | sort -u
#     cd - >/dev/null
# }

function microsoftIntel() {
    domain="${1:?missing domain}"
    curl -s "https://prod.eur.ti.trafficmanager.net/api/dns/passive/subdomains/export?query=$domain" -H "User-Agent: $userAgent" -H "authorization: Bearer $microsoftAuthorization" | awk -F, '{print $1}' | tr -d '"' | tail +2 | sed 's/^\*[.]//g'
}

function securityTrails() {
    domain="${1:?missing domain}"
    pages=64
    for ((page=1;page<=$pages;page++));do
        request=$(curl -s "https://securitytrails.com/list/apex_domain/$domain?page=$page" -H "User-Agent: $userAgent" -H "Cookie: cf_clearance=$cf_clearance; SecurityTrails=$SecurityTrails;")
        if [ $page = 1 ]; then
            pages=$(echo $request | grep -iEo 'total_pages":[0-9]+' | sed 's/^.\{13\}//')
        fi
        echo $request | grep -iEo 'dns">[^<]+<' | sed 's/^.\{5\}//g' | sed 's/.$//g'
    done
}

function compileResults() {
    inputFile="${1:=subdomains.txt}"
    resultsFile="${2:=results.csv}"
    rm -f $resultsFile

    for host in $(cat $inputFile | sort -u); do
        checkHostIPs $host | sed "s/^/$(getDomain $host),/" >> $resultsFile
    done
    sort $resultsFile -o $resultsFile
    sed -i "1i domain,host,ip" $resultsFile
}

function nameNotFound() {
    if [ -z "$1" ]; then
        return 0
    fi
    echo "$1" | grep -Eiq 'has no|not found|is handled by 0'
}

function queryDNS() {
    type="$1"
    target="$2"
    host -t $type $target $dnsServer | tail +6 | grep -v ';; '
}

function checkHostIPs() {
    host="$1"

    A=$(queryDNS A $host)
    AAAA=$(queryDNS AAAA $host)

    if ! (nameNotFound "$A"); then
        echo $A | grep -Eo -m1 'address.*' | sed "s/address /$host,/"
    elif ! (nameNotFound "$AAAA"); then
        echo $AAAA | grep -Eo -m1 'address.*' | sed "s/address /$host,/"
    fi
}

OKGREEN='\033[92m'
WARNING='\033[93m'
ENDC='\033[0m'

function checkIndividualTakeover() {
    host="$1"
    CNAME=$(queryDNS CNAME $host)
    NS=$(queryDNS NS $host)
    MX=$(queryDNS MX $host)

    if ! (nameNotFound "$MX"); then         
        for record in $(echo $MX | rev | cut -d' ' -f1 | rev); do
            if [ ! -z "$(checkDomain $record)" ]; then
                echo $OKGREEN"[+] AVAILABLE MX $ENDC"$record" <- "$host
            fi
        done
    fi

    if ! (nameNotFound "$NS"); then         
        for record in $(echo $NS | rev | cut -d' ' -f1 | rev); do
            if [ ! -z "$(checkDomain $record)" ]; then
                echo $OKGREEN"[+] AVAILABLE NS $ENDC"$record" <- "$host
            fi
        done
    fi

    if ! (nameNotFound "$CNAME"); then         
        cname=$(echo $CNAME | tail -1 | rev | cut -d' ' -f1 | rev)
        echo $WARNING"[*] CNAME $ENDC"$host" -> "$cname
        if ! (nameNotFound "$(queryDNS CNAME $cname)"); then
            checkIndividualTakeover $cname
            return
        fi
        if [ ! -z "$(checkDomain $cname)" ]; then
            echo $OKGREEN"[+] AVAILABLE CNAME $ENDC"$cname" <- "$host
        fi
    fi
}

function checkTakeover() {
    inputFile="${1:=subdomains.txt}"
    for host in $(cat $inputFile | sort -u); do
        checkIndividualTakeover "$host"
    done
}

declare -A whoisDict

function checkDomain() {
    domain="$(getDomain $1)"
    A=$(queryDNS A $domain)
    AAAA=$(queryDNS AAAA $domain)
    # if domain not has A or AAAA entry then check whois
    if (nameNotFound "$AAAA") && (nameNotFound "$A"); then
        if [ -z ${whoisDict["$domain"]} ]; then
            whoisDict["$domain"]=$(whois $domain)
        fi
        result=${whoisDict["$domain"]}
        if ( echo $result | grep -Eq '^No match|^NOT FOUND|^Not fo|AVAILABLE|^No Data Fou|has not been regi|No entri' ) || [ $(echo $result | wc -l) -lt 22 ]; then
            echo "$domain available"
        fi
    fi
    
}

function getDomainCore() {
    host="$1"

    if [[ "$host" != *"."*  ]]; then
        echo $host
        return
    fi

    head=$(echo $host | cut -d'.' -f1 )
    tail=$(echo $host | cut -d'.' -f2- )

    for TLD in $TLDs; do
        if [ $tail = $TLD ];then
            echo $host
            return
        fi
    done
    getDomainCore $tail
}

TLDs=()
function getDomain() {
    if [ ${#TLDs[@]} -eq 0 ]; then
        TLDs=( $(curl -s 'https://publicsuffix.org/list/public_suffix_list.dat' | grep -vE '^//' | sort -u) )
    fi
    host="$(echo $1 | tr '[:upper:]' '[:lower:]' | sed 's/[.]*$//' | sed 's/[.]\+/./g')"
    getDomainCore $host
}

clear && cat <<EOF
## get subdomains
$ echo 'example.com' >> targets.txt
$ getSubdomains targets.txt subdomains.txt
    
## (optional) generate a csv with subdomains and ip addresses
$ compileResults subdomains.txt results.csv
## check subdomain takeover (currently via a homemade way)
$ checkTakeover subdomains.txt
EOF
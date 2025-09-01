#!/bin/zsh

##########################
######## SETTINGS ########
##########################

# https://github.com/settings/personal-access-tokens
GITHUB_API_KEY="github..."
# https://cloud.projectdiscovery.io/?ref=api_key
PDCP_API_KEY="..."
# https://securitytrails.com/app/account/credentials
SECURITY_TRAILS_API_KEY="..."
# https://account.shodan.io/
SHODAN_API_KEY="..."
# https://intelx.io/account?tab=developer
INTELX_API_KEY="..."
# ? https://wpscan.com/api
WPSCAN_API_KEY="..."



USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
DNS_SERVER="1.1.1.1"
TMP_PATH=$(mktemp -d --tmpdir=/var/tmp/ --suffix=".bgby")
OKGREEN='\033[92m'
WARNING='\033[93m'
ENDC='\033[0m'




logAndCall discoverSubdomains
logAndCall compileSubdomains
logAndCall analyzeReconResults
logAndCall webScanning
logAndCall spidering
logAndCall quickPortScanning
logAndCall portScanning # requires sudo



#########################
####### FUNCTIONS #######
#########################

function checkRequirements() {
    requiredCommands=(
        'subfinder'         # go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        'shuffledns'        # go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
        'massdns'           # yay -S massdns || (git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install)
        'chaos'             # go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        'httpx'             # go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        'dnsx'              # go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        'cdncheck'          # go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
        'psl'               # pacman -S libpsl || apt install psl
        'gospider'          # GO111MODULE=on go install github.com/jaeles-project/gospider@latest
        'gowitness'         # go install github.com/sensepost/gowitness@latest
        'gobuster'          # go install github.com/OJ/gobuster/v3@latest
        'github-subdomains' # go install github.com/gwen001/github-subdomains@latest
        'subzy'             # go install -v github.com/PentestPad/subzy@latest
        'hashcat'           # pacman -S hashcat || apt install hashcat
        'nmap'              # pacman -S nmap || apt install nmap
        'naabu'             # go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
        'nuclei'            # go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        'wpscan'            # pacman -S wpscan || (apt install ruby-rubygems ruby-dev && gem install wpscan)
    )
    # 's3scanner'         # go install -v github.com/sa7mon/s3scanner@latest
    # dalfox # go install github.com/hahwul/dalfox/v2@latest

    for command in ${requiredCommands[@]}; do
        if [ -z "$(which $command)" ] || [ ! -z "$(which $command | grep 'not found' )" ]; then
            printf "[-] $command is missing...\n"
            return 1
        fi
    done
}

function discoverSubdomains() {
    domainsFile="${1:=scope.txt}"
    subdomainsFile="${2:=subdomains.all.txt}"

    # passive recon
    function checkCrt() {
        domain="${1:?missing domain}"
        curl -s "https://crt.sh/?q=$domain" -H "User-Agent: $USER_AGENT" | grep -iEo "<TD>[^<>]+?$domain|<BR>[^<>]+?$domain" | sed 's/^<..>//g' | sed 's/^\*[.]//g' | sort -u
    }
    mkdir -p subdomains
    for domain in $(cat $domainsFile); do
        checkCrt $domain >> subdomains/crt.txt
        export GITHUB_TOKEN=$GITHUB_API_KEY
        github-subdomains -d $domain -o subdomains/github.$domain.txt
    done
    
    cat <<EOF >$TMP_PATH/provider-config.yaml
securitytrails:
  - $SECURITY_TRAILS_API_KEY
github:
  - $GITHUB_API_KEY
chaos:
  - $PDCP_API_KEY
shodan:
  - $SHODAN_API_KEY
intelx:
  - $INTELX_API_KEY
EOF

    subfinder -all -dL $domainsFile -pc $TMP_PATH/provider-config.yaml -o subdomains/subfinder.$(date +"%s").txt
    export PDCP_API_KEY
    chaos -dL $domainsFile -o subdomains/chaos.txt
    grep '^*.' subdomains/chaos.txt | sed 's/^*.//' | sort -u > subdomains/chaos.wildcard.txt
    sed -i 's/^*.//' subdomains/chaos.txt

    # TODO: more api keys https://docs.google.com/spreadsheets/d/19lns4DUmCts1VXIhmC6x-HaWgNT7vWLH0N68srxS7bI/edit?gid=0#gid=0
    # https://sidxparab.gitbook.io/subdomain-enumeration-guide/introduction/prequisites

    # zone transfer
    function zoneTransfer() {
        domain="${1:?missing domain}"
        for ns in $(host -t NS $domain | grep -o 'name server .*' | awk '{ print $3 }'); do
            host -t AXFR $domain $ns | grep -Ei -o "[a-z0-9.-]*$domain" | tr '[:upper:]' '[:lower:]' | sort -u
        done
    }
    dnsx -axfr -silent -no-color -l $domainsFile -o $TMP_PATH/targets.zonetransfer.txt
    for ztTarget in $(cat $TMP_PATH/targets.zonetransfer.txt); do
        zoneTransfer $ztTarget >> subdomains/zonetransfer.txt
    done

    # bruteforce
    curl -o $TMP_PATH/subdomains-top1million-110000.txt 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt'
    curl -o $TMP_PATH/n0kovo_subdomains_small.txt 'https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/n0kovo_subdomains_small.txt'
    cat $TMP_PATH/subdomains-top1million-110000.txt $TMP_PATH/n0kovo_subdomains_small.txt | sort -u > $TMP_PATH/subdomain.list.txt
    curl -L https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o $TMP_PATH/resolvers.txt
    
    # TODO: treat case where wildcard file is huge
    # TODO: remove all cases that resolve anything
    for domain in $(cat $domainsFile <(echo) subdomains/chaos.wildcard.txt | sort -u); do
        shuffledns -d $domain -w $TMP_PATH/subdomain.list.txt -r $TMP_PATH/resolvers.txt -mode bruteforce -t 1000 -o $TMP_PATH/brute.$domain.txt
        # removing false positives lines from shuffledns output
        grep -i "$domain" $TMP_PATH/brute.$domain.txt > subdomains/brute.$domain.txt

        # removing some \x00 (null) characters from shuffledns output
        sed -i 's/\x00//g' subdomains/brute.$domain.txt
    done

    # merge all subdomains
    cat subdomains/* | tr '[:upper:]' '[:lower:]' | sort -u > $subdomainsFile
}

function compileSubdomains() {
    subdomainsFile="${1:=subdomains.all.txt}"
    resultsFile="${2:=hosts.csv}"

    cat $subdomainsFile | cdncheck -resp -silent -no-color | awk '{print $1, substr($2,2,length($2)-2)}' > $TMP_PATH/hosts.cdn.txt
    cat $subdomainsFile | dnsx -a -aaaa -resp -silent -no-color | awk '!seen[$1]++ {print $1, substr($3,2,length($3)-2) }' > $TMP_PATH/hosts.dnsx.txt
    cat $TMP_PATH/hosts.dnsx.txt | awk '{print $2}' | sort -u | dnsx -resp -silent -no-color -ptr | awk '{print $1, substr($3,2,length($3)-2)}' > $TMP_PATH/hosts.ptr.txt

    IFS=$'\n'
    for subdomainAndIp in $(cat $TMP_PATH/hosts.dnsx.txt); do
        subdomain=$(echo $subdomainAndIp | cut -d' ' -f1)
        ip=$(echo $subdomainAndIp | cut -d' ' -f2)
        domain=$(getDomain $subdomain)
        ptr=$(grep "^$ip " $TMP_PATH/hosts.ptr.txt | awk '{print $2}' | tr '\n' '|' | sed 's/|$//')
        cdn=$(grep "^$subdomain " $TMP_PATH/hosts.cdn.txt | awk '{print $2}')
        line="$domain,$subdomain,$ip,$ptr,$cdn"
        echo $line >> $resultsFile
    done; unset IFS
    sort $resultsFile -o $resultsFile
    sed -i "1i domain,subdomain,ip,ptr,type" $resultsFile
    
    echo "[*] Filter $resultsFile"
    xdg-open $resultsFile
}

function analyzeReconResults() {
    subdomainsFile="${1:=subdomains.all.txt}"
    hostsFile="${2:=hosts.csv}"

    # TAKEOVER
    function checkTakeover() {
        host="$1"
        CNAME=$(queryDNS CNAME $host)
        
        if ! (nameNotFound "$CNAME"); then         
            cname=$(echo $CNAME | tail -1 | rev | cut -d' ' -f1 | rev)
            if ! (nameNotFound "$(queryDNS CNAME $cname)"); then
                checkTakeover $cname
                return
            fi
            if [ ! -z "$(checkDomain $cname)" ]; then
                echo $OKGREEN"[+] AVAILABLE CNAME $ENDC"$cname" <- "$host
            fi
        fi
    }
    
    mkdir -p results
    for host in $(cat $subdomainsFile | sort -u); do
        checkTakeover "$host"
    done > results/takeover.manual.txt

    subzy run --targets $subdomainsFile --hide_fails --vuln --output results/takeover.subzy.txt
    
    # BUCKET
    cat $subdomainsFile > $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr '.' '_' >> $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr '.' '-' >> $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr -d '.' >> $TMP_PATH/hosts.txt
    gobuster s3 -k --wordlist $TMP_PATH/hosts.txt --no-color -o results/buckets.s3.txt

    # GETTING WEB HOSTS
    httpx -p http:80,8080,8000,8008,8888,9090,9091,https:443,8443 -l <(cat $hostsFile | awk -F, '{print $2}') -o web.txt
    filterWebUrls web.txt

    # GETTING WEB SCREENSHOTS
    mkdir -p gowitness; cd $_; gowitness scan file -f ../web.txt --write-db; cd ..

    # GETTING SCANNABLE IP ADDRESSES
    cat $hostsFile | grep -vE ',(waf|cdn)$' | cut -d, -f3 | tail +2 | awk '!x[$0]++' > ips.txt

}

function webScanning() {
    
    # wordpress
    nuclei -silent -l web.txt  -H "User-Agent: $USER_AGENT" -t http/technologies/wordpress-detect.yaml -o $TMP_PATH/wordpress.txt
    cat $TMP_PATH/wordpress.txt | awk '{ print $4 }' | sed 's/\/$//' | sort -u > wordpress.txt
    nuclei -l wordpress.txt  -H "User-Agent: $USER_AGENT" -tags wordpress,wp-plugin -o results/nuclei.wordpress.txt
    for url in $(cat wordpress.txt); do
        wpscan --random-user-agent --disable-tls-checks --enumerate vp --url $url -o results/wpscan.$(url2path $url).txt --api-token $WPSCAN_API_KEY
    done

    nuclei -l web.txt -H "User-Agent: $USER_AGENT" -o results/nuclei.sniper.results.txt -stats -retries 4 -timeout 35 -mhe 999999 -rate-limit 100 -bulk-size 100 \
        -t http/exposures/apis/swagger-api.yaml \
        -t http/exposures/apis/wadl-api.yaml \
        -t http/exposures/apis/wsdl-api.yaml \
        -t http/exposures/configs/exposed-vscode.yaml \
        -t http/exposures/configs/git-config.yaml \
        -t http/exposures/configs/laravel-env.yaml \
        -t http/exposures/configs/phpinfo-files.yaml \
        -t http/exposures/logs \
        -t http/miscellaneous/directory-listing.yaml \
        -t http/misconfiguration/aws/aws-object-listing.yaml \
        -t http/misconfiguration/glpi-directory-listing.yaml \
        -t http/misconfiguration/springboot \
        -t http/takeovers
    
    nuclei -l web.txt -H "User-Agent: $USER_AGENT" -o results/nuclei.gold.results.txt -stats -retries 4 -timeout 35 -mhe 999999 -rate-limit 100 -bulk-size 100 -exclude-severity info -etags wordpress,wp-plugin,tech,ssl -resume nuclei-gold-resume.cfg


    # TODO: CONTENT DISCOVERY
    
    # TODO: more detailed app scan 
    # - sqlmap
    # - dalfox
    # - dt: ?
    # - ssti: ?gossti, ?SSTImap
    # - https://github.com/topics/VULN
}

function spidering() {
    gospider -S web.txt -u web -d 3 -R -o spider
    
    # CHECKING AWS URLS
    grep -Rio -Pa ".{2,30}amazonaws.{2,70}" spider | grep -Eio "[^\"' ]*amazonaws[^\"' ]+" > $TMP_PATH/aws.txt 
    grep -Rio -Pa "aws-s3.{11,70}" spider | grep -Eio "[^\"' ]*amazonaws[^\"' ]+" >> $TMP_PATH/aws.txt
    cat $TMP_PATH/aws.txt | sed 's/^\.//' | sed 's/http[s]\?...//' | sed 's/^\/\///' | sed 's/\/$//' | sed 's/\=1[0-9]\{9,14\}//' | sort -u > results/aws.urls.txt
    # trufflehog s3 --bucket=bucket name

    # CHECKING NEW SUBDOMAINS
    spiderSubdomains=( $(grep -RP "^\[subdomains\]" spider | awk '{print $3}' | sed 's/http[s]\?...//' | sort -u) )    
    for sub in "${spiderSubdomains[@]}"; do
        if ! (grep -q "$sub" subdomains.all.txt); then
            A=$(queryDNS A $sub)
            # if there is A entry
            if ! (nameNotFound "$A"); then
                echo "[*] found new subdomain: $sub"
                # TODO: instead of save, repeat the function 
                echo $sub >> results/new.subdomains.txt
            fi
        fi
    done

    # CHECKING JWT TOKENS
    grep -Eh -Roa "eyJ[^\"' ]{14,2048}" spider | urlDecode | sort -u > results/jwts.txt
    (
        mkdir -p $TMP_PATH/passwords/ && cd $_ && 
        curl -L https://weakpass.com/download/48/10_million_password_list_top_10000.txt.gz --output - | gunzip -c > 10_million_password_list_top_10000.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkc0de.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/xato-net-10-million-passwords.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/scraped-JWT-secrets.txt
        curl -LO https://raw.githubusercontent.com/wallarm/jwt-secrets/refs/heads/master/jwt.secrets.list 
        cat $TMP_PATH/passwords/* | sort -u > $TMP_PATH/secrets.txt
    )
    hashcat -m 16500 results/jwts.txt $TMP_PATH/secrets.txt -o results/hashcat.jwts.txt
    
    # TODO: more analysis and regex. maybe using another tools
    # TODO: check cognito 
}

function quickPortScanning() {
    nmap -Pn -n -v3 --open -iL ips.txt -oG nmap.quick.tcp.txt -p 21,22,23,445,1433,1521,2049,3306,3389,5432,5900
}

function portScanning() {
    sudo -v
    RUNNING=1
    while [ $RUNNING -eq 1 ]; do
        sudo -n true
        sleep 60
    done 2>/dev/null &

    sudo nmap -sS -Pn -n -v3 --open -T4 -iL ips.txt -oG nmap.top100.tcp.txt
    sudo nmap -sUV -v3 --top-ports 23 --open -iL ips.all.txt -oG nmap.udp.txt
    sudo chown $USER:$USER nmap.*.txt

    RUNNING=0
}

# - # - # - # - # - # - # - # - # - # - # - # - #

#  aux functions

# - # - # - # - # - # - # - # - # - # - # - # - #

function logAndCall() {
    local functionName="$1"
    echo "starting $functionName: $(date)" >> /var/tmp/log.txt
    $functionName
    if [ $? -ne 0 ]; then
        echo "[-] $functionName failed" >> /var/tmp/log.txt
        exit 1
    fi
    echo "finished $functionName: $(date)" >> /var/tmp/log.txt
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
    host -t $type $target $DNS_SERVER | tail +6 | grep -v ';; '
}

declare -A whoisDict

function checkDomain() {
    domain="$(getDomain $1)"
    # exception for some domains to avoid false positives checking subdomain takeover
    if (echo "$domain" | grep -qi akamaiedge.net); then
        return
    fi
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

function getDomain() {
    psl -b --print-reg-domain "$1"
}

function filterWebUrls() {
    input_file="$1"
    output_file=$(mktemp)
    tmp_python_script=$(mktemp)
    cat > "$tmp_python_script" << 'EOF'
import sys
def filter_urls(input_file, output_file):
    url_map = {}
    with open(input_file, "r") as f:
        for line in f:
            url = line.strip()
            normalized = url.replace("http://", "").replace("https://", "")
            if url.startswith("https"):
                url_map[normalized] = "https"
            elif normalized not in url_map:
                url_map[normalized] = "http"
    with open(output_file, "w") as f:
        for url, scheme in url_map.items():
            f.write(f"{scheme}://{url}\n")
if __name__ == "__main__":
    filter_urls(sys.argv[1], sys.argv[2])
EOF
    python3 "$tmp_python_script" "$input_file" "$output_file"
    mv $output_file $input_file
    rm -f "$tmp_python_script"
}

function urlDecode() {
    python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));"
}

function url2path() {
    echo $1 | sed 's/^http[s]\?...//' | sed 's/\//_/g'
}

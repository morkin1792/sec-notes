#!/bin/zsh

# TODO: look for more templates
# TODO: look for similar projects (ex: NucleiFuzzer)


CONFIG_FILE="$HOME/.bgby.yaml"
TMP_PATH=$(mktemp -d --tmpdir=/var/tmp/ -t bgby_$(date +"%Y.%m.%d_%H:%M:%S")_XXXXXXXX)


if [ -z $ZSH_VERSION ]; then
    printf "$(hostname): Oops, this script requires zsh! \n$(whoami): Why?\n$(hostname): Well... because it is annoying to support a lot of different shells, and I use zsh :) \n$(whoami): You convinced me, how can I install zsh? \n$(hostname): 'pacman -S zsh' or 'apt install zsh', but you have to customize it also (check: https://itsfoss.com/zsh-ubuntu/ and https://github.com/morkin1792/mylinux/blob/master/zsh/zshrc). Otherwise, you will hate it! \n"
    # you can comment the following line if you want to use another shell, but I will not support it :)
    exit 1
fi

function checkRequirements() {
    requiredCommands=(
        'shuf'              # coreutils
        'whois'             # pacman -S whois || apt install whois
        'jq'                # pacman -S jq || apt install jq
        'yq'                # pacman -S yq || apt install yq
        'subfinder'         # go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        'shuffledns'        # go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
        'massdns'           # yay -S massdns || (git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install)
        'chaos'             # go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        'httpx'             # go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        'dnsx'              # go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        'cdncheck'          # go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
        'psl'               # pacman -S libpsl || apt install psl
        'katana'            # CGO_ENABLED=1 go install github.com/projectdiscovery/katana/cmd/katana@latest
        'gospider'          # go install github.com/jaeles-project/gospider@latest
        'gitleaks'          # pacman -S gitleaks || (git clone https://github.com/gitleaks/gitleaks.git; cd gitleaks; make build)
        'nipejs'            # go install go install github.com/i5nipe/nipejs/v2@latest
        'trufflehog'        # 
        'gowitness'         # go install github.com/sensepost/gowitness@latest (&& apt install chromium)
        'feroxbuster'       # yay -S feroxbuster-bin || cargo install feroxbuster || https://github.com/epi052/feroxbuster/releases
        'gobuster'          # go install github.com/OJ/gobuster/v3@latest
        'github-subdomains' # go install github.com/gwen001/github-subdomains@latest
        'subzy'             # go install -v github.com/PentestPad/subzy@latest
        'hashcat'           # pacman -S hashcat || apt install hashcat
        'nmap'              # pacman -S nmap || apt install nmap
        'nuclei'            # go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        'afrog'             # go install -v github.com/zan8in/afrog/v3/cmd/afrog@latest
        'wpscan'            # pacman -S wpscan || (apt install ruby-rubygems ruby-dev && sudo gem install wpscan)
        'gau'               # go install github.com/lc/gau/v2/cmd/gau@latest
        'waymore'           # pip install waymore
        'gf'                # go install -v github.com/tomnomnom/gf@latest && git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
        'uro'               # pipx install uro
        'dalfox'            # go install github.com/hahwul/dalfox/v2@latest
    )
    # 'naabu'             # go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest (&& apt install -y libpcap-dev)
    # 's3scanner'         # go install -v github.com/sa7mon/s3scanner@latest

    for command in ${requiredCommands[@]}; do
        if [ -z "$(which $command)" ] || [ ! -z "$(which $command | grep 'not found' )" ]; then
            printf "[-] $command is missing...\n"
            return 1
        fi
    done
}

function checkConfigFile() {
    local file="$CONFIG_FILE"

    if [ ! -f "$file" ]; then
        local template='# bgby config file
variables:
    USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/333.0.0.0 Safari/537.36"
    CUSTOM_WORDLIST_PER_HOST_LIMIT: 5000  # maximum number of lines per host for custom wordlists

apikeys:
    ## source:    https://securitytrails.com/app/account/credentials
    ## quota:     50 reqs/month (https://securitytrails.com/app/account/quota)
    ## obs:       long reset time + small quota, ⚠️ consider adding multiple keys
    securitytrails: [
        "...",
        "..."
    ]

    ## source:    https://account.shodan.io/#:~:text=Show
    ## quota:     100 reqs/month
    ## obs:       long reset time, ⚠️ consider adding multiple keys
    shodan: []

    ## source:    https://accounts.censys.io/settings/personal-access-tokens/#:~:text=Create%20New%20Token
    ## quota:     100 reqs/month (https://accounts.censys.io/settings/billing/plan)
    ## obs:       long reset time, ⚠️ consider adding multiple keys
    censys: []

    ## source:    https://github.com/settings/personal-access-tokens#:~:text=Generate%20new%20token
    ## quota:     10 reqs/min for the search code endpoint (https://docs.github.com/en/rest/search/search?apiVersion=2022-11-28#rate-limit#:~:text=10%20requests%20per%20minute)
    ## obs:       small quota, ⚠️ consider adding multiple keys
    github: []

    ## source:    https://www.virustotal.com/gui/settings#:~:text=API%20Key
    ## quota:     supposedly 4 reqs/min (https://docs.virustotal.com/reference/public-vs-premium-api)
    ## obs:       supposedly small quota, however in practice it seems way higher
    virustotal: []

    ## source:    https://cloud.projectdiscovery.io/settings/api-key
    ## quota:     60 reqs/min/ip (https://docs.projectdiscovery.io/opensource/chaos/running#notes) 
    ## obs:       only one key is supported
    chaos: 
        - ""

    ## source:    https://user.whoisxmlapi.com/settings/general/#:~:text=API%20key
    ## quota:     500 reqs/month (https://user.whoisxmlapi.com/products)
    whoisxmlapi: []

    ## source:    https://intelx.io/account?tab=developer#:~:text=Key
    ## quota:     50 reqs/day (https://intelx.io/product#:~:text=Free%20Tiers)
    intelx: []

    ## source:    https://sslmate.com/account/api_keys
    ## quota:     75 reqs/min (https://sslmate.com/pricing/ct_search_api)
    certspotter: []

    ## source:    https://otx.alienvault.com/settings#:~:text=OTX%20Key
    ## quota:     10000 reqs/hour (https://levelblue.com/blogs/security-essentials/the-upgraded-alienvault-otx-api-ways-to-score-swag#:~:text=requests%20per%20hour)
    alienvault: 
        - ""

    ## source:    https://wpscan.com/profile/
    ## quota:     25 reqs/day (https://wpscan.com/pricing/#:~:text=calls%20per%20day) 
    wpscan: []

    ## source:    https://urlscan.io/user/profile/
    ## quota:     120 reqs/min (https://urlscan.io/user/quotas/#:~:text=Search%20Requests)
    ## obs:       only one key is supported
    urlscan: 
        - ""

'
        printf "%s\n" "$template" > "$file"
        chmod 600 "$file"
        echo "[*] Created config file: $file"
    fi
    # loading variables
    while read -r var; do
        eval $var
    done < <(yq '.variables' "$file" -j -M --indent 0 | tail +2 | head -n -1 | sed 's/^"/export /g' | sed 's/": /=/g' | sed 's/,$//g')

    # setting default values if not defined
    if [ -z "$USER_AGENT" ]; then
        USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/333.0.0.0 Safari/537.36"
    fi
    if [ -z "$CUSTOM_WORDLIST_PER_HOST_LIMIT" ]; then
        CUSTOM_WORDLIST_PER_HOST_LIMIT=5000
    fi

    # checking api keys
    if yq -e '.apikeys[] | select(length == 0)' "$file" >/dev/null; then
        echo -e "[-] ⚠️ Some API keys are empty, to have better results, it is IMPORTANT to fill in ALL API keys in $file\n -> Also consider adding multiple API keys \n -> AT LEAST for \"securitytrails\" and \"github\"\n"
        # read "choice?[*] Do you want to exit now to fill the file? (Y/n): "
        # if [[ "$choice" != "n" && "$choice" != "N" ]]; then
        #     exit 1
        # fi
    fi

    for ghToken in $(yq -r '.apikeys.github[]' "$file"); do
        if [ $(curl https://api.github.com -H "Authorization: Bearer $ghToken" -so /dev/null -w "%{http_code}") -eq 401 ]; then
            echo "[-] ⚠️ GitHub API key expired (or invalid). To have better results, update the key $ghToken in $file"
        fi
    done
}
checkRequirements
checkConfigFile

echo Using $TMP_PATH as temporary space

local welcomeMsg="
logAndCall subdomainDiscovery
logAndCall subdomainCompilation
logAndCall reconAnalysis
logAndCall vulnScanning
logAndCall spidering
# logAndCall customVulnScanning
# logAndCall contentDiscovery
logAndCall quickPortScanning
logAndCall portScanning # requires sudo
"
printf "%s\n" "$welcomeMsg"

function subdomainDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    subdomainsFile="${2:=subdomains.all.txt}"

    passiveSubdomainDiscovery $domainsFile
    activeSubdomainDiscovery $domainsFile
    # merge all subdomains
    cat subdomains/* | sed 's/^[.-]//g' | tr '[:upper:]' '[:lower:]' | sort -u > $subdomainsFile
}

function passiveSubdomainDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile

    bigNumberOfDomains=false
    if [ $(wc -l < $domainsFile) -gt 20 ]; then
        bigNumberOfDomains=true
        echo "[*] ⚠️ Detected a significant number of domains, some tools/providers will be limited to avoid time and quota issues"
    fi
    
    function checkCrt() {
        domain="${1:?missing domain}"
        curl -s "https://crt.sh/?q=$domain" -H "User-Agent: $USER_AGENT" | grep -iEo "<TD>[^<>]+?$domain|<BR>[^<>]+?$domain" | sed 's/^<..>//g' | sort -u
    }
    mkdir -p subdomains
    for domain in $(cat $domainsFile); do
        checkCrt $domain >> subdomains/crt.txt
        export GITHUB_TOKEN=$(yq -r '.apikeys.github[]' "$CONFIG_FILE" | tr '\n' ',' | sed 's/,$//')
        github-subdomains -d $domain -o subdomains/github.$domain.txt >> $TMP_PATH/github-subdomains.output.txt
        if [ $bigNumberOfDomains = false ]; then
            # required for rate limiting, but ignored if there are many domains
            sleep 60
        fi
    done
    grep '^*.' subdomains/crt.txt | sed 's/^*.//' | sort -u > subdomains/crt.tls.wildcard.txt
    sed -i 's/^*.//' subdomains/crt.txt

    cat $TMP_PATH/github-subdomains.output.txt | grep https://github.com | awk '{ print $2}' | sort -u > github.urls.txt
    #TODO: add more github url finder tools (maybe search people using nodes) and repo analysis
    
    export PDCP_API_KEY=$(yq -y '.apikeys.chaos' $CONFIG_FILE | sed 's/^- //' | head -1)
    chaos -dL $domainsFile -o subdomains/chaos.txt
    grep '^*.' subdomains/chaos.txt | sed 's/^*[.]//' | sort -u > subdomains/chaos.tls.wildcard.txt
    sed -i 's/^*[.]//' subdomains/chaos.txt


    yq -y '.apikeys' "$CONFIG_FILE" > "$TMP_PATH/provider-config.yaml"
    chmod 600 "$TMP_PATH/provider-config.yaml"
    extraParam=""
    if [ $bigNumberOfDomains = true ]; then
        # if there are many domains, disable some providers to avoid end of month quota issues
        extraParam="-es securitytrails,censys,shodan,whoisxmlapi"
    fi
    # apparently rls is not working at all (https://github.com/projectdiscovery/subfinder/issues/1434), but it is here for when they fix it
    subfinder -all -dL $domainsFile -pc $TMP_PATH/provider-config.yaml -rls "censys=1/s,virustotal=1/s,intelx=2/s,certspotter=1/s,alienvault=10/s" -o subdomains/subfinder.$(date +"%s").txt $extraParam

    local gau_config="
threads = 2
verbose = false
retries = 15
subdomains = true
parameters = false
providers = [\"wayback\",\"commoncrawl\",\"otx\",\"urlscan\"]
blacklist = []
json = false

[urlscan]
  apikey = \"$(yq -y '.apikeys.urlscan' $CONFIG_FILE | sed 's/^- //' | head -1)\"

[filters]
  from = \"\"
  to = \"\"
  matchstatuscodes = []
  matchmimetypes = []
  filterstatuscodes = []
  filtermimetypes = [\"image/png\", \"image/jpg\", \"image/svg+xml\"]
"
    printf "%s\n" "$gau_config" > "$TMP_PATH/gau.toml"
    chmod 600 "$TMP_PATH/gau.toml"

    # passive url gathering
    cat $domainsFile | gau --config $TMP_PATH/gau.toml --subs --o $TMP_PATH/gau.output.txt
    mkdir -p pages/waymore
    waymore -i $domainsFile -lcc 1 -mode B -oU $TMP_PATH/waymore.output.urls -oR pages/waymore
    domains="$(cat $domainsFile | sed '/^$/d' | tr '\n' '|' | sed 's/\./\\./g' | sed 's/|$//')"
    grep -Eih "[^/:>\"\`( =@]*($domains)[^><)\`\" ;,\!]*" -Ro pages | tr '[:upper:]' '[:lower:]' | sed 's/\\//g' | sed "s/'.\?$//g" | sed 's/[:]\(80\|443\)\(\/\|\?\)/\2/g' | sed 's/[:]\(80\|443\)$//g' | sed 's/\/$//g' | sort -u | sed 's/^/https:\/\//' > $TMP_PATH/waymore.manual.urls
    sort -u $TMP_PATH/gau.output.txt $TMP_PATH/waymore.output.urls $TMP_PATH/waymore.manual.urls > urls.passive.txt
    # extracting subdomains from urls
    cat urls.passive.txt | awk -F/ '{print $3}' | sed 's/:[0-9]\+$//' | sed 's/^[.]*//' | sed 's/^\(%[0-9][0-9]\)*//' | sed 's/\?.*//' | sort -u > subdomains/gau_waymore.txt
}

function activeSubdomainDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    
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

    # getting dns wordlist
    curl -o $TMP_PATH/services-names.txt -L 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/services-names.txt'
    curl -o $TMP_PATH/subdomains-top1million-110000.txt -L 'https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt'
    curl -o $TMP_PATH/n0kovo_subdomains_small.txt -L 'https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/refs/heads/main/n0kovo_subdomains_small.txt'
    cat $TMP_PATH/services-names.txt $TMP_PATH/subdomains-top1million-110000.txt $TMP_PATH/n0kovo_subdomains_small.txt | sort -u > $TMP_PATH/subdomain.list.txt

    # getting dns resolvers
    curl -L https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt -o $TMP_PATH/resolvers.txt

    # preparing dns targets
    cat $domainsFile > $TMP_PATH/brute.dns.potential.txt
    echo >> $TMP_PATH/brute.dns.potential.txt
    cat subdomains/*.tls.wildcard.txt >> $TMP_PATH/brute.dns.potential.txt

    # removing crazy dns wildcards
    awk '!seen[$0]++' $TMP_PATH/brute.dns.potential.txt | sed '/^$/d' > $TMP_PATH/brute.dns.potential.uniq.txt
    sed -i 's/^/nonexist.iuygfcvbnjk./' $TMP_PATH/brute.dns.potential.uniq.txt
    echo 'makingsurethefileisnotempty' > $TMP_PATH/brute.dns.removed.txt
    dnsx -a -silent -no-color -l $TMP_PATH/brute.dns.potential.uniq.txt -o $TMP_PATH/brute.dns.removed.txt
    awk -F, 'NR==FNR { keys[$1]; next } !($1 in keys)' $TMP_PATH/brute.dns.removed.txt  $TMP_PATH/brute.dns.potential.uniq.txt >  $TMP_PATH/brute.dns.targets.txt
    sed -i 's/^nonexist.iuygfcvbnjk\.//' $TMP_PATH/brute.dns.targets.txt

    # bruting dns targets
    for domain in $(cat $TMP_PATH/brute.dns.targets.txt); do
        shuffledns -d $domain -w $TMP_PATH/subdomain.list.txt -r $TMP_PATH/resolvers.txt -mode bruteforce -t 1000 -o $TMP_PATH/brute.$domain.txt
        # removing false positives lines from shuffledns output
        grep -i "$domain" $TMP_PATH/brute.$domain.txt > subdomains/brute.$domain.txt

        # removing some \x00 (null) characters from shuffledns output
        sed -i 's/\x00//g' subdomains/brute.$domain.txt
    done
}

function subdomainCompilation() {
    subdomainsFile="${1:=subdomains.all.txt}"
    resultsFile="${2:=hosts.csv}"

    rm -f ${TMP_PATH:?}/dnsx.subdomains.json
    dnsx -silent -a -aaaa -cname -ns -mx -rcode noerror,nxdomain,refused -json -l $subdomainsFile -o $TMP_PATH/dnsx.subdomains.json >/dev/null
    cat $TMP_PATH/dnsx.subdomains.json | jq 'select (.a != null) | .host + " " + .a[0]' -r > $TMP_PATH/dnsx.hosts.a.txt
    cat $TMP_PATH/dnsx.subdomains.json | jq 'select (.ns != null) | .host + " " + .ns[0]' -r > $TMP_PATH/dnsx.hosts.ns.txt

    cat $TMP_PATH/dnsx.hosts.a.txt | awk '{print $2}' | sort -u | cdncheck -resp -silent -no-color | awk '{print $1, substr($2,2,length($2)-2)"_"substr($3,2,length($3)-2) }' > $TMP_PATH/hosts.cdn.txt
    cat $TMP_PATH/dnsx.hosts.a.txt | awk '{print $2}' | sort -u | dnsx -resp -silent -no-color -ptr -asn -json | jq -r '(.host) + " " + (.ptr[0] // "null") + " " + (.asn["as-number"] // "null") + "_" + ((.asn["as-name"] // "null")| gsub(" "; "_"))' > $TMP_PATH/hosts.ptr_asn.txt


    rm -f ${resultsFile:?}
    while read -r subdomain ip; do
        domain=$(getDomain $subdomain)
        asn=$(grep "^$ip " $TMP_PATH/hosts.ptr_asn.txt | awk '{print $3}' | head -1)
        cdn=$(grep "^$ip " $TMP_PATH/hosts.cdn.txt | awk '{print $2}')
        ptr=$(grep "^$ip " $TMP_PATH/hosts.ptr_asn.txt | awk '{print $2}' | tr '\n' '|' | sed 's/|$//')
        ns=$(grep "^$subdomain " $TMP_PATH/dnsx.hosts.ns.txt | awk '{print $2}' | head -1)
        line="$domain,$subdomain,$ip,${asn:-null},${cdn:-null},${ptr:-null},${ns:-null}"
        echo $line >> $resultsFile
    done < $TMP_PATH/dnsx.hosts.a.txt
    sort $resultsFile -o $resultsFile
    sed -i "1i domain,subdomain,ip,asn,cdn,ptr,ns" $resultsFile
    
    echo "[*] You may want to filter $resultsFile"
    # xdg-open $resultsFile
}

function reconAnalysis() {
    subdomainsFile="${1:=subdomains.all.txt}"
    hostsFile="${2:=hosts.csv}"
    rangesFile="${3:=ranges.txt}"
    # output files
    webAllFile="${4:=web.all.txt}"
    webFilteredFile="${5:=web.filtered.txt}"
    ipsFile="${6:=ips.txt}"

    mkdir -p results

    function checkUnregisteredTakeover() {
        local subdomainsFile="$1"

        if [ ! -f "$TMP_PATH/dnsx.subdomains.json" ]; then
            dnsx -silent -a -aaaa -cname -ns -mx -rcode noerror,nxdomain,refused -json -l $subdomainsFile -o $TMP_PATH/dnsx.subdomains.json >/dev/null
        fi
        # cname
        cat $TMP_PATH/dnsx.subdomains.json | jq -r 'select (.cname != null and .status_code == "NXDOMAIN") | .host + " " + .cname[-1]' | grep -vE 'elb[.]amazonaws[.]com$' > $TMP_PATH/dnsx.cname.nxdomain.txt
        while read -r initialHost finalHost; do
            if (getDomain $finalHost | dnsx -silent -rcode nxdomain | grep -q NXDOMAIN); then
                echo "[CNAME -> NXDOMAIN] $initialHost -> $finalHost"
            fi
        done < $TMP_PATH/dnsx.cname.nxdomain.txt

        # alias
        # if is in rcode is NOERROR and has no A, AAAA or CNAME, then potential alias
        cat $TMP_PATH/dnsx.subdomains.json | jq -r 'select (.a == null and .cname == null and .aaaa == null and .status_code == "NOERROR") | .host' > $TMP_PATH/alias.potential.txt
        # TODO: check ip address history and try to figure out the service

        # ns
        cat $TMP_PATH/dnsx.subdomains.json | jq -r '
        select(.ns and (.ns | map(select(. != "")) | length > 0))
        | .host as $h
        | .ns[]
        | select(. != "")
        | "\($h) \(.)"
        ' > $TMP_PATH/dnsx.ns.txt
        echo > $TMP_PATH/ns.only.txt
        while read -r nserver; do
            getDomain $nserver >> $TMP_PATH/ns.only.txt
        done < <(cat $TMP_PATH/dnsx.ns.txt | awk '{print $2}' | sort -u | sed '/^$/d')
        sort -u $TMP_PATH/ns.only.txt | dnsx -silent -rcode nxdomain > $TMP_PATH/ns.nxdomain.txt
        for nsnx in $(cat $TMP_PATH/ns.nxdomain.txt | awk '{print $1}'); do
            grep -i "$nsnx" $TMP_PATH/dnsx.ns.txt | sed 's/ / -> /g' | sed 's/^/[NS -> NXDOMAIN] /g'
        done
        # mx
        cat $TMP_PATH/dnsx.subdomains.json | jq -r '
            select(.mx and (.mx | map(select(. != "")) | length > 0))
            | .host as $h
            | .mx[]
            | select(. != "")
            | "\($h) \(.)"
        ' > $TMP_PATH/dnsx.mx.txt
        echo > $TMP_PATH/mx.only.txt
        while read -r mx; do
            getDomain $mx >> $TMP_PATH/mx.only.txt
        done < <(cat $TMP_PATH/dnsx.mx.txt | awk '{print $2}' | sort -u | sed '/^$/d')
        sort -u $TMP_PATH/mx.only.txt | dnsx -silent -rcode nxdomain > $TMP_PATH/mx.nxdomain.txt
        for mxnx in $(cat $TMP_PATH/mx.nxdomain.txt | awk '{print $1}'); do
            grep -i "$mxnx" $TMP_PATH/dnsx.mx.txt | sed 's/ / -> /g' | sed 's/^/[MX -> NXDOMAIN] /g'
        done
    }
    
    checkUnregisteredTakeover $subdomainsFile > results/takeover.unregistered.potential.txt

    subzy run --targets $subdomainsFile --hide_fails --vuln --output results/takeover.subzy.txt
    
    # BUCKET
    cat $subdomainsFile > $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr '.' '_' >> $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr '.' '-' >> $TMP_PATH/hosts.txt
    cat $subdomainsFile | tr -d '.' >> $TMP_PATH/hosts.txt
    gobuster s3 -k --wordlist $TMP_PATH/hosts.txt --no-color -o results/buckets.s3.txt

    # GETTING WEB HOSTS
    awk -F, '{print $2}' $hostsFile > $TMP_PATH/web.potential.txt
    if [ -s $rangesFile ]; then
        echo "[*] Adding IP ranges from $rangesFile to web potential targets"
        cut -d, -f2 $rangesFile | prips >> $TMP_PATH/web.potential.txt
    fi

    httpx -p http:80,8080,8000,8008,8888,9090,9091,https:443,8443 -fr -l $TMP_PATH/web.potential.txt -json -o web.all.json
    jq -r '.url' web.all.json | sed 's/[:]\(80\|443\)$//g' > $webAllFile
    filterWebUrls $webAllFile
    # TODO: check preference for https
    jq -r '.url + "," + (.status_code|tostring) + "," + (.title//"") + "," + (.words|tostring) + "," + (.a|sort|tostring)' web.all.json | sort -ur | awk -F, '!seen[$2 FS $3 FS $4 FS $5]++ { print $1 }' | sed 's/[:]\(80\|443\)$//g' > $webFilteredFile

    # GETTING WEB SCREENSHOTS
    mkdir -p gowitness; cd $_; gowitness scan file -f ../$webAllFile --write-db; cd ..

    # GETTING SCANNABLE IP ADDRESSES
    awk -F, '$5 !~ /(cdn|waf)/ { print $3 }' $hostsFile > $TMP_PATH/ips.txt
    if [ -s $rangesFile ]; then
        echo "[*] Adding IP ranges from $rangesFile to scannable IPs"
        cut -d, -f2 $rangesFile | prips >> $TMP_PATH/ips.txt
    fi
    awk '!x[$0]++' $TMP_PATH/ips.txt > $ipsFile
}

function vulnScanning() {
    webAllFile="${1:=web.all.txt}"
    webFilteredFile="${2:=web.filtered.txt}"

    mkdir -p results

    # wordpress
    nuclei -silent -l $webAllFile -H "User-Agent: $USER_AGENT" -t http/technologies/wordpress-detect.yaml -o $TMP_PATH/wordpress.txt
    cat $TMP_PATH/wordpress.txt | awk '{ print $4 }' | sed 's/\/$//' | sort -u > wordpress.txt
    if [ -s wordpress.txt ]; then
        wpApiKeys=$(yq -y '.apikeys.wpscan' "$CONFIG_FILE" | sed 's/- //')
        for url in $(cat wordpress.txt); do
            wpscan --random-user-agent --disable-tls-checks --enumerate vp --url $url -o results/wpscan.$(url2path $url).txt --api-token $(echo $wpApiKeys | shuf -n1)
        done
        nuclei -silent -l wordpress.txt -H "User-Agent: $USER_AGENT" -tags wordpress,wp-plugin -o results/nuclei.wordpress.txt
    fi

    nuclei -l $webAllFile -H "User-Agent: $USER_AGENT" -o results/nuclei.sniper.results.txt -stats -retries 4 -timeout 35 -mhe 999999 -rate-limit 100 -bulk-size 100 \
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
    
    nuclei -l $webFilteredFile -H "User-Agent: $USER_AGENT" -o results/nuclei.gold.results.txt -stats -retries 4 -timeout 35 -mhe 999999 -rate-limit 100 -bulk-size 100 -exclude-severity info -etags wordpress,wp-plugin,tech,ssl -resume nuclei-gold-resume.cfg
    afrog -T $webFilteredFile -H "User-Agent: $USER_AGENT" -mhe 10 -o results/afrog.results.html
    # TODO: ?ceye api key
    # consider Retire.js
}

function spidering() {
    webFilteredFile="${1:=web.filtered.txt}"
    subdomainsFile="${2:=subdomains.all.txt}"
    domainsFile="${3:=scope.txt}"
    # output files
    urlsFile="${3:=urls.all.txt}"
    mkdir -p results

    mkdir -p pages/katana
    katana -list $webFilteredFile -H "User-Agent: $USER_AGENT" -d 4 -jsl -jc -kf all -aff -fx -hl -xhr -sr -srd pages/katana -o urls.katana.txt >/dev/null
    
    gospider -S $webFilteredFile -u web -d 3 --js --subs --sitemap --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)" -R -o pages/gospider
    domains="$(cat $domainsFile | sed '/^$/d' | tr '\n' '|' | sed 's/\./\\./g' | sed 's/|$//')"
    grep -Eo -- "http[^ ]+($domains)[^ ]+" pages/gospider > urls.gospider.txt

    sort -u urls.katana.txt urls.gospider.txt urls.passive.txt > $urlsFile
    
    # CHECKING AWS URLS
    grep -Rioh -Pa "[^\"'>= ]{0,70}(amazonaws|aws-s3)[^\"' ]{2,70}" pages | sed 's/^\.//' | sed 's/http[s]\?...//' | sed 's/^\/\///' | sed 's/\/$//' | sed 's/\=1[0-9]\{9,14\}//' | sort -u > results/aws.urls.txt
    # trufflehog s3 --bucket=bucket name

    # CHECKING NEW SUBDOMAINS
    awk 'NR==FNR { keys[$1]; next } !($1 in keys)' $subdomainsFile <(sed 's/http[s]\?...//' urls.katana.txt | sed 's/\(\/.*\|.*@\)//g' | sort -u) > results/subdomains.new.txt
    # TODO: instead of just saving, repeat everything from subdomainCompilation

    ## pentesting only
    grep -REi 'http[s]?://[^/"\?]+' -aoh pages | sed 's/^http[s]\?:\/\///' | grep -vE 'facebook|google|youtube|instagram|twitter|apple|pinterest|tiktok|reactjs\.org|nextjs\.org|twimg\.com|tumblr\.com|pxf\.io|scene7\.com|imgix\.net|medium\.com|wordpress\.com|shopify\.com|sentry\.io|giphy\.com|cloudfront\.net|hulu\.com' | sed '/^.\{64,\}$/d' | sort -u > results/seeds.potential.txt

    # CHECKING JWT TOKENS
    grep -Eh -Roa "eyJ[^\"' ]{14,2048}" pages | urlDecode | sort -u > results/jwts.txt
    if [ ! -f $TMP_PATH/secrets.txt ]; then (
        mkdir -p $TMP_PATH/passwords/ && cd $_ && 
        curl -L https://weakpass.com/download/48/10_million_password_list_top_10000.txt.gz --output - | gunzip -c > 10_million_password_list_top_10000.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkc0de.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/xato-net-10-million-passwords.txt
        curl -LO https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/scraped-JWT-secrets.txt
        curl -LO https://raw.githubusercontent.com/wallarm/jwt-secrets/refs/heads/master/jwt.secrets.list 
        cat $TMP_PATH/passwords/* | sort -u > $TMP_PATH/secrets.txt
    ) fi
    hashcat -m 16500 results/jwts.txt $TMP_PATH/secrets.txt -o results/jwts.cracked.txt
    #hashcat results/jwts.txt --show
    
    gitleaks dir pages -f csv -r results/secrets.gitleaks.csv
    trufflehog filesystem ./pages --json > results/secrets.truffle.json
    nipejs -d pages -json > results/secrets.nipejs.json

    # TODO: check cognito 
}

function customVulnScanning() {
    targetFile="${1:=web.filtered.txt}"
    urlsFile="${2:=urls.all.txt}"
    
    # TODO: consider POST requests 
    #    - ?llama, gpt4all

    # TODO: more checks
    # - sqlmap
    # - dt: ?
    # - ssti: ?gossti, ?SSTImap
    # - ?ssrf: ?SSRFmap
    # - ?ci: commix
    # - https://github.com/topics/VULN

    echo "[*] Cleaning endpoints..."    
    cat $urlsFile \
    | grep -Eiv 'js\?[a-z]+=[0-9]{7,}' \
    | uro | sort -u > $TMP_PATH/endpoints.potential.txt
    awk -F/ '{print $3}' $TMP_PATH/endpoints.potential.txt | sort -u | httpx -mc 200,201,202,203,204,205,206,207,208,301,302,307,308,400,401,403,404,405,406,410,411,412,415,423 -silent | awk -F/ '{print $3}' | sort -u > $TMP_PATH/domains.alive.txt
    awk -F/ 'NR==FNR { hosts[$0]; next } { split($0, a, "/"); if (a[3] in hosts) print $0 }' $TMP_PATH/domains.alive.txt <(sed 's/[:]\(80\|443\)\(\/\|\?\)/\2/g' $TMP_PATH/endpoints.potential.txt) > $TMP_PATH/endpoints.txt
    echo "[*] Total unique endpoints to analyze: $(wc -l < $TMP_PATH/endpoints.txt)"

    mkdir -p results/dast
    
    # Reflected XSS
    printf "%s %s\n" "XSS nuclei" "$(date)" >> /tmp/log
    grep '\?' $TMP_PATH/endpoints.txt \
    | nuclei -dast -tags xss -H "User-Agent: $USER_AGENT" -silent -o results/dast/xss.nuclei.txt

    # printf "%s %s\n" "XSS dalfox B" "$(date)" >> /tmp/log
    # cat $TMP_PATH/endpoints.txt \
    # | gf xss \
    # | dalfox pipe --user-agent "$USER_AGENT" --skip-mining-all --detailed-analysis --deep-domxss --context-aware --waf-evasion --timeout 11 --delay 300 --follow-redirects --max-cpu 2 --silence -o results/dast/xss.dalfox.B.txt

    # printf "%s %s\n" "XSS dalfox A" "$(date)" >> /tmp/log
    # grep '\?' $TMP_PATH/endpoints.txt \
    # | dalfox pipe --user-agent "$USER_AGENT" --skip-xss-scanning --timeout 8 --delay 100 --follow-redirects --max-cpu 3 -o results/dast/xss.dalfox.A.txt

    printf "%s %s\n" "XSStrike + params" "$(date)" >> /tmp/log
    while read -r url; do
        echo "[*] Scanning $url"
        # TODO: pipx install xsstrike
        xsstrike --url "$url" --headers "User-Agent: $USER_AGENT" --log-file "results/dast/xss.xsstrike.log.$(url2path $url).txt" > results/dast/xss.xsstrike.out.$(url2path $url).txt
    done < <(grep '\?' $TMP_PATH/endpoints.txt)

    # SQLi
    printf "%s %s\n" "sqli" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt \
    | gf sqli \
    | nuclei -dast -tags sqli -H "User-Agent: $USER_AGENT" -silent -o results/dast/sqli_potential.txt
    # pipx install git+https://github.com/r0oth3x49/ghauri.git
    # ghauri -m <(cat $TMP_PATH/endpoints.txt | gf sqli) --random-agent --batch

    # LFI/RFI
    printf "%s %s\n" "lfi" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt | gf lfi | nuclei -dast -tags lfi,rfi -H "User-Agent: $USER_AGENT" -silent -o results/dast/lfi.txt
    
    # SSRF
    printf "%s %s\n" "ssrf" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt | gf ssrf | nuclei -dast -tags ssrf -H "User-Agent: $USER_AGENT" -silent -o results/dast/ssrf.txt

    # XXE
    printf "%s %s\n" "xxe" "$(date)" >> /tmp/log
    local xxe_json='
{
  "flags": "-iE",
  "pattern": "(\\.xml|\\.svg|\\.json|\\.xsd|\\.dtd|\\.xsl|\\.rss|\\.atom|\\.soap|\\.wsdl)|(xml|doc|document|parser|entity|file|import|upload|svg|source|template|config|soap|wsdl|data|query|input)="
}
'
    printf "%s\n" "$xxe_json" > ~/.gf/bgby_xxe.json
    cat $TMP_PATH/endpoints.txt | gf bgby_xxe | nuclei -dast -tags xxe -H "User-Agent: $USER_AGENT" -silent -o results/dast/xxe.txt

    # RCE
    printf "%s %s\n" "RCE" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt | gf rce | nuclei -dast -tags cmdi,rce -H "User-Agent: $USER_AGENT" -silent -o results/dast/rce.txt

    # SSTI
    printf "%s %s\n" "SSTI" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt | gf ssti | nuclei -dast -tags ssti -H "User-Agent: $USER_AGENT" -silent -o results/dast/ssti.txt

    # # IDOR
    # printf "%s %s\n" "IDOR" "$(date)" >> /tmp/log
    # cat $TMP_PATH/endpoints.txt | gf idor | nuclei -dast -tags idor -H "User-Agent: $USER_AGENT" -silent -o results/dast/idor.txt

    # REDIRECT
    printf "%s %s\n" "redirect" "$(date)" >> /tmp/log
    cat $TMP_PATH/endpoints.txt | gf redirect | nuclei -dast -tags redirect -H "User-Agent: $USER_AGENT" -silent -o results/dast/redirect.txt

    # RANDOM SAMPLE
    printf "%s %s\n" "random" "$(date)" >> /tmp/log
    grep '\?' $TMP_PATH/endpoints.txt \
    | shuf -n 1000 \
    | nuclei -dast -H "User-Agent: $USER_AGENT" -silent -o results/dast/random_sample_scan.txt

    # ALL
    printf "%s %s\n" "all" "$(date)" >> /tmp/log
    grep '\?' $TMP_PATH/endpoints.txt \
    | nuclei -dast -H "User-Agent: $USER_AGENT" -silent -o results/dast/all_nuclei_scan.txt

    printf "%s %s\n" "END" "$(date)" >> /tmp/log
    echo "[+] DAST Pipeline Finished. Check results/dast/"
}

function contentDiscovery() {
    webFilteredFile="${1:=web.filtered.txt}"
    urlsFile="${2:=urls.all.txt}"
    domainsFile="${3:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    mkdir -p results

    # getting standard wordlists
    curl https://gist.githubusercontent.com/morkin1792/6f7d25599d1d1779e41cdf035938a28e/raw/wordlists.sh | zsh -c "source /dev/stdin; download \$BASE \$PHP \$JAVA \$ASP \$RUBY \$PYTHON && addDirsearch 'html' 'zip' 'rar' 'php' 'asp' 'jsp';cat \$dir/* | grep -Ev 'Contribed|ISAPI' | sort -u > $TMP_PATH/fuzz.wordlists.txt && rm -rf \${dir:?}"

    # building custom wordlist
    for host in $(cat $domainsFile); do
        currentUrlsFile="$TMP_PATH/urls.$(url2path $host).txt"
        grep -iE "$host" $urlsFile > $currentUrlsFile
        buildCustomWordlist $currentUrlsFile $TMP_PATH/fuzz.custom.$(url2path $host).txt
        rm $currentUrlsFile
    done

    cat $TMP_PATH/fuzz.*.txt | sort -u > $TMP_PATH/fuzz.all.txt
    cat $webFilteredFile | feroxbuster --stdin -r -k -a "$USER_AGENT" -n -g -B --json -w $TMP_PATH/fuzz.all.txt -o results/feroxbuster.$(date +"%s").results.json
}

function quickPortScanning() {
    ipsFile="${1:=ips.txt}"
    nmap -Pn -n -v3 --open -iL $ipsFile -oG nmap.quick.tcp.txt -p 21,22,23,445,1433,1521,2049,3306,3389,5432,5900
}

function portScanning() {
    ipsFile="${1:=ips.txt}"
    sudo -v
    RUNNING=1
    while [ $RUNNING -eq 1 ]; do
        sudo -n true
        sleep 60
    done 2>/dev/null &

    sudo nmap -sS -Pn -n -v3 --open -T4 -iL $ipsFile -oG nmap.top100.tcp.txt
    sudo nmap -sUV -v3 --top-ports 23 --open -iL $ipsFile -oG nmap.udp.txt
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
        # exit 1
    fi
    echo "finished $functionName: $(date)" >> /var/tmp/log.txt
}

function getDomain() {
    local input="$1"
    input="$(printf '%s' "$input" | sed 's/[.]*$//')"
    psl -b --print-reg-domain -- "$input"
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

function prips() {
    function prips_core() {
        nmap -sL -n "$1" | awk '/Nmap scan report/{print $NF}' #| grep -v '\.0$' | grep -v '\.255$'
    }
    if [ "$#" -gt 0 ]; then
        for range in "$@"; do
            prips_core "$range"
        done
    else
        while read -r range; do
            # Skip empty lines
            [ -z "$range" ] && continue
            prips_core "$range"
        done
    fi
}

function urlDecode() {
    python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));"
}

function url2path() {
    echo $1 | sed 's/^http[s]\?...//' | tr '/' '_' | tr ':' '_' | tr '?' '_' | tr '&' '_' | tr '=' '_'
}

function buildCustomWordlist() {
    customUrlsFile="${1:?missing urls input file}"
    customWordlistFile="${2:?missing output file}"
    
    export IGNORE="js|css|png|jpg|jpeg|ico|gif|svg|woff|woff2|ttf"

    ## create a wordlist only considering the first path of the urls ($4), there is a limit to avoid too big wordlists
    cat $customUrlsFile | awk -F/ '{print $4}' | grep -vE "\.($IGNORE)$|\.($IGNORE)?" | sed 's/\?.*//' | sed 's/\/$//g' | sed '/^[;%\^\&]/d' |
    shuf | head -n $CUSTOM_WORDLIST_PER_HOST_LIMIT | sort -u > $TMP_PATH/wordlist.custom.1.txt

    ## create a ordlist considering the full path, but limiting similar paths
    cat $customUrlsFile | awk -F/ -vOFS=/ '{$1=$2=$3=""; print $0}' | sed 's/^..//' | grep -vE '^/\?' | sed 's/\?\(utm\_\|v\=\|ver\=\).*//' | sed 's/data\:image.*//' | grep -vEi "\.($IGNORE)$|\.($IGNORE)?" | awk '
    {
        url = $0
        hasDoubleTilde = index(url, "~~") > 0
        n = split(url, paths, "/")

        if (!hasDoubleTilde) {
            commonKey = paths[2] "-" length(substr(url, 0, index(url, "?")))
            count[commonKey]++
            if (count[commonKey] <= 5) {
                print url
            }
        } else if (hasDoubleTilde) {
            dtKey = paths[2] "~~"
            count[dtKey]++
            if (count[dtKey] <= 4) {
                print url
            }
        }
    }' | sed 's/^\///g' | sed 's/\/$//g' | sed '/^[;\^\&]/d' | shuf | head -n $CUSTOM_WORDLIST_PER_HOST_LIMIT | sort -u > $TMP_PATH/wordlist.custom.2.txt

    cat $TMP_PATH/wordlist.custom.[0-9].txt | sort -u > $customWordlistFile
}

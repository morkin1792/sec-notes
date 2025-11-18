#!/bin/zsh

# TODO: avoid loading big files at once in memory

CONFIG_FILE="$HOME/.bgby.cfg"

if [ -z $ZSH_VERSION ]; then
    printf "$(hostname): Oops, this script requires zsh! \n$(whoami): Why?\n$(hostname): Well... because it is annoying to support a lot of different shells, and I use zsh :) \n$(whoami): You convinced me, how can I install zsh? \n$(hostname): 'pacman -S zsh' or 'apt install zsh', but you have to customize it also (check: https://itsfoss.com/zsh-ubuntu/ and https://github.com/morkin1792/mylinux/blob/master/zsh/zshrc). Otherwise, you will hate it! \n"
    # you can comment the following line if you want to use another shell, but I will not support it :)
    exit 1
fi

function checkRequirements() {
    requiredCommands=(
        'whois'             # pacman -S whois || apt install whois
        'jq'                # pacman -S jq || apt install jq
        'subfinder'         # go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        'shuffledns'        # go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
        'massdns'           # yay -S massdns || (git clone https://github.com/blechschmidt/massdns.git && cd massdns && make && sudo make install)
        'chaos'             # go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        'httpx'             # go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        'dnsx'              # go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
        'cdncheck'          # go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest
        'psl'               # pacman -S libpsl || apt install psl
        'gospider'          # GO111MODULE=on go install github.com/jaeles-project/gospider@latest
        'gowitness'         # go install github.com/sensepost/gowitness@latest (&& apt install chromium)
        'gobuster'          # go install github.com/OJ/gobuster/v3@latest
        'github-subdomains' # go install github.com/gwen001/github-subdomains@latest
        'subzy'             # go install -v github.com/PentestPad/subzy@latest
        'hashcat'           # pacman -S hashcat || apt install hashcat
        'nmap'              # pacman -S nmap || apt install nmap
        'nuclei'            # go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        'wpscan'            # pacman -S wpscan || (apt install ruby-rubygems ruby-dev && sudo gem install wpscan)
        'gau'               # go install github.com/lc/gau/v2/cmd/gau@latest
        'waymore'           # pip install waymore
    )
    # 'naabu'             # go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest (&& apt install -y libpcap-dev)
    # 's3scanner'         # go install -v github.com/sa7mon/s3scanner@latest
    # dalfox # go install github.com/hahwul/dalfox/v2@latest

    for command in ${requiredCommands[@]}; do
        if [ -z "$(which $command)" ] || [ ! -z "$(which $command | grep 'not found' )" ]; then
            printf "[-] $command is missing...\n"
            return 1
        fi
    done
}

function checkConfigFile() {
    local file="$1"

    if [ ! -f "$file" ]; then
        local template='# bgby config file
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/333.0.0.0 Safari/537.36"
# DNS_SERVER="1.1.1.1"
# TMP_PATH=$(mktemp -d --tmpdir=/var/tmp/ -t bgby_$(date +"%Y.%m.%d_%H:%M")_XXXXXXXX)


# fill in the API keys below

## https://github.com/settings/personal-access-tokens > Fine-grained personal access tokens
GITHUB_API_KEY="github..."

## https://cloud.projectdiscovery.io/settings/api-key
PDCP_API_KEY=""

## https://securitytrails.com/app/account/credentials
SECURITY_TRAILS_API_KEY=""

## https://account.shodan.io/ > click "Show"
SHODAN_API_KEY=""

## https://intelx.io/account?tab=developer
INTELX_API_KEY=""

## https://wpscan.com/profile/
WPSCAN_API_KEY=""

## https://urlscan.io/user/profile/
URL_SCAN_API_KEY=""

'
        printf "%s\n" "$template" > "$file"
        chmod 600 "$file"
        echo "[*] Created config file: $file"
    fi
    # loading configs
    source "$CONFIG_FILE"

    # setting default values if not defined
    if [ -z "$USER_AGENT" ]; then
        USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/333.0.0.0 Safari/537.36"
    fi
    if [ -z "$DNS_SERVER" ]; then
        DNS_SERVER="1.1.1.1"
    fi
    if [ -z "$TMP_PATH" ]; then
        TMP_PATH=$(mktemp -d --tmpdir=/var/tmp/ -t bgby_$(date +"%Y.%m.%d_%H:%M")_XXXXXXXX)
    fi

    # checking api keys
    if [ -z "$GITHUB_API_KEY" ] || [ -z "$PDCP_API_KEY" ] || [ -z "$SECURITY_TRAILS_API_KEY" ] || [ -z "$SHODAN_API_KEY" ] || [ -z "$INTELX_API_KEY" ] || [ -z "$WPSCAN_API_KEY" ] || [ -z "$URL_SCAN_API_KEY" ]; then
        echo "[-] To have better results, it is IMPORTANT to fill in all API keys in $file"
        # read "choice?[*] Do you want to exit now to fill the file? (Y/n): "
        # if [[ "$choice" != "n" && "$choice" != "N" ]]; then
        #     exit 1
        # fi
    fi
}
checkRequirements
checkConfigFile "$CONFIG_FILE"

echo Using $TMP_PATH as temporary space

cat <<EOF
logAndCall subdomainDiscovery
logAndCall subdomainCompilation
logAndCall reconAnalysis
logAndCall vulnScanning
logAndCall spidering
# logAndCall customVulnScanning
# logAndCall contentDiscovery
logAndCall quickPortScanning
logAndCall portScanning # requires sudo
EOF

function subdomainDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    passiveUrlsFile="${2:=urls.passive.txt}"
    subdomainsFile="${3:=subdomains.all.txt}"


    passiveSubdomainDiscovery $domainsFile $passiveUrlsFile
    activeSubdomainDiscovery $domainsFile
    # merge all subdomains
    cat subdomains/* | sed 's/^[.-]//g' | tr '[:upper:]' '[:lower:]' | sort -u > $subdomainsFile
}

function passiveSubdomainDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    passiveUrlsFile="${2:=urls.passive.txt}"
    # passive recon
    function checkCrt() {
        domain="${1:?missing domain}"
        curl -s "https://crt.sh/?q=$domain" -H "User-Agent: $USER_AGENT" | grep -iEo "<TD>[^<>]+?$domain|<BR>[^<>]+?$domain" | sed 's/^<..>//g' | sort -u
    }
    mkdir -p subdomains
    for domain in $(cat $domainsFile); do
        checkCrt $domain >> subdomains/crt.txt
        export GITHUB_TOKEN=$GITHUB_API_KEY
        github-subdomains -d $domain -o subdomains/github.$domain.txt >> $TMP_PATH/github-subdomains.output.txt
    done
    grep '^*.' subdomains/crt.txt | sed 's/^*.//' | sort -u > subdomains/crt.tls.wildcard.txt
    sed -i 's/^*.//' subdomains/crt.txt

    cat $TMP_PATH/github-subdomains.output.txt | grep https://github.com | awk '{ print $2}' | sort -u > github.urls.txt
    #TODO: add more github url finder tools (maybe search people using nodes) and repo analysis
    
    local provider_config="
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
"
    printf "%s\n" "$provider_config" > "$TMP_PATH/provider-config.yaml"
    chmod 600 "$TMP_PATH/provider-config.yaml"

    subfinder -all -dL $domainsFile -pc $TMP_PATH/provider-config.yaml -o subdomains/subfinder.$(date +"%s").txt
    export PDCP_API_KEY
    chaos -dL $domainsFile -o subdomains/chaos.txt
    grep '^*.' subdomains/chaos.txt | sed 's/^*.//' | sort -u > subdomains/chaos.tls.wildcard.txt
    sed -i 's/^*.//' subdomains/chaos.txt

    # TODO: more api keys https://docs.google.com/spreadsheets/d/19lns4DUmCts1VXIhmC6x-HaWgNT7vWLH0N68srxS7bI/edit?gid=0#gid=0
    # https://sidxparab.gitbook.io/subdomain-enumeration-guide/introduction/prequisites
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
  apikey = \"$URL_SCAN_API_KEY\"

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
    limitedCommonCrawl=0
    curl -s -I https://index.commoncrawl.org/collinfo.json || limitedCommonCrawl=1
    waymore -i $domainsFile -lcc $limitedCommonCrawl -mode B -oU $TMP_PATH/waymore.output.urls -oR pages
    domains="$(cat $domainsFile | sed '/^$/d' | tr '\n' '|' | sed 's/\./\\./g' | sed 's/|$//')"
    grep -iEh "[^/:>\" =@]*($domains)[^><\" ;,\!]*" -o pages/* | tr '[:upper:]' '[:lower:]' | sed 's/\/$//g' | sed 's/\\//g' | sort -u | sed 's/^/https:\/\//' > $TMP_PATH/waymore.manual.urls
    cat $TMP_PATH/gau.output.txt $TMP_PATH/waymore.output.urls $TMP_PATH/waymore.manual.urls | sort -u > $passiveUrlsFile 
    # extracting subdomains from urls
    cat $passiveUrlsFile | awk -F/ '{print $3}' | sed 's/:[0-9]\+$//' | sed 's/^[.]*//' | sed 's/^\(%[0-9][0-9]\)*//' | sed 's/\?.*//' | sort -u > subdomains/gau_waymore.txt
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

    cat $subdomainsFile | dnsx -a -aaaa -resp -silent -no-color | awk '!seen[$1]++ {print $1, substr($3,2,length($3)-2) }' > $TMP_PATH/hosts.dnsx.txt
    cat $TMP_PATH/hosts.dnsx.txt | awk '{print $2}' | sort -u | cdncheck -resp -silent -no-color | awk '{print $1, substr($2,2,length($2)-2)"_"substr($3,2,length($3)-2) }' > $TMP_PATH/hosts.cdn.txt
    cat $TMP_PATH/hosts.dnsx.txt | awk '{print $2}' | sort -u | dnsx -resp -silent -no-color -ptr | awk '{print $1, substr($3,2,length($3)-2)}' > $TMP_PATH/hosts.ptr.txt

    IFS=$'\n'
    for subdomainAndIp in $(cat $TMP_PATH/hosts.dnsx.txt); do
        subdomain=$(echo $subdomainAndIp | cut -d' ' -f1)
        ip=$(echo $subdomainAndIp | cut -d' ' -f2)
        domain=$(getDomain $subdomain)
        ptr=$(grep "^$ip " $TMP_PATH/hosts.ptr.txt | awk '{print $2}' | tr '\n' '|' | sed 's/|$//')
        cdn=$(grep "^$ip " $TMP_PATH/hosts.cdn.txt | awk '{print $2}')
        line="$domain,$subdomain,$ip,$ptr,$cdn"
        echo $line >> $resultsFile
    done; unset IFS
    sort $resultsFile -o $resultsFile
    sed -i "1i domain,subdomain,ip,ptr,type" $resultsFile
    
    echo "[*] Filter $resultsFile"
    # xdg-open $resultsFile
}

function reconAnalysis() {
    subdomainsFile="${1:=subdomains.all.txt}"
    hostsFile="${2:=hosts.csv}"
    # output files
    webAllFile="${3:=web.all.txt}"
    webFilteredFile="${4:=web.filtered.txt}"
    ipsFile="${5:=ips.txt}"

    # TAKEOVER
    # TODO: rework checkTakeover, consider using dnsx to get all available domains at once
    OKGREEN='\033[92m'
    WARNING='\033[93m'
    ENDC='\033[0m'

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
    httpx -p http:80,8080,8000,8008,8888,9090,9091,https:443,8443 -fr -l <(cat $hostsFile | awk -F, '{print $2}') -json -o web.all.json
    jq -r '.url' web.all.json | sed 's/[:]\(80\|443\)$//g' > $webAllFile
    filterWebUrls $webAllFile
    jq -r '.url + "," + (.status_code|tostring) + "," + (.title//"") + "," + (.words|tostring) + "," + (.a|tostring)' web.all.json | sort -ur | awk -F, '!seen[$2 FS $3 FS $4 FS $5]++ { print $1 }' | sed 's/[:]\(80\|443\)$//g' > $webFilteredFile

    # GETTING WEB SCREENSHOTS
    mkdir -p gowitness; cd $_; gowitness scan file -f ../$webAllFile --write-db; cd ..

    # GETTING SCANNABLE IP ADDRESSES
    cat $hostsFile | grep -vE ',(waf|cdn)$' | cut -d, -f3 | tail +2 | awk '!x[$0]++' > $ipsFile

}

function vulnScanning() {
    webAllFile="${1:=web.all.txt}"
    webFilteredFile="${2:=web.filtered.txt}"

    # wordpress
    nuclei -silent -l $webAllFile -H "User-Agent: $USER_AGENT" -t http/technologies/wordpress-detect.yaml -o $TMP_PATH/wordpress.txt
    cat $TMP_PATH/wordpress.txt | awk '{ print $4 }' | sed 's/\/$//' | sort -u > wordpress.txt
    nuclei -l wordpress.txt  -H "User-Agent: $USER_AGENT" -tags wordpress,wp-plugin -o results/nuclei.wordpress.txt
    for url in $(cat wordpress.txt); do
        wpscan --random-user-agent --disable-tls-checks --enumerate vp --url $url -o results/wpscan.$(url2path $url).txt --api-token $WPSCAN_API_KEY
    done

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
}

function spidering() {
    webFilteredFile="${1:=web.filtered.txt}"
    
    gospider -S $webFilteredFile -u web -d 3 -R -o pages
    
    # CHECKING AWS URLS
    grep -Rio -Pa ".{2,30}amazonaws.{2,70}" pages | grep -Eio "[^\"' ]*amazonaws[^\"' ]+" > $TMP_PATH/aws.txt 
    grep -Rio -Pa "aws-s3.{11,70}" pages | grep -Eio "[^\"' ]*amazonaws[^\"' ]+" >> $TMP_PATH/aws.txt
    cat $TMP_PATH/aws.txt | sed 's/^\.//' | sed 's/http[s]\?...//' | sed 's/^\/\///' | sed 's/\/$//' | sed 's/\=1[0-9]\{9,14\}//' | sort -u > results/aws.urls.txt
    # trufflehog s3 --bucket=bucket name

    # CHECKING NEW SUBDOMAINS
    spiderSubdomains=( $(grep -RP "^\[subdomains\]" pages | awk '{print $3}' | sed 's/http[s]\?...//' | sort -u) )    
    for sub in "${spiderSubdomains[@]}"; do
        if ! (grep -q "$sub" subdomains.all.txt); then
            # A=$(queryDNS A $sub)
            # # if there is A entry
            # if ! (nameNotFound "$A"); then
            #     echo "[*] found new subdomain: $sub"
                # TODO: instead of saving, repeat everything from subdomainCompilation
                echo $sub >> results/subdomains.new.txt
            # fi
        fi
    done

    ## pentesting only
    grep -REi 'http[s]?://[^/"\?]+' -aoh pages | sed 's/^http[s]\?:\/\///' | grep -vE 'facebook|google|youtube|instagram|twitter|apple|pinterest|tiktok|reactjs\.org|nextjs\.org|twimg\.com|tumblr\.com|pxf\.io|scene7\.com|imgix\.net|medium\.com|wordpress\.com|shopify\.com|sentry\.io|giphy\.com|cloudfront\.net|hulu\.com' | sed '/^.\{64,\}$/d' | sort -u > results/seeds.potential.txt

    # CHECKING JWT TOKENS
    grep -Eh -Roa "eyJ[^\"' ]{14,2048}" pages | urlDecode | sort -u > results/jwts.txt
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
    hashcat -m 16500 results/jwts.txt $TMP_PATH/secrets.txt -o results/jwts.cracked.txt
    #hashcat results/jwts.txt --show
    
    # TODO: more analysis and regex. maybe using another tools
    # TODO: check cognito 
}

function customVulnScanning() {
    # TODO: extract URLS, choose some and then try more specific tools
    # extract URLs + parameters (+ methods): katana - OK 
    # https://gist.github.com/morkin1792/0d4ef875d42c7e722117e3fd2f60d10e#app-analysis-and-history 
    # https://github.com/morkin1792/sec-notes/blob/8007e2b6a08811c4d445916ae23355d0d7335ba7/web.md#content-discovery
    
    # choosing urls:
    #    - preprocessing (removing static files, tracking parameters, parameter blacklist)
    #    - maybe manually requesting (checking for reflection, sql error)
    #    - ?llama, gpt4all
    
    # running
    # - sqlmap, dalfox, XSStrike
    # - dt: ?
    # - ssti: ?gossti, ?SSTImap
    # - ?ssrf: ?SSRFmap
    # - ?ci: commix
    # - https://github.com/topics/VULN
}

function contentDiscovery() {
    domainsFile="${1:=scope.txt}"
    sed -i '/^$/d' $domainsFile
    passiveUrlsFile="${2:=urls.passive.txt}"

    # getting standard wordlists
    curl https://gist.githubusercontent.com/morkin1792/6f7d25599d1d1779e41cdf035938a28e/raw/wordlists.sh | zsh -c "source /dev/stdin; download \$BASE \$PHP \$JAVA \$ASP \$RUBY \$PYTHON && addDirsearch 'html' 'zip' 'rar' 'php' 'asp' 'jsp';cat \$dir/* | grep -Ev 'Contribed|ISAPI' | sort -u > $TMP_PATH/fuzz.wordlists.txt && rm -rf \${dir:?}"

    # building custom wordlist
    for host in $(cat $domainsFile); do
        grep -iE "$host" $passiveUrlsFile > $TMP_PATH/urls.$(url2path $host).txt
        # TODO: also considerer SPIDER urls
        buildCustomWordlist $TMP_PATH/urls.$(url2path $host).txt $TMP_PATH/fuzz.custom.$(url2path $host).txt
        rm $TMP_PATH/urls.$(url2path $host).txt
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
    host -t $type -- $target $DNS_SERVER | tail +6 | grep -v ';; '
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
    psl -b --print-reg-domain -- "$1"
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

function buildCustomWordlist() {
    customUrlsFile="${1:?missing urls file}"
    customWordlistFile="${2:?missing output file}"
    
    export IGNORE="js|css|png|jpg|jpeg|ico|gif|svg|woff|woff2|ttf"
    cat $customUrlsFile | awk -F/ '{print $4}' | grep -vE "\.($IGNORE)$|\.($IGNORE)?" | sed 's/\?.*//' | sed 's/\/$//g' | sed '/^[;%\^\&]/d' | sort -u > $customWordlistFile".1"
    # delete custom wordlist if it is too big
    # TODO: consider use head verifing limit in settings variable 
    if [ $(wc -l < $customWordlistFile".1") -gt 5000 ]; then
        rm $customWordlistFile".1"
        >$customWordlistFile".1"
    fi

    cat $customUrlsFile | awk -F/ -vOFS=/ '{$1=$2=$3=""; print $0}' | sed 's/^..//' | grep -vE '^/\?' | sed 's/\?\(utm\_\|v\=\|ver\=\).*//' | sed 's/data\:image.*//' | grep -vEi "\.($IGNORE)$|\.($IGNORE)?" | awk '
    {
        url = $0
        n = split(url, paths, "/")
        
        key = paths[2] "-" length(substr(url, 0, index(url, "?")))
        count[key]++

        key2 = paths[2] "~~"
        hasDoubleTilde = index(url, "~~") > 0
        if (hasDoubleTilde) {
            count[key2]++
        }
        if (count[key] <= 5 && (!hasDoubleTilde || count[key2] <= 4)) {
            print url
        }
    }' | sed 's/^\///g' | sed 's/\/$//g' | sed '/^[;\^\&]/d' | sort -u > $customWordlistFile".2"
    # delete custom wordlist if it is too big
    # TODO: consider use head verifing limit in settings variable
    if [ $(wc -l < $customWordlistFile".2") -gt 10000 ]; then
        rm $customWordlistFile".2"
        >$customWordlistFile".2"
    fi
    cat $customWordlistFile".1" $customWordlistFile".2" | sort -u > $customWordlistFile
    rm $customWordlistFile".1" $customWordlistFile".2"
}

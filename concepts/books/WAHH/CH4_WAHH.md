# CH4 - Mapeando a Aplicação

## Enumeration

- navegação para identificar conteúdo e funcionalidade da aplicação, acessando todos links

- robots.txt pode conter locais interessantes

- web spidering, ferramentas de navegação automatizada, pode ser limitado por diversas razões (campos com verificação mais rigorosa (zip code), request de logout, heuristica de protecao (google), loop infinito, as vezes pode até gerar um deface na página)

- user-directed spidering, usuário navega manualmente através de todos caminhos, seu tráfego é salvo e então um proxy/spider os analisa e constrói um mapa.

- passo-a-passo: 
> 1. configurar proxy e navegar normalmente em todos caminhos possíveis (tip: repetir com outro navegador ou js desativado)
> 2. revisar o mapa gerado e acessar no navegador todos paths novos descobertos recursivamente, enquanto eles ainda surgirem
> 3. (opcionalmente) rodar o spider com o conteúdo já enumerado (excluindo caminhos perigosos) e voltar ao passo 2

- ainda com casos de falha: requests escondidas (debug, admin, deprecated, funcionalidades novas), para isso existem opções de força-bruta

- Brute-force, identificar padrão nos nomes, misturar com extensões da tecnologia usada (.java, .php), palavras mais comuns (Add, Remove), arquivos old (.old, webarchive.org)

- Procurar desenvolvedores da aplicação na internet, em busca de dúvidas de programação ou dicas sobre o alvo

- Vulnerabilidades no web server podem permitir a listagem dos arquivos da aplicação e seu conteúdo

- Nikto, web scanner que busca alguns paths ocultos, através de nomes comuns em libraries (phpmyadmin/) e outros projetos

- Brute-force também pode ser usado para enumerar parâmetros opcionais das requests (debug, test)


## Analisando a aplicação

- Identificar superfície de ataque para formular abordagens (funcionalidades, tecnologias)

### Identificando pontos de entrada para inputs

- parâmetros costumam vir em: URL path (REST), URL query, body, header, mas devem ser considerados quaisquer campos do HTTP (Referer, User-Agent)

- se um formato de parâmetro não convencional é usado, deve-se levar isso em conta na hora de testá-lo (/dir/file?data=%3cfoo%3ebar%3c%2ffoo%3e%3cfoo2%3ebar2%3c%2ffoo2%3e, 'data' pode não ser vulnerável a SQLi mas 'foo' sim)

- Algumas aplicações tratam o Referer para melhorar seu rank de busca ou saber o que os usuário mais buscam, gerando assim mais um ponto na superfície de ataque

- De forma semalhante, muitas aplicações utilizam o User-Agent para dar uma melhor experiência ao usuário (mobile vs web), adicionando mais uma via de ataque (tanto na leitura do campo quanto) na outra interface específica para alguns dispositivos (mobile) (que pode ter passado por menos testes de segurança)

- Adicionar headers inexistentes também pode dar certo. Ex: Aplicações com load balancer ou proxy podem adicionar um campo na request para que o web application saiba o IP do cliente.

- inputs que afetam a web application também podem ocorrer dados fora do HTTP (smtp, ids que mostra dados coletados da rede numa interface web)

### Identificando tecnologias server-side

- Banner grabbing, web servers costumam informar suas versões em responses (Server)

- HTTP headers, URL params e templates HTML também indicam a tecnologia usada

- web servers costumam ter erros diferentes para extensões aceitas mas que o arquivo não existe (bruteforce 2 detect alls)

- cookies (jsessionid, aspsessionid, phpsessid)

- existem ferramentas para reconhecimento de tecnologias (httprecon)

### Identificando funcionalidades server-side

- Pensar como um programador, imaginando como pode estar implementado no server-side e então testar todos nomes e valores de todos parâmetros sendo submetidos

- Pode ser que múltiplas funções da aplicação validem o input do usuário da mesma forma, assim é possível usar uma função que echoes a entrada para explorar outra que é blind

- Erros costumam ser tratados graciosamente em alguns casos, porém para outros inesperados um monte de informação verbosa de bug é retornada ao usuário, o que pode ajudar a exploração

- Encontrar pontos de comportamento único da aplicação também é interessante, indicando partes mais velhas ou que não seguem os padrões das outras, identificadas por diferenças na interface, nomes de parâmetros, comentários no código.

## Questões

> 1. Essa é uma URL para obter tokens de acesso, que pode ser vulnerável a LFI. The filename CookieAuth.dll indicates that Microsoft ISA server is being used. 

> 2. The URL is a common fingerprint for the phpBB web forum software. Information about this software is readily available on the Internet, and you can perform your own installation to experiment on. A listing of members can be found at the following URL: http://wahh-app.com/forums/memberlist.php 

> 3. O software server-side é o Microsoft Active Server Pages, é provável que existam outras funçãos alterando action (edit, delete, add). The function of the location=default parameter should be investigated – this may contain a filename, and you should probe the application for path traversal vulnerabilities.

> 4. A resposta do servidor indica que o web server provavelmente é o apache Tomcat e a web application deve ser feita em java.

> 5. Na primeira aplicação /admin.cpf não existe, na segunda o recurso existe mas houve falha na autorização de acesso. In each case, you could substantiate your conclusion by requesting a clearly non-existent item in the same directory with the same extension (for example, /iuwehuiwefuwedw.cpf) and comparing the responses. In the first application, you would expect to see a response very similar to the original. In the second application, you would expect to see a different response containing a “file not found” message.
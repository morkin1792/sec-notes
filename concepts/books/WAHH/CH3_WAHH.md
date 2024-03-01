# CH3 - Tecnologias de Aplicações Web

- URL query parameters (GET, POST) não devem ser usados para transmitir dados sensíveis (credenciais), já que podem ficar logados em muitos locais (históricos, favoritos, Referer)

## Métodos HTTP
- HEAD método que pede do servidor uma resposta igual ao GET porém sem um body (pegando assim só os headers do GET)

- TRACE método em que o servidor (se assim implementar) devolve a request exatamente como ele recebeu

- OPTIONS faz o servidor retornar os métodos HTTP aceitos (campo Allow)

- REST -> uma arquitetura (padrões de organização) pro HTTP (CRUD), geralmente com URL path parameters.

## Headers HTTP 
- https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/

### Gerais 
- Connection (keep-alive, close) define se deve manter a conexão TCP

- Content-Encoding (gzip, compress, deflate) diz o encode usado no conteúdo do body da mensagem

- Content-Length o tamanho do body em bytes (exceto no HEAD que diz o tamanho pro GET correspondente)

- Content-Type (text/html) o MIME type do body

- Transfer-Encoding (gzip, compress, deflate) diz o encode usado no body da mensagem

### Request
- Accept diz ao servidor os conteúdos aceitos pelo cliente

- Accept-Encoding diz ao servidor os encodes aceitos pelo cliente

- Authorization (Basic YSskdAls) manda credenciais ao servidor

- Cookies manda cookies dados pelo servidor

- Host informa o domínio do servidor que é visto pelo cliente 

- If-Modified-Since pergunta ao servidor se houve modificação desde uma determinada data, se não houve o cliente recebe uma 304 e então usa uma versão do cache

- If-None-Match pergunta ao servidor se houve modificação no hash do recurso solicitado.

- Origin é colocado pelo navegador e diz o domínio que está realizando a request (para evitar cross site request forgery)

- Referer é a url completa da página que tinha a request

- User-Agent informação do software cliente

### Response

- Access-Control-Allow-Origin (*, null, https://domain) diz os domínios (valores do request header Origin) que o navegador deve permitir receber a response

- Cache-Control informa como e se o cliente deve guardar cache

- ETag dá um hash para o client poder submeter depois no If-None-Match e verificar se houve alteração

- Expires dá uma data de expiração daqueles dados, para que o cliente reaproveite a response em novas requests até essa data

- Location diz uma URL para que o cliente faça um redirecionamento (nesses responses o status code é 3xx)

- Pragma mesma função do Cache-Control para HTTP/1.0

- Server informação do software servidor

- Set-Cookie pede ao cliente que guarde um cookie para enviar em requests posteriores

- WWW-Authenticate aparece em responses de status code 401 para dar detalhes do tipo de autenticação suportado

- X-Frame-Options (deny, sameorigin, allow-from) indica ao navegador como uma resposta pode ser usada em um frame

## Cookies

- Cookies de sessão são os que deveriam ficar só na RAM por não terem uma data de expiração (expires) (alguns navegadores deixam eles persistentes)

- Cookies permanentes são armazenados persistentemente até sua data terminar

- Set-Cookie pode conter atributos opcionais para dizer ao navegador como manipular o cookie

- expires diz uma data de expiração (define se é cookie permanente ou de sessão)

- domain diz para quais subdomínios o cookie deve ser enviado

- path restringe o URL path no qual o cookie deve ser enviado

- secure diz para o navegador só mandar o cookie em requests HTTPS

- HttpOnly diz ao navegador para impedir o cookie de ser acessado via linguagens client-side (só o navegador o manipula, para evitar vazamentos com XSSs)

## HTTP Proxy

- Um servidor HTTP proxy intermedia as requests do cliente com os servidores HTTP

- Navegador fala diretamente com servidor proxy usando método CONNECT para configurar canal

## Tecnologias

- DOM é a representação virtual de um documento HTML, permitindo que linguagens client-side acessem seus elementos. Permite também acesso aos cookies, URL e eventos que podem hookar ações.

- Request Ajax é uma forma de fazer requests em background, possibilitando com o DOM que apenas uma parte da página seja atualizada (XMLHttpRequest)

- Same-Origin Policy serve para o navegador controlar se a linguagem client-side pode receber a response de um request feito para outro domínio. Não funciona para scripts (```<script src='whatever'>```)

- URLs só podem conter caracteres imprimíveis (decimais [32,126] ASCII)

- Alguns dos caracteres permitidos tem significado no URL scheme ou no protocol HTTP, então para evitar problemas eles devem ser codificados.

- O URL-encoded é '%' + hex(ord(input))[2:], o espaço também é representado por '+'

- HTML encode é necessário para colocar alguns caractéres na página sem interferir com os componentes HTML (```< == &lt```), pode ser usado por qualquer caractér (&#65 == &#x41 == A), pode ser usado para impedir XSSs


## Questões

> 1) OPTIONS pede do servidor os métodos HTTP aceitos.

> 2) If-Modified-Since e If-None-Match são usado para receber uma nova versão de um recurso caso o atual esteja desatualizado, o primeiro pela data e o segundo por um hash (ETag), em um ataque pode ser interessante removê-los para sempre receber uma nova versão do recurso.

> 3) A flag secure em cookies indica que o mesmo só deve ser enviado em comunicações encriptadas.

> 4) O status code 301 significa que o destino foi movido permanentemente para outro local e o 302 temporariamente.

> 5) Com SSL um navegador faz uma request CONNECT para o servidor proxy, informando o host e porta de destino. Se for aceita, o servidor manda um status 200 e então a conexão continua na mesma request que é usada como um canal tcp.


# http smuggling

- objetivo: aproveitar a arquitetura atual das aplicações web para fazer poising de requests

- precisa existir ao menos um servidor externo que acumula pacotes http de múltiplas fontes e então os encaminha para serviços internos

- funcionameto: inicialmente cada request de diferentes fontes tem seu próprio canal tcp, então o externo tem que ler tudo corretamente para passar adiante, depois o servidor interno deve ler o tamanho do body de forma diferente do externo para misturar pacotes incorretamente

- http pode especificar tamanho do body usando os headers 'Content-Legth: 3' e 'Transfer-Encoding: chunked'

## tipos

- no caso do CL ser o primeiro basta colocar um chunked final logo no inicio (0\r\n\r\n), colocar os dados após isso e deixar o tamanho completo no CL 

- no caso do TE ser o primeiro, seta-se o CL com tamanho pequeno (para ler até o tamanho do primeiro chunked) e toda a request que será realizada na vítima tem que ir dentro do chunked, incluindo um Content-Length e pode-se usar o Content-Type com uma variavel sendo setada para receber o 0 no final (x=\r\n0\r\n\r\n)

- um outra opção é tentar fazer o TE não ser lido por um dos servers, alterando um pouco sua sintaxe:
    * repetir TE 2 vezes e na segunda colocar um valor errado
    * Transfer-Encoding: xchunked
    * Transfer-Encoding:[tab]chunked
    * [space]Transfer-Encoding: chunked
    * X: X[\n]Transfer-Encoding: chunked

## procurando

### CL-TE time-based

O back vai tentar ler o tamanho do próximo chunk, causando um delay.
```
 POST / HTTP/1.1
Host: vulnerable-website.com
Transfer-Encoding: chunked
Content-Length: 4

1
A 
```




## extra

- pode-se tentar usar parâmetros que se repetem para ver como a request recebida é alterada internamente

- pode-se usar requests de edição, storing, envio de email para obter a request de uma vítima e assim seus tokens de sessão

- pode-se usar para entregar um xss refletido a qualquer usuário arbitrariamente


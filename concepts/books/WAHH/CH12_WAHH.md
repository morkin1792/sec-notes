# CH 12 - XSS

- xss refletido é chamado de primeira ordem

- xss stored é chamada de segunda ordem, pois geralmente envolve 2 requests

- para identificar xss dom-based pode-se tentar payloads em parâmetros direto no navegador (perdendo alguns casos) ou analisar códigos javascript em busca de funções que podem ler ou alterar o DOM (document.write, eval, ...)

- xss dom-based pode ser visto pelo back-end. Por exemplo, quando o ponto afetado é uma variável normal da url site.com?error=<script>alert(1)</script>

- uma forma de bypassar filtros em dom-based pode ser torná-lo invisível para o back-end. ex: site.com?#error=<script>alert(1)</script>

- ou ainda tentar colocá-lo como valor de uma nova variável da url (se o filtro checar apenas variáveis pré-determinadas): site.com?error=msg&a=<script>alert(1)</script>

- self-xss is a form of cross-site scripting (xss) that appears to only function on the user’s account itself and typically requires the user to insert the JavaScript into their own account. 

- self-xss pode ser explorado com CSRF

## Explorando XSS

- ```<base href=''>``` pode ser usado para mudar urls não absolutas (```<script src="a.js"></script>```), se ele ainda não foi usado na página, e assim é possível realizar hijacks em scripts e outros elementos

- pode não ser necessário fechar uma tag para se ter sucesso: ```<img/onerror=alert(1) src//```

- HTML encoding pode ser útil dentro de atributos de tags Because the browser HTML-decodes the attribute value before processing it further, you can use HTML encoding to obfuscate your use of script code: ```<img onerror=alert&#040&#39opa&#39&#x29 src=a>```

- se a aplicação substituir caracteres especiais por outros similares comuns, talvez o filtro também possa ser bypassado: ```«img onerror=alert(1) src=a»```

- se o filtro buscar por símbolos abrindo e fechando <...>, algo assim pode funcionar: ```<<script>alert(1);//<</script>```
 
- se for possível alterar o HTTP Content-Type header ou ainda adicionar um charset parameter de forma a setar o encoding utilizado, é possível criar payloads com eles (UTF-7: +ADw-script+AD4-alert(document.cookie)+ADw-/script+AD4-)

- Unicode escapes can be used to represent characters within JavaScript keywords, allowing you to bypass many kinds of filters: ```<script>a\u006cert(1);</script>```

- se existir mais de uma word sanitizada, pode-se verificar se a sanitização acontece recursivamente em cada um e assim pode ser bypassada: ```<scr<object>ipt>alert(1)</script>```

- if you find that the backslash character is also being properly escaped, but angle brackets are returned unsanitized, you can use the following attack: ```<script>var a = ‘</script><script>alert(1)</script>```

- "converter" xss refletido para DOM-based: ```<script>eval(location.hash.slice(1))</script>```

## Questões

>> - 1) Quando uma aplicação repete um input em uma resposta HTTP existe a possibilidade dela estar vulnerável a XSS refletido.
>> - 2) In most cases, XSS flaws within unauthenticated functionality work just as effectively against authenticated users – the functionality behaves in the same way, resulting in arbitrary JavaScript execution within the context of the authenticated user’s session. Nesse caso a vulnerabilidade poderia ser usada para carregar um script que ficaria persistente até o momento da autenticação e posteriormente roubando os tokens de sessão da vítima. Outra abordagem seria modificar a página para gerar um falso formulário solicitando as credenciais da vítima.
>> - 3) É possível utilizar o cookie refletido para injetar um script em casos aonde pode-se a partir desse ponto é permitido a inserção de quebras de linha, a fim de redefinir o body da resposta. Ou ainda se a aplicação tiver um XSS DOM-based relacionado a esse cookie. The answer to the second question is "maybe". Historically, various ways have existed of injecting arbitrary HTTP headers into cross-domain requests, to inject a malicious cookie. Older versions of Flash and XMLHttpRequest have been vulnerable in this way. Further, many applications designed to use a cookie will in fact accept the same named parameter in other locations, such as the query string or message body. 
>> - 4) Sim, mesmo self-XSS podem ser encadeados com outras vulnerabilidades para aumentar seu grau de severidade.
>> - 5) Deve-se checar se é possível fazer com que HTML/Javascript seja interpretado nesses anexos. Further, if a JPEG file contains HTML, then this will be automatically processed as HTML within some browsers. Many web mail applications do not adequately defend against XSS in message attachments.
>> - 6) The same-origin policy is a critical security mechanism that restricts how a document or script loaded from one origin can interact with a resource from another origin. It helps isolate potentially malicious documents, reducing possible attack vectors.
>> - 7) Roubar tokens de sessão, realizar phishing, ler dados de aplicações internas não disponíveis na internet, stealing cached autocomplete data.
>> - 8) Pode-se transformar o xss refletido em um DOM-based para bypassar esse limite de tamanho.
>> - 9) Enviar para a vítima uma página que, por meio de um CSRF, executa o XSS.

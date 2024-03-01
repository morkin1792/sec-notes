# CH 7 - Atacando Gerenciamento de Sessão

- sessão permite que a aplicação identifique um usuário em suas requests

- geralmente basta que um ID seja submetido em todas requests no lado cliente, o servidor então guarda variáveis daquela sessão referenciadas pelo ID 

- cookies são a forma mais comum para gerenciar a sessão (porém outras as vezes também podem ser usadas em conjunto: url, body)

- vulnerabilidades nos mecanismos de gerenciamente de sessão podem ser categorizadas em:
* fraqueza na geração de token de sessão
* fraqueza na manipulação de tokens de sessão

- alternativas a sessões:
    * autenticação HTTP, utiliza headers HTTP padrões para enviar credenciais (resubmete em todas requests)
    * estado sem sessão, todos dados para gerenciar sessão ficam com o cliente, para ser seguro eles deevem ser encriptados ou assinados pelo servidor

## fraqueza na geração de tokens

- permite a um atacante identificar valores de tokens gerados a outros usuários

- muitas partes do token podem na verdade serem só offsets

- entender estrutura de token (geralmente contém username, email)

- cifras em que uma parte do plaintext resulta sempre no mesmo ciphertext (ecb) podem ser mais facilmente auditadas e manipuladas, buscando por offsets no cifrotexto

- Para verificar se é possível explorar o cifrotexto, pode-se usar um ataque alterando bit a bit do mesmo (burp intruder bit flipper) e analisar a resposta

- pode ser possível solicitar a decriptação de um texto para a aplicação

## fraqueza na manipulação de tokens

- o mesmo token pode ser usado antes e depois do login (e antes pode ser que nenhuma criptografia seja utilizada)

- armazenamento de tokens em logs, que muitas vezes são guardados sem muito cuidado (pode ser por salvar campo relacionado a ele propositalmente ou ainda por fazê-lo ser passado por URL query)

- tokens em URL querys podem ser recebidos em outro servidor pelo campo Referer

- fraquezas no mapeamento dos tokens:
    * permitir múltiplos clientes logados com as mesmas credenciais
    * utilizar sempre o mesmo token para várias sessões do usuário (static token)
    * não correlacionar dados do token possibilitando ataque de controle de acesso (se usuário é válido e código de confirmação de qualquer usuário também é permite algo) 

- terminar a sessão corretamente diminui a janela de oportunidades de um atacante

- termino de sessão deve ocorrer no servidor também

- toda vez que outro usuário se logar um novo token deve ser gerado para que quem já estava logado com A não mude para B

- cookies por padrão são resubmetidos somente para o domínio da origem do request (sub.site.com), porém se domain for especificado eles serão resubmetidos também para os subdomínios (x.sub.site.com)

- para fazer com que os cookies sejam submetidos apenas na aplicação principal (e não em outros subdomínios) pode-se criar o subdomínio www para a aplicação principal

- cookies com domain ignoram protocolo e porta, permitindo o envio para outra aplicação rodando por trás do mesmo hostname

- opção Path de cookies é ineficiente contra aplicações perigosas do mesmo domínio, pois é possível usar um XSS

## Prevenindo e remediando

### na geração de token
- tokens não devem ser previsíveis (função de randomização fracas) ou vulnerável a brute-force

- estados devem ser guardados no server


### na manipulação

- token só deve ser transmitido por canais criptografados

- se passado como cookie deve ter a fag secure e ser o mais restringido possível

- tokens não devem ir na URL

- o front deve ter opção de logout (ou um timeout pequeno) e a operação deve ser acontecer no server 

- deve ter timeout com período razoável se o server não receber mais requests

- evitar logins concorrentes (deautenticar token)  

- em novos logins, novos tokens devem ser criados

- log para tokens inválidos (detectar bruteforces)

- alertar usuário de atividades anômalas

- terminar sessões com requests estranhas (valor que deveria ser barrado no client-side)

#### Per-Page Tokens

- tokens únicos que mudam a cada request 

- usados em aplicações de alto nível de segurança

- pode ajudar como defesa de controle de acesso



## Questões

> - 1) Os cookies dessa aplicação são inseguros, pois eles são transmitidos em plaintext (base64) e são extremamente previsíveis, possibilitando um hijack com um brute-force num intervalo de tempo.

> - 2) ambos os campos tem um conjunto de possibilidades relativamente pequeno, deixando-as vulneráveis para brute-force. Cada um tem suas vantagens, para atacar senhas é necessário também descobrir o usuário relacionado, pode-se acabar bloqueando o usuário ou ainda ter de enfrentar um captcha e além disso elas podem ser alteradas para valores maiores, já os tokens são sempre do mesmo tamanho porém não deve ser possível usar um token quando o usuário não estiver mais logado e se a aplicação não permitir login concorrente não será possível hijackar a sessão.

> - 3) O browser submeterá o cookie sessionId para as opções: a, c, d, E

> - 4) Session hijacking is still possible. If an attacker obtains the tokens issued to a user, the attacker can immediately make requests using those tokens, and the server will accept the requests. However, if the user issues a single further request to the application, then the per-page token submitted by the user will be out of sequence, and the entire session will be invalidated. Hence, if the user is still interacting with the application, the window for exploitation may be very small. If an attacker simply wishes to perform a specific action with the user’s privileges, it is likely that they can script an attack to perform the desired action within the available window. 

> - 5) Provavelmente essa aplicação não finaliza realmente a sessão no servidor, apenas pede para o cliente não submeter mais o token. Ainda deixando-o válido e assim aumentando a janela de oportunidades do atacante.
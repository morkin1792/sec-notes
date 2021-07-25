# CH 6 - Atacando Autenticação

- smartcards costumam ser usados em aplicações bom uma base de usuário pequena (como web-based VPNs para remote workers)

- HTTP-based authentication (basic, digest) raramente é usado

- o mecanismo dominante é o de submeter credenciais por um form html

## Falhas de Design em Autenticação 

- permitir senhas fracas fará com que muitos usuários as usem o que será um problema de segurança, porém se essa verificação acontecer somente a nível client-side não é um problema (visto que clientes normais estarão seguros)

- para verificar as regras de senha pode-se fazer um registro ou trocar a senha

- se for possível utilizar um bruteforce na página de login a aplicação estará bem vulnerável

- se para prevenir um bruteforce a aplicação utilizar variáveis no client-side, ela ainda deve ser vulnerável

- a aplicação pode bloquear a conta após algumas tentativas mas ainda responder de forma que se possa saber se a senha está correta

- formas de enumerar usuários: funções de cadastro, reset de senha, responses verbosos (login), response time-based 

- deve-se rodar um diff nas responses para verificar qualquer diferença mínima

- páginas http podem podem trabalhar com importantes requests ajax sobre https, porém elas ainda serão vulneráveis a modificações MITM e por tanto tudo ainda fica vulneráveis

- credenciais devem ser transmitidas no body (pois como query podem ser logadas facilmente)

- páginas password reset podem permitir brute-force de senha (tentar com campo de repetição de senha diferente)

- pode ser possível fazer uma mudança de senha de um usuário A logado como o usuário B (procurar campo que identifique usuário ou que possa sobreescrever o atual) 

- pode ser possível fazer brute-force no desafio de recuperação de senha

- tentar prever a geração de urls dos password resets

- quando existir "remember me" analisar local storage e requests, comparar resultados com usuários e senhas similares

- se exister uma funcionalidade de impersonation, tentar atuar como um administrador  

- web applications podem realizar uma validação incompleta de credenciais (fazendo strip de caracteres, deixando case insensitive, verificando só até o Nº char), facilitando o brute-force

- tentar registrar usuários com mesmo nome e diferentes senha

- aplicações que sugerem nomes podem permitir a adivinhação de possíveis usuários e assim a geração de wordlists

- aplicações que geram senhas podem permitir a predição de senhas geradas a outros usuários (obter algumas e comparar)

## Falhas de implementação em autenticação

- falha de abertura de login (usuário inexistente faz login)

- fazer login normalmente, depois fazer requests modificando vários dados (string vazia, colocar valores muito longos e muito curtos, trocar tipos) e ir buscando diferenças nas reponses

### defeitos em logins com multipassos

- podem ser feitos pressupostos incorretos, possibilitando um usuário que foi do estágio 1 para o 3 se autenticar


## Autenticação segura
- internamente senhas devem ser salvas com hash irreversíveis e salts para evitar uso de tabelas já computadas

- qualidade mínimo da senha deve ser garantida (tamanho mínimo, sem palavras de dicionário, cases diferentes)

- usernames/passwords geradas automaticamente não podem ser previsíveis

- usuários devem ser permitidos a escolher senhas fortes

- credenciais devem transitar apenas por canal criptografado e nunca em URL query (logs) ou cookies (storage client, repeticao em requests)

- se a senha precisar ser armazenada, deve ser feita apenas no server e criptografadamente

- usuários devem mudar senha periodicamente

- credenciais fornecidas out-of-band devem ser time-limited e obrigar a troca no primeiro login

- em logins multipassos, nenhum dado deve ser coletado mais que uma vez

- não especificar que dado está incorreto

- suspender conta após algumas tentativas, porém não explicitar quando a conta for suspensa (apenas informar que pode ser se errar muito)

- captchas são muito úteis contra brute-force e outros ataques automatizados

- qualquer tentativa envolvendo autenticação (mudança de senha, login) bem sucedida ou não deve ser salva num log

- usuários devem ser avisados out-f-band de qualquer evento crítica de autenticação (mudança de senha)

## Questões

> 1) As vulnerabilidades que podem ser percebidas são:
> * Passagem de credenciais direto na URL
> * Política de senhas fracas
> * Passagem de credenciais por um canal sem criptografia 

> 2) Funções de auto registro podem informar que determinado usuário não está disponível, permitindo assim a enumeração de usuários. Para evitar isso pode-se gerar um usuário aleatoriamente para o usuário ou ainda usar um meio out-of-band (e-mail) como usuário.

> 3) O mecanismo de login é dividido em 2 etapas para adicionar uma camada extra de segurança mesmo que suas credenciais tenham sido comprometidas uma vez, pois é improvável que o atacante consiga logar visto que novas pares de letras serão solicitados. Se fosse tudo em uma request, o par de letras seria aleatório então bastaria ao atacante tentar novamente até ter que adivinhar o par que ele sabe.

> 4) Em um login multipassos, qualquer item submetido incorretamente deve ao final causar uma falha genérica. Impedindo um atacante de saber o que está incorreto.

> 5) Este processo de login introduz a possibilidade de garantia que um usuário e data de aniversário são válidos.
O mecanismo não é totalmente efetivo contra phishing pois pede informações relativamente fracas para identificar o usuário (username e data de aniversário) e se não houver um captcha é possível montar um servidor phishing que faz requests ao autêntico em tempo real.
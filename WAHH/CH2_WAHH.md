# CH2 - Principais Mecanismos de Defesa
- conhecer as medidas de defesa da aplicação (autorizações, tratamento de entradas, alertas) alvo é o melhor caminho para realizar ataques

## manipulando acesso do usuário

- mecanismos de defesa geram as superfícies de ataque (autenticação, gerenciamento de sessão, controle de acesso) 

- autenticação -> confirma identidade do usuário. gerando mais superfícies com funcionalidades extras como registro ou recuperação de senha

- gerenciamento de sessão -> torna possível a existência de uma sessão virtual do usuário. Pode vir com falhas na geração de token ou que permitem obtenção de tokens alheios

- controle de acesso -> decide se o usuário tem permissão para acessar o que foi solicitado. É comum gerar falhas por assumir determinado comportamento do usuário e omitir verificação em uma função

## manipulando input do usuário

### abordagens de manipulação de input

* checar padrões de uma blacklist (má opção, n engloba tudo) -> uso de bytes nulos com input pode bypassar a expressão

* checar whitelist -> nem sempre pode ser usada (campo q por questão de negócio precise de caracteres não seguros -> chat facebook permitindo código html)

* sanitização -> pode aceitar tudo, geralmente encoda alguns caracteres em outro formato para que eles não causem problemas

* manipulação de dados seguros -> programar de forma segura evitando algumas vulnerabilidades (SQL injection) sem tratar o input

* checagem semantica -> verificações de controle de acesso

### Validação de limite

- A abordagem de inicialmente tratar todo input e depois considerar tudo como confiável não é boa -> é difícil criar uma barreira que defende contra todos ataques, pode-se manipular entradas comuns para ao serem modificadas internamente se tornarem um problema (```<scr<script>ipt>```), podem existir validações que são incompatíveis entre si (xss -> command execution)

- uma melhor abordagem é fazer checagens em cada componente individualmente (nos limites confiáveis), então cada parte pode validar a entrada para as suas possíveis vulnerabilidades

### Validação de Múltiplos passos

- Canonização -> codificar ou decodificar dados

- Sanitizar múltiplas vezes uma entrada pode gerar falhas na sua filtragem (%%2727)


## manipulando atacantes

- Erros inéditos provavelmente indicam um ataque, devem ser bem registrados e acionar um alerta

- Erros devem ser tratados para que nunca cheguem detalhadamente ao usuário, pois podem ter informações que ajudam um atacante

- Erros inéditos podem ser sinal de defeitos na aplicação que devem ser corrigidos

- Logs de auditoria servem para entender como uma vulnerabilidade foi (tentada ou) explorada e o que exatamente o atacante acessou

- web application firewalls são bons para identificar ataques óbvios e componentes com CVEs (plugin wp), mas pelo grau de variação das aplicações, deixam passar muitos ataques mais sutis

- sutis checagens específicas para cada aplicação (como a mudança de um id em um form oculto) podem diferenciar atacantes dos outros usuários com menos falsos positivos do que soluções prontas

- como medida extra contra 0-days, quando um usuário é classificado como potencialmente malicioso (input suspeito, excesso de requests), medidas podem ser tomadas para retardar seu progresso (delay request, captcha)

## gerenciando a aplicação

- muitas aplicações tem um painel de administração implementados em si mesma, fazendo nisso um ponto bem atrativo para atacantes

- poucos testes costumam ser feitos em funcionalidades voltadas para administradores

## questões

> 1) Mecanismos da aplicação para controle de acesso dos usuários são tão seguros quanto o componente mais fraco deles, pois qualquer falha em um dos mecanismos (autenticação, gerenciamento de sessão, controle de acesso) quebram o sistema que garante a identidade do usuário

> 2) A session is a set of data structures held on the server, which are used to track the state of the user’s interaction with the application, um token de sessão é um parâmetro passado no header das requests para identificar a identidade do usuário

> 3) nem sempre é possível usar uma abordagem baseada em whitelist para validar uma entrada, pois por regras de negócio pode ser necessário que caracteres 'perigosos' sejam permitidos (postagem em um blog de xss) 

> 4) mesmo sem credenciais para acessar o painel administrativo deve-se dar muito atenção para ele pois geralmente são menos testados que o resto da aplicação, tendo assim mais chances de ter falhas e são o ponto de maior privilégio, possibilitando comprometer toda a aplicação de uma vez

> 5) Para bypassar esse sistema de validação de entrada, pode-se usar o seguinte input:  <pre> %22>%3cscript>alert(%22foo%22)</script> </pre>
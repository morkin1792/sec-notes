# CH 9 Atacando Bases de Dados

- vulnerabilidades code injection surgem em linguagens interpretadas

- deve-se usar a funcionalidade para tentar prever o tipo de statement sql: select (recuperar info), insert (cadastro), update (atualização de dados)

- os locais mais prováveis de entry point são: WHERE (select, update, delete), ORDER BY (select), dentro parenteses (insert), porém qualquer local da query é possível

## detectando sql injection 
- esse é o primeiro passo, em seguida deve-se tentar descobrir qual o db sendo utilizado

- em string: 
    * submeter aspas simples (')
    * se acontecer algo de diferente, ver resposta com 2 aspas simples (''), deveria ser interpretado como uma aspas simples escapada (\')

- pode ser que o entry point esteja no nome da tabela ou ORDER BY com string (nesse caso aspas apenas resultarão em erro interno), deve-se suspeitar disso se a string controlar ordem ou for um nome de tipo e então tentar construir o resto da query (adicionar WHERE ou DESC)

- em parametro numerico:
    * tentar operacoes matematicas (2-1, 50-ASCII(1))

## fingerprinting o db

- testar diferenças sintáticas

* concatendo
    |    db     | sintaxe  |
    |-----------|----------|
    | Oracle    |'a'\|\|'b'|
    | Microsoft | 'a' + 'b'|
    | MySQL     | 'a' 'b'  |
* buscando versão
    |    db     | sintaxe  |
    |-----------|----------|
    | Oracle    |SELECT version FROM v$instance|
    | Microsoft |SELECT @@version |
    | MySQL     |SELECT @@version |

* funções que resultem em valor numérico
    |    db     | sintaxe  |
    |-----------|----------|
    | Oracle    |BITAND(1,1)-BITAND(1,1)|
    | Microsoft |@@PACK_RECEIVED-@@PACK-RECEIVED|
    | MySQL     |CONNECTION_ID()-CONNECTION_ID()|

## extraindo dados

- existem formas específicas para cada db de listar todas tabelas e colunas existentes

|   db   |                 sintaxe                  |
|--------|------------------------------------------|
| oracle | SELECT * FROM all_tab_columns            |
| resto  | SELECT * FROM information_schema.columns |


## bypassando filtros

- no MySQL é possível burlar algumas verificações colocando comentários entre palavras reservadas:
    * SEL/*foo*/ECT user FR/*foo*/OM users

## sqli de segunda ordem

- uma falha geralmente stored que não é executada imediatamente

- ex: registrar um usuário de nome foo' (aplicação trata aspas e salva o nome exatamente como recebeu)
- tentar alterar a senha de foo': SELECT password FROM users WHERE username = 'foo'' (aplicação tem sqli com nome salvo anteriormente) 

## exploração avançada

- qd não se recebe diretamente o output da query na response

- oracle tem funções que permitem realizar request HTTP (UTL_HTTP.request)

- uma forma comum é recuperar informações usando querys para um servidor DNS, que muito facilmente passa pelo firewall

- mysql tem o INTO OUTFILE que permite mandar a saída diretamente para um servidor SMB e também o load_file que permite ler arquivos

- microsoft tem o xp_cmdshell que permite execução direta no shell

### Inferência em Respostas Condicionais

- se a única comunicação do db com a internet for pela a aplicação web, existem técnicas para alterar a resposta e assim recuperar informações

- ASCII(c) converte um char em um int

- SUBSTRING(word, i, length) pega uma substring de word , em oracle é SUBSTR

- pode-se também recuperar bit a bit (&, POWER(2,0)), garantindo um número de requests para cada byte

- induzir erro interno não tratado (1/0)


## Prevenindo SQLi

- querys parametrizadas/prepared statements -> apis para manipular input inseguras, inpedindo interferência com a query (protege também de sql injection de 2ª ordem)

- caso seja preciso utilizar um input para especificar nomes de tabelas ou colunas deve-se usar a abordagem de white list

- camadas de defesa: 
    * a aplicação deve ter o menor nível de privilégios possíveis ao acessar o db (pode-se ter múltiplos usuários para cada ação da aplicação)
    * desativar funções desnecessárias
    * manter o sistema atualizado


## XPath injection
- XPath é uma forma de query em xmls
- explorável quase da mesma forma que sqli, porém é case-sensitive
- é possível recuperar toda a estrutura do xml as cegas com funções nativas
- a prevenção se limita a utilização de white lists alfanuméricas, nada de sanitização 

## Questões

>> * 1) Para descobrir quantas colunas a query original contém, pode-se tentar usar o ORDER BY e ir aumentando o número até ocorrer um erro interno ou ainda ir adicionando nulls no select do union

>> * 2) Para descobrir o tipo de banco num ambiente blind porém com diferenças condicionais, pode-se tentar diferentes formas de concatenação de cada banco e verificar se eles ainda respondem da mesma maneira

>> * 3) O ponto afetado de SQLi mais seguro nesse caso deve ser o (a) pois provavelmente ele contém apenas um INSERT e assim não há risco de afetar outros usuários.

>> * 4) Existem diversas maneiras, uma seria esperando uma aspas simples no final do payload (' or '1'='1) outra seria tentando bypassar o filtro com um encoding ou outra forma de comentário se o db aceitar (#, /**/).

>> * 5) Uma forma de bypassar essa barreira dos whitespace é colocando comentários no lugar deles (/**/).

>> * 6) É possível criar uma string dinamicamente por meio de uma função que transforma um int num char (CHAR)

>> * 7) Quando o input do usuário é utilizado para definir nomes de tabelas ou colunas (ou ainda partes da query como o ASC/DEC), nesse caso a única proteção é permitir caracteres de uma restrita white list.

>> * 8) Com uma vulnerabilidade de SQLi nessa situação pode ser possível fazer escalações horizontais, DoS, RCE, pivoting e diversos outros ataques.

>> * 9) Depende da aplicação, pensando em um repositório de busca simples a significância dessas vulnerabilidades se daria provavelmente na seguinte ordem: C, A e B. B sempre é o último pois XPath só serve para ler um xml porém a aplicação nem autenticação tem. A pode ser melhor que C em casos de RCE que permitam mais privilégios (db rodando como root).

>> * 10) Para dizer o que a aplicação está acessando pode-se tentar fazer uma injeção específica para cada um (% - sqli,  * - lpad)


TODO: extraindo dados em mensagens de erro
- https://www.mathyvanhoef.com/2011/10/exploiting-insert-into-sql-injections.html
- https://hackernoon.com/exploit-database-error-to-leak-users-table-informations-writeup-be62b3c86968
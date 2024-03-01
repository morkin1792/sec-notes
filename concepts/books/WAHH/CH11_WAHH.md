# CH 11 - Atacando a Lógica da Aplicação

- submeter requests sem alguns parâmetros (captcha, senha antiga)

- forced browsing - pular uma request da etapa (pagamento)

- submeter parâmetros em estágios diferentes

- bypassar filtros que escapam com barra invertida: colocar outra barra invertida \, escapando o escapamento

- bypassar filtro que duplica aspas simples e limita o tamanho depois: ''''[...]'''''''

## Prevenindo

- documentar e revisar toda arquitetura da aplicação, tentando bypassar pressupostos

## Questões

>> - 1) Forced browsing é o ato de fazer requests em uma ordem fora da padrão de navegação esperada de um usuário comum, isso pode gerar muitas inconsistências, bugs e vulnerabilidades (ex: pular pagamento para a tela de entrega).

>> - 2) Se ele duplicar as aspas antes de truncar a entrada pode acabar deixando um número ímpar delas, ocasionando um sql injection. If the length limit is applied before the doubling up, then you may still be able to exploit any buffer overflow conditions by placing a large number of single quotes at the start of your payload, causing this to extend sufficiently far to overflow the buffer with crafted data positioned towards the end of your payload. 

>> - 3) Using valid credentials for an account you control, you should repeat the login process numerous times, modifying your requests in specific ways:

    For each parameter submitted, try submitting an empty value, omitting the name/value pair altogether, and submitting the same item multiple times with different values.

    If the process involves multiple stages, try performing these stages in a different sequence, skipping individual stages altogether, proceeding directly to arbitrary stages, and submitting parameters at stages where they are not expected.

    If the same item of data is submitted more than once, probe to determine how each value is processed, and whether data that is validated at one stage is trusted later on.


>> - 4) Nessa caso deve-se verificar se as etapas de autenticação são independentes, usando credenciais de um usuário e o cpf + token de outro.

>> - 5) Parece que o log de cada falha está estático para todos usuários. Pode-se usar duas sessões silmultâneas para tentar confirmar isso.

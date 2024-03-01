# CH 8 - Atacando controles de acesso

- Fraquezas comuns pois o problema não pode ser resolvido apenas usando tecnologias, é necessária a decisão de uma pessoa

- categorias controle de acesso:
    * vertical -> existem vários tipos de usuários, cada um com suas funções
    * vertical privilege escalation -> o usuário consegue realizar ações que não são papel dele (acesso a funções de administrador)
    * horizontal -> todos usuários tem acesso a um certo subconjunto do mesmo tipo (ex: contas do facebook)
    * horizontal privilege escalation -> usuário consegue acessar subconjunto de outro usuário (ver posts privados de outro usuário)
    * dependente de contexto -> as permissões do usuário variam com o estado da aplicação, podendo prevenir usuário de acessar funções fora de ordem (compra)
    * business logic exploitation -> usuário consegue acesso a permissões de outro estado (bypassar passo de pagamento de uma compra)

- uma escalação horizontal pode permitir ataques ao administrador, gerando uma escalação vertical

- uma tentativa incorreta de "proteção" em algumas aplicações pode ser usar da obscuridade, mostrando os links corretos apenas para os usuários corretos, ou seja, as rotas não verificam o usuário (/admin, ebook.pdf), basta descobrí-la para se ter acesso 

- aplicações que usam um identificar (?docid=23) e permitem que qualquer um de posse dele (sem checar identidade) consiga acessá-lo devem ser vulneráveis (logs, id previsível), pode-se testar analisando as respostas de repetir todas requests de um usuário em outro 

- em funções de múltiplos estados (necessita de vários requests) é possível que por pressupostos errados, a verificação de acesso só seja feita na primeira request, para testar deve-se fazer as requests com um usuário e selecionadamente repetir algumas delas em outro

- uma função pode aceitar vários métodos HTTP (GET, HEAD, POST, INVALID) e fazer o controle de acesso apenas em alguns deles

- deve-se validar o controle de acesso em todo request recebido

- logar sempre que um dado ou função sensíveis forem acessados

- ao invés de implementar controle de acesso em cada componente é preferível ter uma aplicação central que gerencia isso (mais claro, simples, maintainability, menos omissões)

- para dar mais segurança, pode-se utilizar de um modelo de privilégios multicamadas (imaginar cada tipo de usuário com uma conta relacionada em um menor nível) fazendo um comprometimento não levar o atacante muito longe: 
    * application server controla o acesso a URL paths
    * contas de database específicas e restritivas são usadas (read-only, acesso só a algumas tables)
    * contas do OS para cada serviço e com o menor privilégio possível
- pode-se criar perfis para classificar tipos de usuários e ter permissões bem detalhadas (privilege matrix)

- uma matriz de privilégios pode ser armazenada no db e ser aplicada programaticamente, rotas com política de whitelist



## Questões

> * 1) Para testar se uma aplicação está utilizando o header Referer pode-se logar em um usuário com altos privilégios, mapear toda aplicação e então tentar repetir as requests com o mesmo Referer em outro usuário (de menos permissões) e verificando se ele consegue acesso. 

> * 2) Nesse caso existem 2 abordagens, pode-se tentar acessar a mesma url em outra conta ou tentar um brute-force no parâmetro da url (uid) e verificar se a aplicação responde como se o dono do uid estivesse logado.

> * 3) Apenas examinar o endereço IP do usuário não ser o único controle de acesso, pois endereços IPs podem ser facilmente alterados por inúmeros serviços (proxy, vpn), múltiplos usuários podem depender de um único endereço IP e por fim uma pessoa má intencionada pode ter acesso a rede com o endereço de IP permitido.

> * 4) There is no horizontal or vertical segregation of access within the application, so there is no need for any access controls that discriminate between different individual users. Even though all users are in the same category, the application still needs to restrict the actions that any user can perform. A robust solution will use the principle of least privilege to ensure that all user roles within the application’s architecture have the minimum permissions necessary for the application to function. For example, because users only need read access to data, the application should access the database using a low privileged account with read-only permissions to only the relevant tables.


> * 5) Isso indica que provavelmente esses arquivos de dados sensíveis não implementam um controle de acesso, ou seja, basta que qualquer usuário acesse suas URLs para obtê-los.
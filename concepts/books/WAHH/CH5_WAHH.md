# CH5 - Bypassando controles Client-side

- controles client-side sempre pode ser bypassados

- analisar o header Referer que pode estar sendo usado para validar requests

- um erro de deslocamento na decodificacao base64 pode deixar o resultado completamente errado, então ao decodificar se o resultado parecer sem sentido faça até 3 deslocamentos

- os campos If-Modified-Since e If-None-Match são interessantes de serem removidos nas requests do navegador para que a request sempre receba a response completa

- enviar dados bloqueados em client-side à web application para verificar se a validação é replicada lá

- elementos desabilitados não são enviados nas requests, para identificá-los é necessário olhar o código da página ou responses do servidor

- tentar submeter elementos desabilitados e ver se são aceitos

- browser extensions que usam virtual machine -> flash, java, silverlight, pode-se interceptar suas requests ou ainda melhor, decompilar seus bytecodes

- browser extensions podem serializar dados, geralmente é possível descobrir o tipo de serialização pelo Content-Type

- se a serialização for proprietária ou houver uma encriptação pode-se decompilar ou debugar o software client-side

- browser extensions podem ignorar proxys configurados, mas ainda pode-se pegá-los por DNS, configurando o hosts file

- browser extensions podem ser usadas com cache agressivamente, de forma que seja necessário um full clear cache

- Pode existir casos que a comunicação não é interceptável (outros protocolos), porém ainda deve ser possível ver e modificar pacotes com um network sniffer

- disassembly transforma uma linguagem de máquina em um assembly

- debugger mostra e manipula o estado de execução da aplicação

- decompiler transforma um binário em código de mais alto nível

- após modificar um browser extension pode-se empacotá-lo de forma standalone para executá-lo sem depender do site original (main para java, local html file para flash)

- ténicas de ofuscação mais usadas:

> * trocar nomes de variáveis por palavras reservadas (porém aceitas após o pré-processamento), fazendo o decompilador retornar código inválido

> * código redundante

> * modificar lógica sequencial padrão de execução, com jumps

> * programação ilegal (caminhos com instruções inacessíveis ou ausentes) aceita pelas VMs

- alguns ofuscadores tem opção de desofuscação 


- usar um debugger é uma boa maneira para um client-side bypass

- se o server-side receber um dado que deveria ter sido filtrado no cliente, ele pode classificar o usuário como provavelmente malicioso e tomar as medidas cabíveis

- é possível manter importantes (preço) seguros contra adulteração no client com criptografia (jwt)

## Questões

> 1. enviando ao cliente um dado validado no servidor com um bom algoritmo é possível confiar que o dado não poderá ser adulterado no cliente (jwt). However, the attacker may still be able to take data from one context and replay it in another – for example, the encrypted price for a cheap item could be submitted in place of the encrypted price for an expensive item. To prevent this attack, the application should include sufficient context within the protected data to be able to confirm that it originated in the same context as it is being employed – for example, the product code and price could be combined in a single encrypted blob.

> 2. se o atacante parar de mandar os cookies que contam a quantidade de tentativas ele bypassa essa defesa. An alternative defense would be to use CAPTCHA controls to slow down an attacker, or to block the source IP address after five failed logins, although this may have an adverse impact where multiple clients are located behind a proxy or a NAT-ting firewall.

> 3. A opção C é a mais apropriada, a B necessitaria que as aplicações fossem do mesmo domínio e tivessem com os cookies devidamente configurados.

> 4. é possível mudar campos desativados em forms html ao interceptar o tráfego com um proxy ou alterando o html do browser

> 5. não há como uma web application confiar num dado validado pelo client-side pois validações client-side podem ser sempre bypassadas de diversas formas

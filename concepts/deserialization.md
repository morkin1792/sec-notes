## Deserialization

- Deserialization é pegar um conjunto de bytes e transformar de volta em um objeto de uma linguagem;

- Outros termos podem ser utilizados como sinônimos de serialization, como marshalling (ruby) ou pickling (python);

- Muitos ataques de deserialization acontecem antes do término da operação, assim funcionando mesmo quando o objeto é de uma classe diferente da esperada;

- Existem linguagens que invocam funções na deserialization, como o PHP que chama o método __drestruct() da classe recebida. Esse comportamento pode ser usado de forma maliciosa se o código da aplicação for acessível;

- gadget é um pedaço de código que existe na aplicação e pode ser usado para ajudar em um ataque;

- é improvável identificar gadgets sem acesso ao código fonte, para resolver isso, é possível se aproveitar de gadgets que existem em bibliotecas amplamente utilizadas
    - para auxiliar nesse processo, existem ferramentas (ysoserial, phpggc) que permitem escolher entre bibliotecas conhecidas para criar objetos serializados que se aproveitam de gadgets nelas


## Fontes

* https://portswigger.net/web-security/deserialization
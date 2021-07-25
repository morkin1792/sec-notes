- Algumas funções podem ter resultados diferentes de acordo com o momento em que são executadas. Ex Java.enumerateLoadedClasses() 
    - Pode ser que seja necessario esperar para sobreescrever uma funcao apenas apos sua classe ter sido carregada
- Para hookar a funcao de uma ClasseB dentro de outra, pode-se usar $:

```javascript
c1ass = Java.use('com.package.ClassA$ClassB')  
```


## references

- https://11x256.github.io/
- https://frida.re/docs/javascript-api/

# api

## api tests
- subvert business rules
- change Host
- try change http methods
    - manual common way
    - _method=PUT
    - X-HTTP-Method-Override: PUT
    - X-Method-Override: PUT
    - X-Http-Method: PUT
- understand how route is defined
    - add / at end of the path
    - check web cache deception
- search code injection
- fuzzing potencial parameter
    - https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
- fuzzing headers
    - web cache poison
- http smuggling

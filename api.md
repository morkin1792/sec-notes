# api

## api tests
- subvert business rules
- change Host
- try change http methods
    - traditional way
    - param `_method=PUT`
    - header `X-HTTP-Method-Override: PUT`
    - header `X-Method-Override: PUT`
    - header `X-Http-Method: PUT`
    - header `Method: PUT`
- understand how route is defined
    - add / at end of the path
    - check web cache deception
- search code injection
- fuzzing potential parameters
    - https://github.com/s0md3v/Arjun
    - https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/Web-Content/burp-parameter-names.txt
- fuzzing headers
    - web cache poison
- http smuggling

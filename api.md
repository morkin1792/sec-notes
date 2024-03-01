# api

## api tests
- subvert business rules
- change Host
- try change http methods
    - common way
    - /add_user?_method=DELETE
    - X-HTTP-Method-Override: DELETE
- understand how route is defined
    - add / at end of the path
    - check web cache deception
- search code injection
- fuzzing potencial parameter
- fuzzing headers
    - web cache poison
- http smuggling
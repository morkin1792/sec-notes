## mobile
- mobsf static analysis
- search hardcoded keys:
    * access.?key|access.?token|api.?key|api.?secret|client.?password|client.?secret|client.?session|client.?token|private.?key|private.?token|secret.?access|secret.?key|secret.?token|session.?token|amazonaws|appspot|firebaseio|senha|password
    * \w{3,36}:\w+@(\w+[.])+\w+
    * [0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}
    * <pre> grep --color=yes -A5 -B5 -Einf patterns.regex index.android.js </pre>
    - [js analysis](../web.md#js-sensitive-information-analysis)
## ios
- /var/mobile/Media  # mount point of usb storage
- /var/containers/Bundle/Application # app

## android
- [android step 0](android_0.md)

## to check
- https://cobalt.io/blog/ios-pentesting-101

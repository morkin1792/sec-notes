## mobile
- mobsf static analysis
- search hardcoded keys:
    * https://github.com/dwisiswant0/apkleaks
    * `access.?key|access.?token|api.?key|api.?secret|client.?password|client.?secret|client.?session|client.?token|private.?key|private.?token|secret.?access|secret.?key|secret.?token|session.?token|amazonaws|appspot|firebaseio|senha|password`
    * `\w{3,36}:\w+@(\w+[.])+\w+`
    * `[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`
    * <pre> grep --color=yes -A5 -B5 -Einf patterns.regex index.android.js </pre>
    - [js analysis](../web.md#js-sensitive-information-analysis)

## android
- [android step 0](android_0.md)
- checking RASP https://github.com/rednaga/APKiD/

## ios
- usb storage `/var/mobile/Media`
- app `/var/containers/Bundle/Application`
- configs `/var/mobile/Containers/Data/Application/`
- generating ipa: `mkdir Payload && cp -r YourApp.app Payload/ && zip -r MyApp.ipa Payload`
- installing ipa:
   * 1) Unpack the ipa
     2) Copy the folder inside Payload (<AppName>.app)
     3) Paste it in /var/jb/Applications/
     4) Run ```uicache -ar``` in an ios terminal
- https://cobalt.io/blog/ios-pentesting-101

## reversing flutter apps 
- https://www.guardsquare.com/blog/current-state-and-future-of-reversing-flutter-apps
- https://swarm.ptsecurity.com/fork-bomb-for-flutter/
- https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/
- https://blog.tst.sh/reverse-engineering-flutter-apps-part-2/
- https://cryptax.medium.com/reversing-an-android-sample-which-uses-flutter-23c3ff04b847

## to check
Medusa mobile framework https://github.com/Ch0pin/medusa

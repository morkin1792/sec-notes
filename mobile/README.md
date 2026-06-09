## mobile
### static analyzers
- https://github.com/thecybersandeep/ipaauditor
- https://github.com/dwisiswant0/apkleaks
- https://github.com/mobsf/mobile-security-framework-mobsf

## android
- [android step 0](android_0.md)
- checking RASP https://github.com/rednaga/APKiD/
- https://github.com/REAndroid/APKEditor

## ios
- installing ipa
   - option A: https://github.com/claration/Impactor
   - option B: Copy ipa to "On My iPhone": `/rootfs/private/var/mobile/Containers/Shared/AppGroup/{UUID}/File Provider Storage/`, then install via TrollStore
- extracting ipa
   - option A: `mkdir Payload && cp -r YourApp.app Payload/ && zip -r MyApp.ipa Payload`
   - option B: https://github.com/donato-fiore/TrollDecrypt
- https://cobalt.io/blog/ios-pentesting-101
- common locations
   - usb storage `/var/mobile/Media`
   - app `/var/containers/Bundle/Application`
   - configs `/var/mobile/Containers/Data/Application/`


## frida
### frida frameworks
- Medusa mobile framework - https://github.com/Ch0pin/medusa
- objection - https://github.com/sensepost/objection
### stealthy frida servers
- https://github.com/taisuii/rusda
- https://github.com/hackcatml/ajeossida

## flutter apps 
- https://www.guardsquare.com/blog/current-state-and-future-of-reversing-flutter-apps
- https://swarm.ptsecurity.com/fork-bomb-for-flutter/
- https://blog.tst.sh/reverse-engineering-flutter-apps-part-1/
- https://blog.tst.sh/reverse-engineering-flutter-apps-part-2/
- https://cryptax.medium.com/reversing-an-android-sample-which-uses-flutter-23c3ff04b847

## bypassing jailbreak detection

### tweaks
- https://ios.cfw.guide/blocking-jailbreak-detection
- shadow (rootless support) -> ios.jjolano.me
- A-Bypass -> repo.co.kr
- Hestia -> havoc.app
- Choicy (support)
- liberty lite -> ryleyangus.com/repo
- vnodebypass
- Not a bypass (palera1n) -> uckermark.github.io/repo

### frida scripts
- objection -g TARGET run ios jailbreak disable
- frida --codeshare liangxiaoyi1024/ios-jailbreak-detection-bypass -f TARGET
- frida --codeshare incogbyte/ios-jailbreak-bypass -f TARGET
- https://node-security.com/posts/frida-for-ios/

### manual
- check logs
    - idevicesyslog
    - dmesg via ssh
- try previous version
    - appstore++ && build external identifier (tools.lancely.tech)
    
- https://www.synacktiv.com/sites/default/files/2021-10/2021_sthack_jailbreak.pdf
- https://www.romainthomas.fr/post/21-07-pokemongo-anti-frida-jailbreak-bypass/
- https://mobile-security.gitbook.io/mobile-security-testing-guide/ios-testing-guide/0x06j-testing-resiliency-against-reverse-engineering



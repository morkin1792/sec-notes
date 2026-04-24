# Android Application Pentesting - Part 0 (Setup)
Some tricks to use when you are testing Android Apps

## Setting proxy

Choose one of the options below:

- A) **[🥇Recommended]** "Rethink VPN" app (available on Google Play, or also https://github.com/celzero/rethink-app)
    * Change DNS settings to "System DNS", Add a HTTP(S) CONNECT proxy, and start the "VPN".
    * If there is AP isolation in the WiFi network, connect the device via adb and run: `adb reverse tcp:8080 tcp:8080`. Then, consider that the proxy address is `127.0.0.1` and port `8080`.
- B) Android builtin proxy system (some apps ignore it, such as the ones made in Flutter): `adb shell settings put global http_proxy 127.0.0.1:8080`
- C) Network Level (firewall + transparent Proxy)
    - 1) Choose one of the options below:
        * A) Create an AP on your computer and connect the Android.
        * B) Connect your device and your pc in the same router (assuming there is no AP isolation and the app does not need ipv6) 
            - In your mobile device: Go to your current wifi network settings and edit its IP settings. Choose Manual/Static IPv4. Define an ip address for your device from the same range your pc have. And put the ip address of the pc (that is running the proxy) as the gateway and the DNS server.
            - Search "How to enable ip forwarding" in your system. If you are using linux:
                * `sudo sysctl -w net.ipv4.ip_forward=1`
                * For persistence, check `man 5 sysctl.d`
            - Start a DNS server ignoring ipv6. If you are using linux:
            ```sh
            function startDnsServer() {
               echo '
               no-resolv
               log-queries
               server=/*/8.8.8.8
   
               # ignoring ipv6
               address=/*/::
   
               listen-address=0.0.0.0
               bind-interfaces
               ' > /tmp/dnsmasq.conf
               sudo dnsmasq -C /tmp/dnsmasq.conf --no-daemon
            }
            startDnsServer
            ```
    - 2) Set the pc's firewall to redirect the device's traffic to your transparent proxy (and allow querying the dns server). If you are using linux:
         ```sh
         export deviceAddr="192.168..."
         export proxyPort="8080"
         iptables -A INPUT -p udp --source $deviceAddr --dport 53 -j ACCEPT
         iptables -A INPUT -p tcp --source $deviceAddr --dport $proxyPort -j ACCEPT
         iptables -t nat -A PREROUTING -p tcp --source $deviceAddr -j REDIRECT --to-ports $proxyPort
         ```
    - 3) If you are using Burp Suite, go to Proxy Settings, add or edit a proxy listener, and enable invisible proxy inside Request handling tab. 

## Installing CA certificate
* 1) Get the certificate file (http://burp, http://mitm.it, …)
* 2) Install the certificate

### A) Installing as System certificate
- A) Install a Magisk/Zygisk Module to do user certs be installed as System certs, and then just install them as user certs (via settings/file manager).
    * https://github.com/NVISOsecurity/AlwaysTrustUserCerts (⚠️ this module may not work for [flutter apps](https://github.com/NVISOsecurity/AlwaysTrustUserCerts/issues/44) and may not work when used together with [another modules](https://github.com/NVISOsecurity/AlwaysTrustUserCerts/issues/46) )
    * https://github.com/lupohan44/TrustUserCertificates (⚠️ this module may be deprecated)
- B) Via a custom recovery (such as TWRP)
    - **[No requires root directly on Android]** Use the adb in recovery to have root file system access. Then install it:
```bash
function installCertViaRecovery() {
    CERT="${1:?Provide a certificate file (cert.der) as an argument}"
    function convertCert() {
        CERT="${1:-}"
        openssl x509 -inform DER -in $CERT -out ca.pem
        name=$(openssl x509 -inform PEM -subject_hash_old -noout -in ca.pem)
        mv ca.pem "$name".0
        openssl x509 -inform PEM -text -noout -in "$name".0 >> "$name".0
        openssl x509 -inform PEM -fingerprint -noout -in "$name".0 >> "$name".0
        adb push "$name".0 /data/local/tmp && echo "Converted $CERT and sent to device (/data/local/tmp/$name.0)"
    }
    convertCert "$CERT"
    if (adb shell whoami | grep root >/dev/null 2>&1); then 
        if (adb shell ls -lah /system/etc/security 2>&1 | grep -qi 'no such'); then
            echo "[*] Search an option to mount the partition System, then try again."
         else
            adb shell '
                mv /data/local/tmp/*.0 /system/etc/security/cacerts/
                chown root:root /system/etc/security/cacerts/*
                chmod 644 /system/etc/security/cacerts/*
                reboot
             '
             echo "Certificate installed successfully. Device is rebooting."
         fi
    else
        echo "Restart the device in Recovery Mode (using a non stock (custom) recovery, such as TWRP or OrangeFox)."
    fi
}
```

### B) Installing as User certificate (via Settings / File Manager)
- Problematic since Android 7 (https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html). You will need:
   - A) Use a magisk/zygisk module (see [#a-installing-as-system-certificate](#a-installing-as-system-certificate))
   - B) **[No requires root]** Recompile the app modifying it to trust in User certificates: https://github.com/shroudedcode/apk-mitm
   - C) Hook the config to trust in user certs (https://medium.com/keylogged/bypassing-androids-network-security-configuration-575819a8f317, https://github.com/httptoolkit/frida-interception-and-unpinning)
   - D) Use a very old Android version

## Bypassing root detection
- Can you use a **non-rooted device**, installing the CA certificate via Recovery (as explained in [#a-installing-as-system-certificate](#a-installing-as-system-certificate))?
    - If the app implements certificate pinning:
        - https://github.com/mitmproxy/android-unpinner
        - Frida without root
            - https://lief-project.github.io/doc/latest/tutorials/09_frida_lief.html
            - https://fadeevab.com/frida-gadget-injection-on-android-no-root-2-methods/
            - https://jlajara.gitlab.io/Frida-non-rooted
            - https://koz.io/using-frida-on-android-without-root/
- MagiskDenyList ~~MagiskHide (v23)~~ + Magisk Modules (Shamiko)
- Frida scripts
    - https://codeshare.frida.re/@dzonerzy/fridantiroot/
    - https://codeshare.frida.re/@fdciabdul/frida-multiple-bypass/
    - https://github.com/sensepost/objection
    - "root" inurl:codeshare.frida.re
- Manual solution
    * Static
        * what look for?
            - generic strings (magisk, supersu, root)
            - stacktrace (logcat)
            - message appearing in the app
            - diff using old versions without the protection
        * jadx, ghidra, ida pro
        * if the app was built in react-native and its bundle is not obfuscated: js-beautify 
    * Dynamic
        * what look for?
            - methods found in static analysis
            - loaded methods/classes names
            - use a debugger and check the stacktrace
            - syscalls hooking
        * Frida
        * Debbuger (gdb via termux)

## Bypassing Play Integrity API (~~SafetyNet Attestation~~)
* Play Integrity Fix (https://github.com/chiteroman/PlayIntegrityFix)

## Bypassing Certificate Pinning
- [pinning](pinning.md)

## Bypassing Developer Mode detection
- Try Frida CodeShare
    - to check: https://codeshare.frida.re/@zionspike/bypass-developermode-check-android/
- Disable developer mode
    * You can let frida server running as daemon (`frida-server -D`) and connect via network
    * Use termux (you can install ssh server and/or frida client)
- Manual analysis

## Debugging Setup
0) Do **NOT** take into account the reaction of ANY browsers apps ⚠️. They may trust on user certificates, and do not trust on system certificates.
1) First of all, make sure your target app is working without any proxying.
2) At least temporarily, avoid ANY network issues (firewall, ap isolation, etc.) by using adb for creating a reverse socket connection between your computer and the device: `adb reverse tcp:PORT tcp:PORT`. 
3) Use an ALL-your-traffic routing solution (rethink, (ap||dns||vpn)+iptables, ...) to make sure everything is going to http://127.0.0.1:$PORT. See [#setting-proxy](#setting-proxy).
4) Install Termux (via [google play](https://play.google.com/store/apps/details?id=com.termux) or [github](https://github.com/termux/termux-app)), and then run: `curl -v duck.com`
   - If curl `did NOT work`, read its error logs, make sure adb reverse is still there, and the ports are right.
   - If curl `worked` but the request was `NOT captured` by the proxy, you are not routing all your device traffic.
   - If curl `worked` and the request was `captured` by the proxy, everything fine. Go to next step.
5) Install an app that, for sure, **does NOT have certificate pinning**, such as [https://github.com/httptoolkit/android-ssl-pinning-demo](https://github.com/httptoolkit/android-ssl-pinning-demo).
6) Perform an NOT pinned HTTPS request. If you are using **android-ssl-pinning-demo**, just press the first button ("unpinned request"):
    - If the request was `NOT captured` by the proxy, your proxy **CA certificate** is not being recognized. See [#installing-ca-certificate](#installing-ca-certificate).
    - Otherwise, **your setup is working fine**.
7) If whenever you open your target app while proxying the traffic, the internet connection is still **failing**, it is highly **probably** a **certificate pinning** issue. See [pinning](pinning.md).




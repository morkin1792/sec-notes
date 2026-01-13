# Android Application Pentesting - Part 0 (Setup)
Some tricks to use when testing Android Apps

## Setting proxy

Choose one of the options below:

- A) **[🥇Recommended]** "Rethink VPN" app (available on Google Play, or also https://github.com/celzero/rethink-app)
    * Change DNS settings to "System DNS", Add a HTTP(S) CONNECT proxy, and start the "VPN".
    * If there is AP isolation in the WiFi network, connect the device via adb and run: `adb reverse tcp:8080 tcp:8080`. Then, consider that the proxy address is `127.0.0.1` and port `8080`.

- B) Network Level (firewall + transparent Proxy)
     - 1) Set the computer's firewall to redirect the device's traffic to a transparent proxy. If you are using linux:
         ```sh
         export deviceAddr="192.168..."
         iptables -A INPUT -p udp --source $deviceAddr --dport 53 -j ACCEPT
         iptables -A INPUT -p tcp --source $deviceAddr --dport 8080 -j ACCEPT
         iptables -t nat -A PREROUTING -p tcp --source $deviceAddr -j REDIRECT --to-ports 8080
         ``` 
     - 2) Choose one of the options below:
        * A) Create an AP on your computer and connect the Android.
        * B) Use your regular WiFi router (assuming there is no AP isolation and the app does not need ipv6) 
            - In your Android device: Go to Settings > WiFi, select the option to edit your wifi network. Then, fill the current ip address of the computer that is running the proxy as the gateway and the DNS server. Also define a different ip address for you android device.
            - Search for "How to enable ip forwarding" in your system. If you are using linux:
                * `sudo sysctl -w net.ipv4.ip_forward=1`
                * For persistence, check `man 5 sysctl.d`
            - Start a DNS server ignoring ipv6. If you are using linux:
            ```sh
            echo '
            no-resolv
            log-queries
            server=/*/8.8.8.8

            # ignoring ipv6
            address=/*/::

            listen-address=0.0.0.0
            bind-interfaces
            ' > ~/dnsmasq.conf
            sudo dnsmasq -C ~/dnsmasq.conf --no-daemon
            ```

## Installing CA certificate
* 1) Get the certificate file (http://burp, http://mitm.it, …)
* 2) Install the certificate as a:
    - A) **User Certificate** (via Settings / File Manager). 
        - Problematic since Android 7 (https://android-developers.googleblog.com/2016/07/changes-to-trusted-certificate.html). You will need:
            - A) Use a magisk/zygisk module (check System Certificate installation) 
            - B) **[No requires root]** Recompile the app modifying it to trust in User certificates: https://github.com/shroudedcode/apk-mitm
            - C) Hook the config to trust in user certs: https://medium.com/keylogged/bypassing-androids-network-security-configuration-575819a8f317
            - D) Use a very old Android version
    - B) **System Certificate**
        - A) Install a Magisk/Zygisk Module to make user certs be installed as System certs (https://github.com/NVISOsecurity/AlwaysTrustUserCerts), and then just install them as user certs (via settings/file manager).
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
            echo "Using the Recovery, mount the partition System, then try again."
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

## Bypassing root detection
- Can you use a **non-rooted device**, installing the CA certificate without root as detailed above?
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

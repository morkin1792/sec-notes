function pullApks() {
    packageName="${1:?missing package_name}"
    outputDirectory="${2:-.}"

    apks=( $(adb shell pm path $packageName | sed 's/package://') )

    if [ ${#apks[@]} -eq 0 ]; then
        echo "[-] $packageName not found"
    else
        version=$(adb shell dumpsys package $packageName | grep versionName | awk -F= '{print $2}')
        mkdir -p $outputDirectory/"$packageName"_"$version" && cd $_
        for apk in $apks; do
            adb pull $apk .
        done
        cd - >/dev/null
    fi
}

# adb uninstall $packageName
# java -jar ~/Tools/uber-apk-signer-1.3.0.jar --allowResign -a . -o modifiedApks
# adb install-multiple modifiedApks/*apk

function pullIpa() {
    IP_ADDRESS="$1"
    APP_NAME="$2"

    if [ -d "Payload" ]; then
        echo "first, delete the Payload folder inside $(pwd), then try again"
        return
    fi

    echo -n "Enter SSH Password: "
    read -s SSHPASS
    echo "ok, trying to connect..."
    export SSHPASS

    APP_OPTIONS="$(sshpass -e ssh -v mobile@$IP_ADDRESS "grep -Eiao --color=yes \".{0,30}$APP_NAME.{0,30}\" /var/containers/Bundle/Application/*/*/Info.plist" | awk -F/ '!seen[$6]++')"
    APP_UUID=$(echo $APP_OPTIONS | awk -F'/' '{ print $6 }')
    AMOUNT_LINES=$(echo $APP_UUID | wc -l)

    if [ -z $APP_UUID ]; then
        echo "[-] app not found"
    elif [ $AMOUNT_LINES -gt 1 ]; then
        echo "[*] multiple apps with the term, try to specify more:"
        echo $APP_OPTIONS | grep --color=yes -Ei "$APP_NAME"
    else
        echo "[+] app found: $(echo $APP_OPTIONS | grep --color=yes -Ei "$APP_NAME")"
        echo "[-] keep your device connected to the wifi"
        echo "downloading..."

        sshpass -e scp -r mobile@$IP_ADDRESS:/var/containers/Bundle/Application/$APP_UUID/ Payload 2>&1
        if [ ! $? -eq 0 ]; then
            echo "something is wrong, it was not possible to get the app files"
        else
            NAME=$(cat Payload/*/Info.plist | grep -i CFBundleName -A1 | grep -io '<string>[^<]*' | sed 's/^.\{8\}//')
            VERSION=$(cat Payload/*/Info.plist | grep -i CFBundleShortVersionString -A1 | grep -io '<string>[^<]*' | sed 's/^.\{8\}//')
            echo "$NAME"_"$VERSION"
            zip -rm "$NAME"_"$VERSION".ipa Payload
        fi
    fi
}

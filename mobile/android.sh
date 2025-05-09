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

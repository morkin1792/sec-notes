# setting ssh in windows

1) get openssh

```powershell
cd $env:TEMP
rm -r -fo .\OpenSSH-Win32\ 2>NULL
iwr "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.5.0.0p1-Beta/OpenSSH-Win32.zip" -o openssh.zip
Expand-Archive -LiteralPath openssh.zip -DestinationPath .
cd .\OpenSSH-Win32\
```

2) start ssh server
```powershell
$pubKey="ssh-..."
Add-Content authorized_keys $pubKey
Clear-Content .\sshd_config_default
Add-Content .\sshd_config_default "AuthorizedKeysFile $(Get-Location)\authorized_keys"
Add-Content .\sshd_config_default "PermitTTY No"
.\ssh-keygen.exe -f host_key -N """"
.\sshd.exe -f .\sshd_config_default -h host_key -p 2222
```
or

2) use ssh client (available by default in windows v1803+)
```powershell
cd $env:TEMP\OpenSSH-Win32\
.\ssh.exe -p 2222 -i .\key -o UserKnownHostsFile=a -o StrictHostKeyChecking=no -T $Env:Username@1.2.3.4 
```


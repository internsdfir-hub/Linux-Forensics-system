sudo systemctl status nginx
sudo systemctl status ssh
uptime
free -h
df -h
top -b -n 1 | head -n 20
sudo tail -n 50 /var/log/syslog
cat /proc/cpuinfo | grep 'model name' | wc -l
ss -tulpn
exit

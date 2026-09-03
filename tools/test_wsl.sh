#!/bin/bash
HOST_IP=$(ip route | grep default | awk '{print $3}')
echo "Host IP is $HOST_IP"
python3 /mnt/d/C/Git/Linux-Forensics-system/tools/remote_collector.py /etc http://$HOST_IP:8080

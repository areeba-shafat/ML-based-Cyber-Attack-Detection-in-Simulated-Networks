#!/bin/bash

TARGET="192.168.188.130"
USER="bc220420516"
PASS="1234" 

echo "[1/7] Initial connections and handshakes..."
for i in $(seq 1 5); do
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $USER@$TARGET "echo connected" 2>/dev/null
    sleep 2
done

echo "[2/7] Interactive commands - small keystrokes..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $USER@$TARGET << 'ENDSSH'
for i in $(seq 1 30); do
    echo "test $i"
    sleep 0.5
done
pwd
whoami
date
uptime
ls -la
ENDSSH

echo "[3/7] Idle session with keepalives - 60 seconds..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no \
    -o ServerAliveInterval=5 \
    -o ServerAliveCountMax=20 \
    $USER@$TARGET "sleep 60" &
SSH_PID=$!
sleep 65
kill $SSH_PID 2>/dev/null

echo "[4/7] Large output commands..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $USER@$TARGET << 'ENDSSH'
find / -maxdepth 4 2>/dev/null | head -500
cat /etc/passwd
ps aux
ss -an
df -h
free -m
env
ENDSSH

echo "[5/7] File transfers..."
dd if=/dev/urandom bs=1K count=512  2>/dev/null | base64 > /tmp/test_small.txt
dd if=/dev/urandom bs=1K count=2048 2>/dev/null | base64 > /tmp/test_large.txt
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no /tmp/test_small.txt $USER@$TARGET:/tmp/
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no /tmp/test_large.txt $USER@$TARGET:/tmp/
sshpass -p "$PASS" scp -o StrictHostKeyChecking=no $USER@$TARGET:/etc/passwd /tmp/retrieved.txt

echo "[6/7] Mixed activity - commands then pauses..."
sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $USER@$TARGET << 'ENDSSH'
for i in $(seq 1 10); do
    ls /var/log/ 2>/dev/null
    cat /proc/meminfo | head -5
    sleep 3
    top -bn1 | head -20
    sleep 3
done
ENDSSH

echo "[7/7] Multiple short sessions..."
for i in $(seq 1 15); do
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no $USER@$TARGET \
        "hostname; uname -r; cat /proc/loadavg" 2>/dev/null
    sleep 1
done

echo "All done"

#!/bin/bash
# /usr/bin/guard.sh eth0 $2 $3 $4 $5 $6
# $1 = interface
# $2 = source IP
# $3 = destination port
# $4 = sleeping time (seconds)
# $5 = protocol1 (TCP or UDP)
# $6 = protocol2 (UDP or TCP) -- optional
if [ -z "$5" ];
then
    echo "Usage: $0 ethx src_ip dest_port seconds protocol1 [protocol2]"
    exit
fi
if [ -z "$6" ];
then
    iptables -i $1 -D INPUT -p $5 -m state --state NEW --dport $3 -j DROP
    iptables -i $1 -D INPUT -p $5 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -p $5 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -s $2 -p $5 --dport $3 -j ACCEPT
    sleep $4
    iptables -i $1 -D INPUT -s $2 -p $5 --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -p $5 -m state --state NEW --dport $3 -j DROP
    exit
else
    iptables -i $1 -D INPUT -p $5 -m state --state NEW --dport $3 -j DROP
    iptables -i $1 -D INPUT -p $6 -m state --state NEW --dport $3 -j DROP
    iptables -i $1 -D INPUT -p $5 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -D INPUT -p $6 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -p $5 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -s $2 -p $5 --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -p $6 -m state --state ESTABLISHED --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -s $2 -p $6 --dport $3 -j ACCEPT
    sleep $4
    iptables -i $1 -D INPUT -s $2 -p $5 --dport $3 -j ACCEPT
    iptables -i $1 -D INPUT -s $2 -p $6 --dport $3 -j ACCEPT
    iptables -i $1 -I INPUT -p $5 -m state --state NEW --dport $3 -j DROP
    iptables -i $1 -I INPUT -p $6 -m state --state NEW --dport $3 -j DROP
    exit
fi


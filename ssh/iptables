# secure iptables.rules
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:LOGGING - [0:0]
-A INPUT -s 192.168.0.0/24 -i wlan0 -j DROP
-A INPUT -s 10.0.0.0/8 -i wlan0 -j DROP
-A INPUT -s 192.168.100.0/24 -j ACCEPT
-A INPUT -i wlan0 -p tcp -m tcp --sport 31337 --dport 31337 -j DROP
-A INPUT -s 192.168.1.0/24 -i wlan0 -j DROP
-A INPUT -p tcp -m multiport --dports 21,22,23,25,80,443,31337,7000,7001,7002,7003,7004,7016 -j DROP
-A INPUT -p tcp -m tcp --dport 80 -m limit --limit 100/min --limit-burst 200 -j ACCEPT
-A INPUT -m conntrack --ctstate INVALID -j DROP
-A INPUT -i lo -j ACCEPT
-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT
-A INPUT -j LOGGING
-A FORWARD -o wlan0 -p tcp -m tcp --sport 31337 --dport 31337 -j DROP
-A FORWARD -s 192.168.1.0/24 -i wlan0 -j DROP
-A OUTPUT -j ACCEPT
-A OUTPUT -o wlan0 -p tcp -m tcp --sport 31337 --dport 31337 -j DROP
-A OUTPUT -s 192.168.1.0/24 -o wlan0 -j DROP
-A LOGGING -m limit --limit 1/sec -j LOG --log-prefix "IPTables packet DROP: " --log-level 7
-A LOGGING -j DROP
COMMIT
# Completed on Mon Feb  5 02:47:42 2019

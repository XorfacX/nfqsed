### POP(vtun client)

iptables -t mangle -A INPUT -s 45.77.29.109 -p tcp --sport 8800  -j NFQUEUE --queue-num 0
iptables -t mangle -A POSTROUTING -d 45.77.29.109 -p udp --dport 8800  -j NFQUEUE --queue-num 0

### FW NODE

iptables -t mangle -A INPUT -p tcp --dport 8800  -j NFQUEUE --queue-num 0
iptables -t mangle -A POSTROUTING -p udp --sport 8800  -j NFQUEUE --queue-num 0


### DEBUG

can add LOG target to filter table in order to found why packet is dropped, mainly about
checksum/length error.

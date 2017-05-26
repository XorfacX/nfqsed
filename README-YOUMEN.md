### WARNING

之前给出的配置不对，对于vtun来说，一开始建立的其实是tcp，等tcp建立后，双方互发一个udp port
，然后通过这个udp port进行通信，并关闭原有的tcp连接，切为udp收发模式。

如果我们想容易做的话，则对发出的所有到FW node的udp报文进行翻译，将udp端口存入seq number
，到对端还原出来，然后tcp用一个假的并不用到的21端口做为源端口，目的端口用32767(linux默认local
port用32768开始，因此不重复)，供对端识别用。

### POP(vtun client)

iptables -t mangle -A INPUT -s 45.77.29.109 -p tcp --sport 32767  -j NFQUEUE --queue-num 0
iptables -t mangle -A POSTROUTING -d 45.77.29.109 -p udp  -j NFQUEUE --queue-num 0

### FW NODE

iptables -t mangle -A INPUT -p tcp --sport 32767  -j NFQUEUE --queue-num 0
iptables -t mangle -A POSTROUTING -p udp -j NFQUEUE --queue-num 0


### DEBUG

can add LOG target to filter table in order to found why packet is dropped, mainly about
checksum/length error.

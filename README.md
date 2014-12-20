ToyVPN
======
a simple vpn forked from android sdk and xiaoxia.org/2012/02/21/udpip-vpn

On server
----------
```bash
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE #replace eth0 with your server interface
```

# Collection of ODNS Measurement Tools
## DNS over TCP
An implementation to measure the open DNS infrastructure using TCP over IPv4.
It comprises all ODNS components: 
- Recursive resolvers
- Recursive forwarders
- Transparent forwarders

Regular scan results are published under http://odns.secnow.net

## DNS Traceroute Tools
These tools measure the path to and beyond transparent DNS forwarders. 
### DNS over TCP Traceroute
Sends out SYN packets with increasing IP TTL values.
As soon as a SYN/ACK arrives, the tool starts to send DNS requests over TCP with increasing IP TTL to explore the path between scanner over target to DNS resolver.

**Usage**
```
sudo go run dns_traceroute_tcp.go [target-ip]
```

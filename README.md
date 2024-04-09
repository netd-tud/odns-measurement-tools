# Collection of ODNS Measurement Tools

An implementation to measure the open DNS infrastructure using various Protocols over IPv4 (for now DNS-over-TCP & DNS-over-UDP).
It comprises all ODNS components: 
- Recursive resolvers
- Recursive forwarders
- Transparent forwarders

Regular scan results are published under http://odns.secnow.net

## DNS over TCP

### Usage
**Setup:**
```
cd dns_over_tcp
cp config.yml.template config.yml
```

Then modify the `config.yml` accordingly (set your interface name and IP-address).

Ensure kernel reset packets are disabled:

```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```


**Run the scan:**
```
sudo go run dns_over_tcp.go [net-to-scan-in-CIDR|filename-of-ip-list]
```

Results are written to `tcp_results.csv.gz`

**Postprocessing:**

Transform the data into a format useful for postprocessing:
```
python3 postproc_data_tcp_pure.py tcp_results.csv.gz
```

The resulting file will be named `tcp_results_combined.csv.gz`

## DNS over UDP

### Usage
**Setup:**
```
cd dns_over_tcp
cp config.yml.template config.yml
```

Then modify the `config.yml` accordingly (set your interface name and IP-address).

The port range can also be specified in the config. By default the range lies outside the Linux ephemeral port range (random port range) used by normal applications.

**Run the scan:**
```
sudo go run dns_over_udp.go [net-to-scan-in-CIDR|filename-of-ip-list]
```

Results are written to `udp_results.csv.gz` and are in a similiar format as the `tcp_results_combined.csv.gz`.



## DNS Traceroute Tools
These tools measure the path to and beyond transparent DNS forwarders. 
### DNS over TCP Traceroute
Sends out SYN packets with increasing IP TTL values.
As soon as a SYN/ACK arrives, the tool starts to send DNS requests over TCP with increasing IP TTL to explore the path between scanner over target to DNS resolver.

**Usage**
```
sudo go run dns_traceroute_tcp.go [target-ip]
```

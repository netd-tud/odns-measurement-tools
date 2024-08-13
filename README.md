# Collection of ODNS Measurement Tools

An implementation to measure the open DNS infrastructure using various Protocols over IPv4 (for now DNS-over-TCP & DNS-over-UDP).
It comprises all ODNS components: 
- Recursive resolvers
- Recursive forwarders
- Transparent forwarders

Regular scan results are published under http://odns.secnow.net.

The data of the last scan can be accessed via an API on https://odns-data.netd.cs.tu-dresden.de/. 

# Usage
```
  -c, --config [string]
    	Path to configuration file
  -e, --ethernet
    	dns_tool will manually craft the ethernet header
  --help
    	Display help
  -m, --mode [string]
    	available modes: <(s|scan) | (t|trace|traceroute) | (r|rate|ratelimit)>
  -o, --out [string]
    	output file path
  --profile
    	enable cpu profiling (output file: cpu.prof)
  -p, --protocol [string]
    	available protocols: tcp, udp
  -r --rate [int]
    	overwrites packet rate set in the config in pkt/s, -1 for unlimited (default -2)
  -v, --verbose [int]
    	overwrites the debug level set in the config (default -1, 1-6)
  -q, --qname [string]
      overwrites the dns query name
  -port [int]
      overwrites the port
```

## DNS over TCP

**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The config template is located at ` src/scanner/tcp/config.yml.template`

**Run the scan:**
```
cd src
sudo go run dns_tool.go --mode scan --protocol tcp --config scanner/tcp/config.yml <net-to-scan-in-CIDR|filename-of-ip-list>
```

Results are written to `tcp_results.csv.gz`

**Postprocessing:**

Transform the data into a format useful for classification:
```
python3 src/postprocessing/postproc_data_tcp_pure.py <input_file> <output_file>
```

## DNS over UDP

**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The config template is located at ` src/scanner/udp/config.yml.template`

The port range can also be specified in the config. By default the range lies outside the Linux ephemeral port range (random port range) used by normal applications.

**Run the scan:**
```
cd src
sudo go run dns_tool.go --mode scan --protocol udp --config scanner/udp/config.yml [net-to-scan-in-CIDR|filename-of-ip-list]
```

Results are written to `udp_results.csv.gz`

**Postprocessing:**

Appends the type of forwarder to the results file

```
python3 src/postprocessing/postproc_data_udp_pure.py <input_file> <output_file>
```


## DNS Traceroute Tools
These tools measure the path to and beyond transparent DNS forwarders. 
### DNS over TCP - Traceroute
Sends out SYN packets with increasing IP TTL values.
As soon as a SYN/ACK arrives, the tool starts to send DNS requests over TCP with increasing IP TTL to explore the path between scanner over target to DNS resolver.

**Run the traceroute**
```
cd src
sudo go run dns_tool.go --mode traceroute --protocol tcp [target-ip|path-to-list-of-ips]
```

## DNS Rate Limit Testing

**Run the test**\
This requires:
- `scanner/udp/config_uniq.yml` with a reduced scan rate
- `ratelimit/config.yml` specifying a `rate_curve` and `dynamic_domain` (see ratelimit/config.yml.template)
```
cd src
sudo ratelimit/check_pub_resolvers.sh [in: last udp scan] [out: intermediate resolver scan file] [out: intersect file]
```
Results will be in `ratelimit_results/<timestamp>/`

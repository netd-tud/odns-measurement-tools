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
      overwrites the destination port (typically 53)
```

## Internet-wide DNS scanning

### DNS over TCP

**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The config template is located at `src/scanner/tcp/config.yml.template`

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

### DNS over UDP

**Setup:**
Modify the config accordingly (set your interface name and IP-address).

The config template is located at `src/scanner/udp/config.yml.template`

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


### Optional DNS follow-up queries

Both standalone scanners support an optional list of questions sent to the original
target after its first valid DNS response, including empty answers and DNS errors:

```yaml
follow_up_queries:
  - name: version.bind
    type: TXT
    class: CH
  - name: version.server
    type: TXT
    class: CH
```

Omit the list or use `follow_up_queries: []` to disable it. Each entry requires
`name`, `type` (`A`, `AAAA`, `DNSKEY`, `ANY`, or `TXT`), and `class` (`IN` or `CH`).
An optional trailing dot in the name is accepted.

When the initial target and response IPs match, each question is sent once with
recursion desired (RD=1). When they differ, each question is sent twice, with
RD=1 and RD=0. Both variants still go to the original target, using the scan's
protocol and destination port. RD=1 requests recursion; the target may forward,
answer locally, or refuse the query. Follow-up replies never trigger more queries.
Each TCP variant opens a fresh raw connection. Follow-ups omit EDNS/DNSSEC, share
the scan's probe rate limiter, and time out after 10 seconds without retries.
Traceroute, rate-limit tests, and internal discovery scans do not run follow-ups.

The primary scan CSV stays unchanged. Follow-ups are saved to a separate gzip CSV
(e.g. `tcp_results_followups.csv.gz` for `tcp_results.csv.gz`), with a header:

```text
parent_id;query_index;initial_response_ip;target_ip;response_ip;protocol;qname;qtype;qclass;request_rd;timestamp_request;timestamp_response;status;rcode;txt_json;dns_response_base64
```

`parent_id` links to the primary scan ID; `query_index` is zero-based. `request_rd`
records the sent value (1 or 0). `status` is `response`, `timeout`, or `reset`.
`rcode` is always a separate column, numeric for DNS replies (including 0 for
NOERROR) and empty for timeout/reset without a DNS reply. `txt_json` preserves
TXT records as arrays of string segments; `dns_response_base64` preserves the
whole DNS message without the TCP length prefix. There is one terminal row per
question/RD variant. Normal shutdown waits for pending follow-ups and flushes
both outputs. As with the existing scanner, TCP replies must fit in one complete
DNS frame in one TCP segment; general TCP stream reassembly is not implemented.

## DNS Traceroute Tools
These tools measure the path to and beyond transparent DNS forwarders. 
### DNS over TCP - Traceroute
Sends out SYN packets with increasing IP TTL values.
As soon as a SYN/ACK arrives, the tool starts to send DNS requests over TCP with increasing IP TTL to explore the path between scanner over target to DNS resolver.

**Run the traceroute**
```
cd src
sudo go run dns_tool.go --mode traceroute --protocol tcp --config scanner/traceroute/config.yml [target-ip|path-to-list-of-ips]
```

## DNS Rate Limit & Performance Testing

This component allows for rate limit and performance testing of DNS resolvers.
A specialized configuration and input file is required to run the tests.
The configuration template is located under ` src/ratelimit/config.yml.template`.
Please refer to [config.go](src/config/config.go) for an explanation of each parameter that can be adjusted.

**To run the rate limit testing:**\
The input file needs to be in a .csv.gz format, containing two columns: `ip_request` and `ip_response`.
The header needs to be present in the input file.
`ip_request` will be used as target IPs for the rate limit testing while they are grouped by their `ip_response` value respectively.
If `rate_response_ip_only` is set to `true` in the `config.yml` file, the `ip_response` column will be used as target addresses during the test, and the `ip_request` column can be dropped.

Either this can be done with the last UDP scan as follows:
```
cd src
sudo ratelimit/check_pub_resolvers.sh [in: last udp scan] [out: intermediate resolver scan file] [out: intersect file]
```

Or directly:
```
cd src
sudo go run dns_tool.go --mode ratelimit --config scanner/ratelimit/config.yml input.csv.gz
```

**To test the performance of a single resolver:**\
It sufficies to set the desired configuration and run the following:
```
cd src
sudo go run dns_tool.go --mode ratelimit --config scanner/ratelimit/config.yml <1.2.3.4>
```

Results will be in `ratelimit_results/<timestamp>_<config-settings>/`

# Fingerprinting
Fingerprinting of device vendor and model may be performed for ODNS components.
Please refer to [fingerprinting](src/fingerprinting/README.md) for any further instructions.

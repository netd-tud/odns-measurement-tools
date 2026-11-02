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
      output directory (scans default to ./data/raw)
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

Results are written below `./data/raw/tcp/<scan-start-timestamp>/`.

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

Results are written below `./data/raw/udp/<scan-start-timestamp>/`.

**Postprocessing:**

Appends the type of forwarder to the results file

```
python3 src/postprocessing/postproc_data_udp_pure.py <input_file> <output_file>
```


### Scan output directories

Use `--out /path/to/results` (or `-o /path/to/results`) to select the base directory.
Without this option, scans use `data/raw/` relative to the current working directory.
Protocol and scan-start directories are created automatically. For example, a UDP
scan starting at 15:04:22 UTC on 2026-11-02 produces:

```text
data/raw/udp/2026-11-02_15-04-22/
  odns_udp_scan_2026-11-02_15-04.csv.gz
  odns_udp_followup_queries_2026-11-02_15-04.csv.gz
```

The follow-up file is created when follow-up queries are enabled. TCP uses the
same layout with `tcp` in the directory and filenames. Both filenames use the
same scan-start timestamp in UTC; the directory also includes seconds. An
existing scan directory is rejected to prevent overwriting its results.

Separate UDP and TCP service templates and alternating two-day timers, including
output directory creation and overlap prevention, are available in
[`systemd/`](systemd/README.md).

### Polars postprocessing with follow-up results

The new `src/postprocessing/postproc_data_udp_followup.py` and
`src/postprocessing/postproc_data_tcp_followup.py` merge initial and follow-up
results without filtering out unexpected A-record answers. Each selected follow-up
adds its `txt_json` in a column named after the question (defaults: `version.server`
and `version.bind`), plus an `_rd0_used` flag recording whether the RD=0 fallback supplied it.
They annotate DNS errors, missing control records, unexpected question names,
and IP inconsistencies. See [usage and output fields](src/postprocessing/README.md).
Processing uses disk partitions with an approximate 1024 MiB RAM target by default;
`--memory-mb`, `--workers`, and `--temp-dir` control memory, parallelism, and temporary storage.

### Optional DNS follow-up queries

Both standalone scanners support an optional list of questions sent to the original
target after its first valid DNS response, including empty answers and DNS errors:

```yaml
follow_up_nsid: true
follow_up_rd: "1"  # "1", "0", or "both"
follow_up_interval: 1s
follow_up_use_same_port: true
follow_up_queries:
  - name: version.bind
    type: TXT
    class: CH
  - name: version.server
    type: TXT
    class: CH
  - name: id.server
    type: TXT
    class: CH
  - name: hostname.bind
    type: TXT
    class: CH
  - name: authors.bind
    type: TXT
    class: CH
```

Omit the list or use `follow_up_queries: []` to disable it. Each entry requires
`name`, `type` (`A`, `AAAA`, `DNSKEY`, `ANY`, or `TXT`), and `class` (`IN` or `CH`).
An optional trailing dot in the name is accepted.

`follow_up_rd` selects the recursion desired bit for every configured question:
`"1"` sends only RD=1 (the default), `"0"` sends only RD=0, and `"both"` sends
RD=1 followed by RD=0 for each question. This applies whether the initial target
and response IPs match or differ. Both variants retain the same `query_index`;
the `request_rd` column distinguishes them. Queries go to the original target,
using the scan's protocol and destination port. RD=1 requests recursion; the
target may forward, answer locally, or refuse the query. Follow-up replies never
trigger more queries. Each TCP follow-up opens a fresh raw connection.

`follow_up_interval` sets a minimum gap between follow-up DNS queries to the same
target IP, including the two RD variants in `both` mode, for both UDP and TCP.
It accepts durations such as `1s` or `250ms`;
omitting it or setting `0s` keeps the previous behavior with no additional gap.
The first follow-up can be sent immediately. Other target IPs continue independently,
and all follow-ups still share the scan's packet rate limit. For TCP, the gap starts
after the DNS query is sent, following its handshake; a failed handshake releases
the next query after the interval. This setting does not change the 10-second
response timeout, which starts only when a follow-up is launched.

`follow_up_use_same_port: true` (the default) reuses the initial query's exact
source port for every follow-up, including both RD variants. TCP waits for the
primary connection and each preceding follow-up connection to close before
reusing that port. If the primary connection stalls, it is reset on timeout before
follow-ups start.

To use a separate source-port pool, configure:

```yaml
port_min: 61440
port_max: 65535
follow_up_use_same_port: false
follow_up_port_min: 50000
follow_up_port_max: 51000
```

Both follow-up bounds are required and must not overlap `port_min`/`port_max`.
TCP also rejects overlap with its existing fixed primary range, 61440–63487.
The scanner reserves available ports in the configured range and skips ports
already in use. Each follow-up leases one port until its response, reset or
timeout; TCP retains the lease until the connection closes or expires. If all
ports are busy, follow-ups wait for a free port without consuming their response
timeout. A scan fails at startup if no port in the pool can be reserved.

`follow_up_nsid: true` adds an empty NSID option (code 3) in an EDNS OPT record to
every follow-up, over either UDP or TCP. It does not send a separate query. The
option defaults to false; NSID requires EDNS, which this setting adds automatically
without enabling DNSSEC. Initial scan queries are unaffected. Servers may omit NSID
or reject the query, and a transparent proxy may return an upstream identifier.
NSID is an opaque identifier, not necessarily a software version. Follow-ups share
the scan's probe rate limiter and time out after 10 seconds without retries.
Traceroute, rate-limit tests, and internal discovery scans do not run follow-ups.

Existing primary CSV columns retain their positions. New primary rows append
`rcode` and `response_qnames` (a JSON array; empty TCP packet fields before a DNS
response). The Polars postprocessors accept both old and extended formats.
This metadata is written even when follow-ups are disabled: numeric `rcode` is
column 13 for UDP and column 9 for TCP (counting from 1), including `0` for
NOERROR, `2` for SERVFAIL and `5` for REFUSED. TCP packets without a DNS response
have an empty RCODE field. Primary CSVs have no header.
Follow-ups are saved to a separate gzip CSV
(e.g. `odns_tcp_followup_queries_2026-11-02_15-04.csv.gz`), with a header:

```text
parent_id;query_index;initial_response_ip;target_ip;response_ip;protocol;qname;qtype;qclass;request_rd;timestamp_request;timestamp_response;status;rcode;txt_json;dns_response_base64;nsid_hex
```

`parent_id` links to the primary scan ID; `query_index` is zero-based. `request_rd`
records the sent value (always 1 for new scans). `status` is `response`, `timeout`, or `reset`.
`rcode` is always a separate column, numeric for DNS replies (including 0 for
NOERROR) and empty for timeout/reset without a DNS reply. `txt_json` preserves
TXT records as arrays of string segments; `dns_response_base64` preserves the
whole DNS message without the TCP length prefix. The appended `nsid_hex` column
contains the returned NSID as hexadecimal, or is empty when none is returned.
Existing columns retain their positions. There is one terminal row per question.
Normal shutdown waits for pending follow-ups and flushes both outputs.
As with the existing scanner, TCP replies must fit in one complete
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

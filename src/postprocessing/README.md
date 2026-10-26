# Polars scan and follow-up postprocessing

The new `postproc_data_udp_followup.py` and `postproc_data_tcp_followup.py` retain
responses even when the expected control A-record pattern is absent. The existing
`*_pure.py` scripts retain their original behavior.

Install the runtime dependencies, preferably in a virtual environment:

```bash
python3 -m pip install -r src/postprocessing/requirements.txt
```

From `src/`, run either transport's entry point:

```bash
python3 postprocessing/postproc_data_udp_followup.py \
  udp_results.csv.gz udp_results_followups.csv.gz udp_merged.parquet \
  --expected-qname rr-mirror.research.nawrocki.berlin

python3 postprocessing/postproc_data_tcp_followup.py \
  tcp_results.csv.gz tcp_results_followups.csv.gz tcp_merged.parquet \
  --expected-qname rr-mirror.research.nawrocki.berlin
```

Set `--expected-qname` to the **actual initial query**, including any scanner CLI
override. `--control-ip` defaults to `91.216.216.216`; change it for another control
answer. The expected A-record pattern is exactly one control A record and one
other IPv4 A record. Record order does not matter. This is an annotation rule,
not a filter.

## Output and joins

- Inputs can be plain CSV or gzip CSV. Primary inputs are headerless scanner
  files; follow-up inputs have a header. Quoted CSV fields are parsed correctly.
- Output can be `.parquet` (recommended), `.csv`, or `.csv.gz`. Parquet output
  uses Zstandard compression. Each output file is replaced atomically on success.
- TCP's SYN, SYN/ACK, and DNS response packet rows are collapsed by probe ID.
  The target comes from SYN; the replying IP comes from the DNS response packet,
  which can differ from the SYN/ACK address. Incomplete connections present in
  the input are retained.
- Follow-ups join on **probe ID, target IP, and initial DNS-response IP**.
  A matching ID with inconsistent IPs does not attach data to the wrong primary
  row: both the primary row and unmatched follow-up row are retained separately.
  Follow-up-only probes are also retained with `primary_present=false`.
- The actual follow-up reply IP may differ from the initial reply IP. Such
  results remain attached to their correct probe, with
  `reply_ip_matches_initial=false` and a warning. A transparent forwarder's
  target differing from its initial reply IP is not itself an inconsistency.
- Every question gets distinct columns, for example:
  `rcode__udp_q0_version_bind_txt_ch_rd1`,
  `txt_json__udp_q0_version_bind_txt_ch_rd1`, and
  `response_ip__udp_q0_version_bind_txt_ch_rd1`.
  Suffixes include transport, configuration index, query name, type, class, and
  RD, so older RD=0/RD=1 files and repeated configured names stay separate.
- Follow-up columns retain statuses, numeric/readable RCODEs, TXT, NSID, returned
  question names, timestamps, and DNS payloads. Use `--omit-payloads` to omit the
  wide Base64 columns. Other result data remains available.
- Process one scan and its corresponding follow-up file per invocation. Duplicate
  primary IDs, conflicting TCP addresses for an ID, duplicate follow-up keys, or
  colliding normalized query suffixes cause an explicit error instead of silently
  overwriting a result or multiplying join rows. Follow-up files from the wrong
  transport are rejected explicitly.

The scripts normalize each compressed input once to temporary Parquet, then use
Polars lazy scans, native aggregations/joins, and streaming sinks. DNS header and
question decoding is performed in batches; the scripts do not parse every
answer record in Python. Use `--temp-dir /path/with/space` to choose where the
intermediate Parquet files are stored. Intermediates are removed after the run.

## Expected-answer diagnostics

Primary output contains `rcode`, `rcode_name`, `response_qnames` (a JSON array),
`a_record_count`, `control_a_present`, `a_record_pattern_matches`,
`answer_matches_expected`, `answer_deviation`, `resolver_ip`, and `odns_type`.
`answer_deviation` contains zero or more `|`-separated reasons:

| Reason | Meaning |
| --- | --- |
| `rcode_not_success` | RCODE is nonzero; `rcode_name` identifies the error. |
| `no_a_records` | A DNS response contains no stored A records. |
| `single_a_record_control_only` | The only A record is the control address. |
| `single_a_record_control_missing` | One A record is present and it is not the control address. |
| `control_a_record_missing` | Multiple A records are present, without the control address. |
| `only_control_a_records` | Multiple records contain only the control address. |
| `unexpected_a_record_count` | More than two A records are present. |
| `invalid_a_record` | The stored A-record field contains a non-IPv4 value. |
| `wrong_query_name` | Returned question names differ from the expected name; see `response_qnames`. |
| `response_question_missing` | The response has no question section. |
| `multiple_response_questions` | More than one question was returned. |
| `no_dns_response` | TCP input contains no DNS response packet for the probe. |
| `rcode_unknown` / `question_name_unknown` | The input did not preserve this metadata. |

An empty `answer_deviation` means all checks passed. `answer_matches_expected` is
true when the answer passes all checks, false when a known deviation exists,
and null when missing metadata prevents a conclusion. Structural ODNS
classification can still be provided from the A-record pattern when unavailable
legacy metadata is the only uncertainty. Unclassifiable rows use `Unknown`.

Follow-up RCODEs are independent of the initial query's RCODE. They are never
used to fill in an unknown initial RCODE. Follow-up question names are decoded
from the Base64 DNS payload and compared against that follow-up's requested name.
Malformed or unavailable payloads are retained with diagnostic columns.

Warnings, counts, and up to ten IP-mismatch examples are logged to stderr. A full
long-form issue report is written to `OUTPUT.issues.csv` by default. Override
this path with `--issues-output`. It includes observed and expected IP addresses
and covers initial-answer deviations, follow-up errors, IP mismatches, and
follow-up probes missing a primary record.

## New and older scanner files

New scanner outputs append two fields to the primary CSVs:

| Protocol | Existing columns | Appended fields |
| --- | --- | --- |
| UDP | 12 | `rcode`, `response_qnames` |
| TCP | 8 per packet | `rcode`, `response_qnames`; empty for non-DNS packets |

Existing column positions are preserved. Older 12-column UDP and 8-column TCP
files are accepted. UDP's standard four-bit RCODE can be recovered from
`dns_flags`; old TCP RCODEs and old primary question names cannot be recovered
and are explicitly marked unknown. Follow-up files with or without `nsid_hex`
are supported.

The scripts cannot reconstruct responses the scanner never wrote. In particular,
legacy TCP scans may omit connections that did not reach the original FIN/result
writing path or that contained non-IP answers. Available follow-up-only probes
are retained, but their missing initial answers are not invented.

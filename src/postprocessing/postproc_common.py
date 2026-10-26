"""DNS postprocessing retaining unexpected answers, with joins in Polars.

Gzip CSVs are normalized to temporary Parquet once. All further joins, checks,
and wide aggregations read those columnar files instead of repeatedly inflating
the source files. Only DNS wire question decoding runs in Python, in batches.
"""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import ipaddress
import json
import logging
import os
import struct
import tempfile
from pathlib import Path

import dns.name
import dns.rcode
import polars as pl

LOG = logging.getLogger("dns-postprocessing")
CONTROL_IP = "91.216.216.216"
UDP_COLUMNS = [
    "id", "target_ip", "response_ip", "a_records", "timestamp_request",
    "timestamp_response", "port", "dnsid", "dns_pkt_size", "dns_rrs",
    "dns_flags", "dns_ttl", "rcode", "response_qnames",
]
TCP_COLUMNS = [
    "id", "timestamp", "ip", "port", "seq", "ack", "flags", "a_records",
    "rcode", "response_qnames",
]
JOIN_KEYS = ["id", "target_ip", "response_ip"]
RCODES = {int(code): dns.rcode.to_text(code) for code in dns.rcode.Rcode}
OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])"
IPV4_PATTERN = rf"^(?:{OCTET}\.){{3}}{OCTET}$"
WIRE_SCHEMA = pl.Struct({
    "response_qnames": pl.String, "wire_rcode": pl.Int64,
    "wire_qr": pl.Boolean, "dns_decode_error": pl.String,
})


def scan_primary(path: Path, protocol: str) -> pl.LazyFrame:
    columns = UDP_COLUMNS if protocol == "udp" else TCP_COLUMNS
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", newline="") as handle:
        first = next(csv.reader(handle, delimiter=";"), None)
    width = len(first) if first is not None else len(columns)
    if width not in (len(columns) - 2, len(columns)):
        raise ValueError(f"{path}: expected {len(columns)-2} or {len(columns)} columns, got {width}")
    raw = pl.scan_csv(
        path, has_header=False, separator=";", glob=False,
        schema={name: pl.String for name in columns[:width]}, raise_if_empty=False,
    )
    if width < len(columns):
        raw = raw.with_columns(*(pl.lit(None, dtype=pl.String).alias(c) for c in columns[width:]))
    raw = raw.with_columns(pl.col("id").cast(pl.UInt64))
    if protocol == "udp":
        return raw.with_columns(
            pl.coalesce(
                pl.col("rcode").cast(pl.Int64),
                pl.col("dns_flags").cast(pl.Int64) % 16,
            ).alias("rcode"),
            pl.lit(True).alias("has_dns_response"),
            pl.lit(True).alias("primary_present"),
        )

    # TCP stores multiple packet rows per probe; response address is from the
    # DNS-bearing packet, never the SYN/ACK (transparent forwarding can differ).
    is_response = pl.col("flags").is_in(["PA", "FPA"]) | pl.col("rcode").is_not_null()
    grouped = raw.group_by("id").agg(
        pl.col("ip").filter(pl.col("flags") == "S").first().alias("target_ip"),
        pl.col("ip").filter(is_response).first().alias("response_ip"),
        pl.col("timestamp").filter(pl.col("flags") == "S").first().alias("timestamp_request"),
        pl.col("timestamp").filter(is_response).first().alias("timestamp_response"),
        *(pl.col(c).filter(is_response).first().alias(c) for c in ["a_records", "rcode", "response_qnames"]),
        pl.col("port").first(),
        pl.col("flags").str.join(",").alias("tcp_flags"),
        (pl.col("flags") == "S").any().alias("has_syn"),
        (pl.col("flags") == "SA").any().alias("has_syn_ack"),
        is_response.any().alias("has_dns_response"),
        pl.col("ip").filter(pl.col("flags") == "S").n_unique().alias("_targets"),
        pl.col("ip").filter(is_response).n_unique().alias("_responders"),
        pl.len().alias("tcp_packet_rows"),
    )
    return grouped.with_columns(
        pl.col("rcode").cast(pl.Int64), pl.lit(True).alias("primary_present"),
    )


def rcode_name(column: str = "rcode") -> pl.Expr:
    code = pl.col(column)
    return code.replace_strict(
        RCODES, default=pl.concat_str(pl.lit("RCODE"), code.cast(pl.String)),
        return_dtype=pl.String,
    ).fill_null("UNKNOWN")


def reasons(entries: list[tuple[pl.Expr, str]]) -> pl.Expr:
    return pl.concat_list([
        pl.when(condition.fill_null(False)).then(pl.lit(text)).otherwise(pl.lit(None, dtype=pl.String))
        for condition, text in entries
    ]).list.drop_nulls().list.join("|")


def question_checks(frame: pl.LazyFrame, expected: pl.Expr) -> pl.LazyFrame:
    return frame.with_columns(
        pl.col("response_qnames").str.json_decode(pl.List(pl.String)).alias("_qnames"),
    ).with_columns(
        pl.when(pl.col("_qnames").is_not_null()).then(
            (pl.col("_qnames").list.len() == 1)
            & (pl.col("_qnames").list.first().str.to_lowercase().str.strip_suffix(".") == expected)
        ).otherwise(None).alias("query_name_matches"),
    )


def annotate_primary(frame: pl.LazyFrame, expected_qname: str, control_ip: str) -> pl.LazyFrame:
    frame = question_checks(frame, pl.lit(expected_qname))
    frame = frame.with_columns(
        pl.col("a_records").fill_null("").str.split(",").list.eval(
            pl.element().str.strip_chars().filter(pl.element().str.strip_chars() != "")
        ).alias("_a"),
        rcode_name().alias("rcode_name"),
    ).with_columns(
        pl.col("_a").list.len().alias("a_record_count"),
        pl.col("_a").list.contains(control_ip).alias("control_a_present"),
        pl.col("_a").list.eval(pl.element().str.contains(IPV4_PATTERN)).list.all().alias("_valid_a_records"),
        pl.col("_a").list.eval(pl.element().filter(pl.element() != control_ip)).alias("_non_control"),
    ).with_columns(
        ((pl.col("a_record_count") == 2) & pl.col("control_a_present")
         & (pl.col("_non_control").list.len() == 1) & pl.col("_valid_a_records")).alias("a_record_pattern_matches"),
    )
    known_issues = [
        (~pl.col("has_dns_response"), "no_dns_response"),
        (pl.col("rcode") != 0, "rcode_not_success"),
        (pl.col("has_dns_response") & (pl.col("a_record_count") == 0), "no_a_records"),
        ((pl.col("a_record_count") == 1) & pl.col("control_a_present"), "single_a_record_control_only"),
        ((pl.col("a_record_count") == 1) & ~pl.col("control_a_present"), "single_a_record_control_missing"),
        ((pl.col("a_record_count") > 1) & ~pl.col("control_a_present"), "control_a_record_missing"),
        ((pl.col("a_record_count") > 1) & (pl.col("_non_control").list.len() == 0), "only_control_a_records"),
        (pl.col("a_record_count") > 2, "unexpected_a_record_count"),
        (~pl.col("_valid_a_records"), "invalid_a_record"),
        (pl.col("_qnames").list.len() == 0, "response_question_missing"),
        (pl.col("_qnames").list.eval(
            pl.element().str.to_lowercase().str.strip_suffix(".") != expected_qname
        ).list.any(), "wrong_query_name"),
        (pl.col("_qnames").list.len() > 1, "multiple_response_questions"),
        (pl.col("target_ip").is_null(), "primary_target_ip_missing"),
    ]
    unknown_issues = [
        (pl.col("rcode").is_null() & pl.col("has_dns_response"), "rcode_unknown"),
        (pl.col("_qnames").is_null() & pl.col("has_dns_response"), "question_name_unknown"),
    ]
    known = pl.any_horizontal([expr.fill_null(False) for expr, _ in known_issues])
    unknown = pl.any_horizontal([expr.fill_null(False) for expr, _ in unknown_issues])
    classifiable = (pl.col("a_record_pattern_matches")
                    & (pl.col("rcode").is_null() | (pl.col("rcode") == 0))
                    & pl.col("query_name_matches").fill_null(True))
    return frame.with_columns(
        pl.lit(expected_qname).alias("expected_qname"), pl.lit(control_ip).alias("control_ip"),
        pl.when(known).then(False).when(unknown).then(None).otherwise(True).alias("answer_matches_expected"),
        reasons(known_issues + unknown_issues).alias("answer_deviation"),
        pl.when(classifiable).then(pl.col("_non_control").list.first()).otherwise(None).alias("resolver_ip"),
        pl.when(~classifiable).then(pl.lit("Unknown"))
        .when(pl.col("target_ip") != pl.col("response_ip")).then(pl.lit("Transparent Forwarder"))
        .when(pl.col("_non_control").list.first() == pl.col("response_ip")).then(pl.lit("Resolver"))
        .otherwise(pl.lit("Forwarder")).alias("odns_type"),
    ).drop("_qnames", "_a", "_non_control", "_valid_a_records")


def decode_questions(series: pl.Series) -> pl.Series:
    """Decode just the DNS header/questions; do not parse every answer RR in Python."""
    result = []
    for value in series:
        names, code, qr, error = None, None, None, None
        if value:
            try:
                wire = base64.b64decode(value, validate=True)
                _, flags, count = struct.unpack_from("!HHH", wire)
                if len(wire) < 12:
                    raise ValueError("short DNS header")
                offset, names = 12, []
                for _ in range(count):
                    name, used = dns.name.from_wire(wire, offset)
                    offset += used
                    if offset + 4 > len(wire):
                        raise ValueError("short DNS question")
                    offset += 4
                    names.append(name.to_text(omit_final_dot=True))
                names, code, qr = json.dumps(names), flags & 15, bool(flags & 0x8000)
            except Exception as exc:
                names, error = None, f"{type(exc).__name__}: {exc}"
        result.append({"response_qnames": names, "wire_rcode": code, "wire_qr": qr, "dns_decode_error": error})
    return pl.Series(result, dtype=WIRE_SCHEMA)


def scan_followups(path: Path, protocol: str) -> pl.LazyFrame:
    frame = pl.scan_csv(path, separator=";", infer_schema=False, glob=False)
    schema = frame.collect_schema()
    required = {"parent_id", "query_index", "initial_response_ip", "target_ip", "response_ip",
                "protocol", "qname", "qtype", "qclass", "request_rd", "timestamp_request",
                "timestamp_response", "status", "rcode", "txt_json", "dns_response_base64"}
    if missing := required - set(schema.names()):
        raise ValueError(f"{path}: missing follow-up columns: {sorted(missing)}")
    if "nsid_hex" not in schema:
        frame = frame.with_columns(pl.lit(None, dtype=pl.String).alias("nsid_hex"))
    frame = frame.rename({"parent_id": "id", "response_ip": "followup_response_ip"}).with_columns(
        pl.col("id").cast(pl.UInt64), pl.col("query_index").cast(pl.UInt32),
        pl.col("request_rd").cast(pl.UInt8), pl.col("rcode").cast(pl.Int64),
        pl.col("qname").str.to_lowercase().str.strip_suffix("."),
    ).with_columns(
        pl.col("dns_response_base64").map_batches(decode_questions, return_dtype=WIRE_SCHEMA, is_elementwise=True).alias("_wire"),
    ).unnest("_wire")
    frame = question_checks(frame, pl.col("qname"))
    entries = [
        (pl.col("protocol") != protocol, "protocol_mismatch"),
        ((pl.col("status") == "response") & (pl.col("rcode") != 0), "rcode_not_success"),
        ((pl.col("status") == "response") & pl.col("rcode").is_null(), "rcode_unknown"),
        ((pl.col("status") == "response") & pl.col("_qnames").is_null(), "question_name_unknown"),
        ((pl.col("status") == "response") & pl.col("dns_response_base64").is_null(), "dns_payload_missing"),
        (pl.col("dns_decode_error").is_not_null(), "dns_decode_error"),
        ((pl.col("status") == "response") & (pl.col("_qnames").list.len() == 0), "response_question_missing"),
        ((pl.col("status") == "response") & (pl.col("_qnames").list.len() > 0) & ~pl.col("query_name_matches"), "wrong_query_name"),
        (pl.col("wire_qr") == False, "not_dns_response"),
        ((pl.col("rcode") % 16) != pl.col("wire_rcode"), "rcode_payload_mismatch"),
        (pl.col("status") == "timeout", "timeout"), (pl.col("status") == "reset", "reset"),
    ]
    return frame.with_columns(
        rcode_name().alias("rcode_name"), reasons(entries).alias("followup_deviation"),
        pl.concat_str([
            pl.lit(protocol + "_q"), pl.col("query_index"), pl.lit("_"),
            pl.col("qname").str.replace_all(r"[^a-z0-9]+", "_"), pl.lit("_"),
            pl.col("qtype").str.to_lowercase(), pl.lit("_"), pl.col("qclass").str.to_lowercase(),
            pl.lit("_rd"), pl.col("request_rd"),
        ]).alias("query_suffix"),
    ).drop("_qnames")


def require_unique(frame: pl.LazyFrame, keys: list[str], label: str) -> None:
    bad = frame.group_by(keys).len().filter(pl.col("len") > 1).limit(5).collect(engine="streaming")
    if bad.height:
        raise ValueError(f"{label}: duplicate keys would make the wide join ambiguous: {bad.to_dicts()}")


def write_output(frame: pl.LazyFrame, path: Path) -> None:
    if not str(path).endswith((".parquet", ".csv", ".csv.gz")):
        raise ValueError("output must end in .parquet, .csv, or .csv.gz")
    with tempfile.NamedTemporaryFile(prefix=".odns-postproc-", suffix="".join(path.suffixes), dir=path.parent, delete=False) as handle:
        temporary = Path(handle.name)
    try:
        if str(path).endswith(".parquet"):
            frame.sink_parquet(temporary, compression="zstd", engine="streaming")
        else:
            frame.sink_csv(temporary, separator=";", compression="gzip" if path.suffix == ".gz" else "uncompressed", engine="streaming")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def process(protocol: str, results: Path, followups: Path, output: Path, *,
            expected_qname: str, control_ip: str = CONTROL_IP, issues_output: Path | None = None,
            temp_dir: Path | None = None, omit_payloads: bool = False) -> None:
    expected_qname = expected_qname.rstrip(".").lower()
    if not expected_qname:
        raise ValueError("expected query name must not be empty")
    ipaddress.IPv4Address(control_ip)
    issues_output = issues_output or Path(str(output) + ".issues.csv")
    paths = [results.resolve(), followups.resolve(), output.resolve(), issues_output.resolve()]
    if len(set(paths)) != len(paths):
        raise ValueError("input, output, and issue-report paths must be distinct")
    with tempfile.TemporaryDirectory(prefix="odns-postproc-", dir=temp_dir) as work:
        work = Path(work)
        LOG.info("Normalizing %s primary results", protocol.upper())
        primary_path = work / "primary.parquet"
        annotate_primary(scan_primary(results, protocol), expected_qname, control_ip).sink_parquet(primary_path, engine="streaming")
        primary = pl.scan_parquet(primary_path)
        if protocol == "tcp":
            conflicts = primary.filter((pl.col("_targets") > 1) | (pl.col("_responders") > 1)).limit(5).collect(engine="streaming")
            if conflicts.height:
                raise ValueError(f"ambiguous TCP probe IDs with multiple target/response IPs: {conflicts.to_dicts()}")
            primary = primary.drop("_targets", "_responders")
        require_unique(primary, ["id"], "primary results (process one scan per invocation)")
        primary_lookup = primary.select(
            "id", pl.col("target_ip").alias("_primary_target_ip"),
            pl.col("response_ip").alias("_primary_response_ip"),
            pl.col("primary_present").alias("_parent_present"),
        )
        LOG.info("Normalizing and validating follow-ups")
        joined = scan_followups(followups, protocol).join(primary_lookup, on="id", how="left", validate="m:1")
        joined = joined.with_columns(
            (pl.col("target_ip") == pl.col("_primary_target_ip")).alias("target_ip_matches"),
            (pl.col("initial_response_ip") == pl.col("_primary_response_ip")).alias("initial_response_ip_matches"),
            pl.when(pl.col("status") == "response").then(
                pl.col("followup_response_ip") == pl.col("_primary_response_ip")
            ).otherwise(None).alias("reply_ip_matches_initial"),
        ).with_columns(reasons([
            (pl.col("_parent_present").is_null(), "primary_result_missing"),
            (pl.col("_parent_present").is_not_null() & pl.col("_primary_response_ip").is_null(), "initial_response_ip_unknown"),
            (pl.col("target_ip_matches") == False, "target_ip_mismatch"),
            (pl.col("initial_response_ip_matches") == False, "initial_response_ip_mismatch"),
            (pl.col("reply_ip_matches_initial") == False, "followup_reply_ip_differs"),
        ]).alias("ip_issues"))
        followup_path = work / "followups.parquet"
        joined.sink_parquet(followup_path, engine="streaming")
        joined = pl.scan_parquet(followup_path)
        bad_protocols = joined.filter((pl.col("protocol") != protocol) | pl.col("protocol").is_null()).select("protocol").unique().collect(engine="streaming")
        if bad_protocols.height:
            raise ValueError(f"follow-up protocol does not match {protocol}: {bad_protocols.to_dicts()}")
        followup_keys = ["id", "target_ip", "initial_response_ip", "query_suffix"]
        require_unique(joined, followup_keys, "follow-up results")
        specs = joined.select("query_suffix", "query_index", "qname", "qtype", "qclass", "request_rd").unique().sort("query_index", "query_suffix").collect(engine="streaming")
        if specs["query_suffix"].n_unique() != specs.height:
            raise ValueError("follow-up query names collide after column-name normalization")

        primary_issues = primary.filter(pl.col("answer_deviation") != "").select(
            "id", "target_ip", pl.col("response_ip").alias("initial_response_ip"),
            pl.lit(None, dtype=pl.String).alias("followup_response_ip"),
            pl.lit("initial").alias("query_suffix"), pl.col("answer_deviation").alias("issue"),
            pl.col("target_ip").alias("expected_target_ip"), pl.col("response_ip").alias("expected_initial_response_ip"),
        )
        followup_issues = joined.with_columns(
            pl.concat_list("followup_deviation", "ip_issues").list.eval(pl.element().filter(pl.element() != "")).list.join("|").alias("issue")
        ).filter(pl.col("issue") != "").select(
            "id", "target_ip", "initial_response_ip", "followup_response_ip", "query_suffix", "issue",
            pl.col("_primary_target_ip").alias("expected_target_ip"),
            pl.col("_primary_response_ip").alias("expected_initial_response_ip"),
        )
        report = pl.concat([primary_issues, followup_issues], how="vertical")
        write_output(report, issues_output)
        summary = report.select(pl.col("issue").str.split("|")).explode("issue").group_by("issue").len().sort("issue").collect(engine="streaming")
        for row in summary.iter_rows(named=True):
            LOG.warning("%s: %d", row["issue"], row["len"])
        examples = followup_issues.filter(pl.col("issue").str.contains("ip_mismatch|ip_differs")).limit(10).collect(engine="streaming")
        for example in examples.iter_rows(named=True):
            LOG.warning("IP consistency: %s", example)

        fields = [
            "query_index", "protocol", "qname", "qtype", "qclass", "request_rd",
            "followup_response_ip", "status", "rcode", "rcode_name", "txt_json", "nsid_hex",
            "timestamp_request", "timestamp_response", "response_qnames", "query_name_matches",
            "dns_decode_error", "followup_deviation", "target_ip_matches", "initial_response_ip_matches",
            "reply_ip_matches_initial", "ip_issues",
        ]
        if not omit_payloads:
            fields.append("dns_response_base64")
        aggregations = []
        for suffix in specs["query_suffix"]:
            mask = pl.col("query_suffix") == suffix
            for field in fields:
                label = "response_ip" if field == "followup_response_ip" else field
                aggregations.append(pl.col(field).filter(mask).first().alias(f"{label}__{suffix}"))
        if aggregations:
            wide = joined.group_by("id", "target_ip", "initial_response_ip").agg(aggregations).rename({"initial_response_ip": "response_ip"})
            merged = primary.join(wide, on=JOIN_KEYS, how="full", coalesce=True, validate="1:1")
        else:
            merged = primary
        merged = merged.with_columns(
            pl.lit(protocol).alias("protocol"),
            pl.col("primary_present").fill_null(False),
            pl.when(pl.col("primary_present").is_null()).then(pl.lit("primary_result_missing|rcode_unknown|question_name_unknown"))
            .otherwise(pl.col("answer_deviation")).alias("answer_deviation"),
        )
        LOG.info("Writing %s; issue report: %s", output, issues_output)
        write_output(merged, output)


def main(protocol: str) -> None:
    parser = argparse.ArgumentParser(description=f"Merge {protocol.upper()} scan/follow-up results without A-record filtering.")
    parser.add_argument("results", type=Path)
    parser.add_argument("followups", type=Path)
    parser.add_argument("output", type=Path, help=".parquet (recommended), .csv, or .csv.gz")
    parser.add_argument("--expected-qname", required=True, help="initial dns_query used for this scan")
    parser.add_argument("--control-ip", default=CONTROL_IP)
    parser.add_argument("--issues-output", type=Path, help="default: OUTPUT.issues.csv")
    parser.add_argument("--temp-dir", type=Path, help="directory with space for normalized Parquet files")
    parser.add_argument("--omit-payloads", action="store_true", help="omit wide Base64 DNS payload columns")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    try:
        process(protocol, **vars(args))
    except (ValueError, OSError, pl.exceptions.PolarsError) as exc:
        LOG.error("%s", exc)
        raise SystemExit(2) from exc


# Run scans with systemd

The service templates run one scan each:

- `odns-udp-scan.service.template`: UDP scan.
- `odns-tcp-scan.service.template`: TCP scan.

All service and timer files in this directory end in `.template`. Copy and edit
them for your installation; remove `.template` from the installed filenames.

Matching timer files schedule alternating scans. Enable both timers together:

| Protocol | First scan after timer activation | Repeat interval |
| --- | --- | --- |
| UDP | 1 minute | 48 hours |
| TCP | 1 day and 1 minute | 48 hours |

This uses elapsed time rather than odd/even dates, so month boundaries do not
break the two-day interval. Restarting the timers or rebooting resets their
initial delays; scans missed while the machine is off are not caught up.

Build the scanner from the repository's `src/` directory:

```bash
go build -o dns_tool .
```

Edit copies of the service templates for your installation. Replace `/opt/odns-measurement-tools`
with your repository's absolute path in `WorkingDirectory`, `ExecStart`,
`SCAN_TARGET`, and `OUTPUT_DIR`. Configure the interface and DNS query in each
protocol's YAML configuration file.

`SCAN_CONFIG` selects the scan configuration. `SCAN_TARGET` is either a file with
one target IP per line or a CIDR network. Relative paths are resolved from
`WorkingDirectory` (`src/` by default), including the configuration's exclusion
file. `OUTPUT_DIR` is the base output directory; do not append the protocol to it.
Environment values use `${...}` in the commands so paths containing spaces remain
single arguments. Quote `WorkingDirectory` and the executable path in `ExecStart`
if your repository path contains spaces.

Each service creates its protocol directory with `mkdir -p` before starting:

```text
<OUTPUT_DIR>/udp/<scan-start>/odns_udp_scan_<yyyy-mm-dd_HH-MM>.csv.gz
<OUTPUT_DIR>/udp/<scan-start>/odns_udp_followup_queries_<yyyy-mm-dd_HH-MM>.csv.gz
<OUTPUT_DIR>/tcp/<scan-start>/odns_tcp_scan_<yyyy-mm-dd_HH-MM>.csv.gz
<OUTPUT_DIR>/tcp/<scan-start>/odns_tcp_followup_queries_<yyyy-mm-dd_HH-MM>.csv.gz
```

The scanner creates the timestamp directory using the scan start in UTC and
writes follow-up files when follow-ups are enabled. Existing protocol directories
are kept. The scanner also creates missing output directories when run directly.

Install the edited services and timers from the repository root:

```bash
sudo install -m 0644 systemd/odns-udp-scan.service.template /etc/systemd/system/odns-udp-scan.service
sudo install -m 0644 systemd/odns-tcp-scan.service.template /etc/systemd/system/odns-tcp-scan.service
sudo install -m 0644 systemd/odns-udp-scan.timer.template /etc/systemd/system/odns-udp-scan.timer
sudo install -m 0644 systemd/odns-tcp-scan.timer.template /etc/systemd/system/odns-tcp-scan.timer
sudo systemctl daemon-reload
sudo systemctl enable --now odns-udp-scan.timer odns-tcp-scan.timer
```

Enable the timers for periodic scans; leave the scan services disabled for boot.
Inspect the next runs with:

```bash
systemctl list-timers 'odns-*-scan.timer'
```

To stop periodic scheduling:

```bash
sudo systemctl disable --now odns-udp-scan.timer odns-tcp-scan.timer
```

Stopping a timer does not stop a scan already running. You can also start either
protocol manually:

```bash
sudo systemctl start odns-udp-scan.service
sudo systemctl start odns-tcp-scan.service
```

These commands return once the process has started. Each service exits when its
scan finishes and does not restart automatically. Start it again to run a new
scan. Manual service starts also reset that protocol's 48-hour repeat interval.

Both services use the same exclusive lock, `/run/lock/odns-scan.lock`. If one scan
is still running when the other is due, the new service waits for it to finish
before starting its scanner. This applies to manual starts as well as timer
starts. `flock` (provided by util-linux) must be installed. The lock is released
automatically when the scanner exits.

View progress or stop a scan:

```bash
sudo journalctl -fu odns-udp-scan.service
sudo systemctl stop odns-udp-scan.service
```

Use `odns-tcp-scan.service` for TCP. Services run as root for raw sockets and packet
capture. TCP also uses the scanner's existing `sudo iptables` commands, so both
`sudo` and `iptables` must be available. Stopping sends SIGINT for the scanner's
cleanup, with a 120-second limit before systemd forces termination.

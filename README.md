# LAN Discovery

LAN Discovery scans IP networks and shows hosts, open ports, service details,
operating system hints, security findings and an **inferred** network map. It
keeps scan history and device notes locally, and exports results as CSV, JSON or
HTML. The map estimates routes; it does not identify physical switch ports or
prove cabling.

## Install

Install the Debian package with `sudo apt install ./landiscovery_1.0.0_all.deb`.
The graphical application appears in the Network menu. Run `landiscovery gui`
or `lds gui` from a terminal. The package requires Python 3.11 or newer, GTK 3,
Nmap, arp-scan and polkit. Avahi tools and SNMP tools enable optional discovery.

## Scan

Enter an IP address or CIDR network, choose a profile and select **Start**.
Large and public ranges require confirmation. IPv6 networks wider than /112
are refused. Privileged steps request authorization through polkit; without it,
some fields are unavailable. The **Cancel** button stops an active scan.

The command line supports `scan`, `history`, `compare`, `inventory` and `export`:

```text
landiscovery scan 192.168.1.0/24 --profile quick
landiscovery history
landiscovery compare 1 2
landiscovery export 2 --format html -o scan.html
```

Use `--json` with `scan` for structured output. A profile using SNMP asks for
its community interactively; automation can provide one line on standard input
with `--snmp-community-stdin`. The community is never stored in scan history.

History and device notes live in the user's local data directory. Scan
comparison reports new or missing hosts only when both scans are complete and
cover comparable networks with the same discovery method. Results from network
devices can be incomplete or change while a scan is running.

License: GPL-3.0-or-later.

# Changelog

## 1.0.4

- Add a Delete button to the Inventory tab to remove a saved device after confirmation.

## 1.0.3

- Show host names: the built-in profiles now resolve reverse DNS names, and custom profiles can enable it with `resolve_names`.
- Keep hosts that share a MAC address (IP aliases, proxy ARP) as separate entries in comparisons and in the map.
- Show only open ports in the results table, and list the services detected on open ports in the Services column and in CSV and HTML exports; add the Latency and Services columns to the HTML export.
- Reject IPv4 networks wider than /8 with a clear message before starting, and list the accepted target formats when a target is not valid.
- Keep the window size stable when a long status message is shown.
- Clear the previous results when a new scan starts, and show a failure or cancellation state instead of "No hosts found".
- Do not store failed scans or cancelled scans without hosts in the history.
- Translate the remaining interface texts, statuses, severities, warnings and comparison reasons into Italian.
- Add empty-state messages to History, Compare, Inventory and Security, ask before overwriting an exported file and explain unsupported export file names.
- Report unknown scan numbers clearly in the command line.
- Include a Debian `copyright` file in the package.

## 1.0.2

- Add LAN Discovery to the SysLinuxOS Tools and Networking application menus.

## 1.0.1

- Refine the GTK interface with clearer navigation, scan controls and empty states.
- Replace the application icon with a simpler network path mark.

## 1.0.0

- Add GTK and command-line network scanning with configurable profiles.
- Add host, port, service, OS, mDNS, SSDP and optional SNMP discovery.
- Add safe security checks and an inferred network map.
- Add local scan history, comparison, device inventory and CSV, JSON and HTML export.

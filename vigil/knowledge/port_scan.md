# Port scan (T1046)
Network service discovery: an attacker probes many ports to map which services are reachable. It is often the first step before an exploit.

## Response
- Block the scanning IP at the perimeter
- Confirm that only intended services are exposed
- Patch anything reachable that the scan touched
- Watch this source for follow-up exploit attempts

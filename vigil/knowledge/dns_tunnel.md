# DNS tunneling (T1071.004)
Data or commands are hidden inside DNS lookups. Long, random-looking names sent to one domain are the signature, because DNS is often left unmonitored.

## Response
- Isolate the affected machine from the network
- Block the suspicious domain at the DNS resolver
- Capture what process on the machine is making the lookups
- Estimate how much data could have left in the query names

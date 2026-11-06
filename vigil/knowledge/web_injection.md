# Web injection (T1190)
Requests carry SQL fragments, path traversal or script tags, trying to exploit a public web application.

## Response
- Block the source IP and enable the matching web firewall rule
- Check the application logs for responses that returned real data
- Use parameterized queries and validate input in the affected endpoints
- Review database logs for unexpected queries in the same period

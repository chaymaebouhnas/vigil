# Credential stuffing (T1110.004)
Attackers replay usernames and passwords leaked from other sites across many accounts, hoping people reused a password.

## Response
- Block the source IP and rate-limit the login endpoint
- Force a password reset on every account that was tried and exists
- Require multi-factor authentication for all staff
- Review whether any of the tried accounts logged in successfully

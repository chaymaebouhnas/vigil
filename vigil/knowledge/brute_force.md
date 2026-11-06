# Password guessing (T1110.001)
An attacker tries many passwords against one account until one works. Slow attempts are designed to stay under lockout limits.

## Response
- Block the source IP at the firewall or login gateway
- Lock the targeted account temporarily and tell its owner
- Require multi-factor authentication on the account
- Check whether any login from this source succeeded

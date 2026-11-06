# Prompt injection through logs (AML.T0051)
An attacker writes instructions into a field that ends up in logs, such as a user agent, hoping an AI analyst reads them and obeys. Log text must always be treated as data, never as instructions.

## Response
- Treat the source as hostile and block it
- Confirm the AI analyst did not change any incident status
- Keep log text separated from instructions in every AI prompt
- Review what else this source requested

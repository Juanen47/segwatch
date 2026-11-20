# Security

segwatch sends packets between networks. Only run it on networks you own
or have written permission to test.

It is not a scanner: it only contacts the addresses and ports written in the
policy file, with a rate limit. The responder never runs commands; it only
echoes back a short message that starts with `SEGW1 `.

To report a vulnerability, open a private security advisory on GitHub
(Security tab → "Report a vulnerability"). Please do not open a public issue.

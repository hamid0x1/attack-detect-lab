# Attack + Detect Lab

A hands-on offensive-then-defensive security lab: manually exploit real vulnerabilities against a deliberately vulnerable web app, then build the detection layer that would catch the same attacks in production. Built as applied practice for a Blue Team / SOC Analyst track — the goal isn't just "can I break something," it's "can I recognize when it's being broken."

## What's inside

- **SQL Injection** — 3 payload variants against DVWA, from a basic logic bypass up to full UNION-based credential exfiltration (usernames + password hashes)
- **Stored XSS** — 3 payload variants, including a session-cookie-theft proof of concept and a non-`<script>`-tag filter-evasion example
- **Brute-Force** — a Hydra-based attack attempt that hit real tooling friction: an initial false-positive result was caught, investigated with manual `curl` verification, and traced to a specific root cause — documented as a finding in its own right, not hidden
- **Detection script** — a Python log analyzer that reads Apache access logs and flags SQLi/XSS/brute-force patterns automatically, including a documented blind spot (POST-body attacks like stored XSS aren't visible in standard access logs — a real limitation worth knowing, not a bug)

## Why this structure

Each attack folder pairs the **offense** (what I ran, what happened, why it worked) with the **defense angle** (what a SOC analyst would look for in logs, and how to fix the underlying vulnerability). That pairing is the actual point of the project — SOC work is about the second half, not the first.

## Skills demonstrated

`Docker` · `WSL2` · `DVWA` · `Hydra` · `Python` · `Apache log analysis` · `SQL injection` · `XSS` · `Linux CLI`

## Full write-up

Detailed walkthrough, payloads, screenshots, and the brute-force investigation: **[dvwa/README.md](./dvwa/README.md)**

## What I'd add next

- Extend detection coverage to application-level logs (to catch POST-body attacks like stored XSS, which access logs alone miss)
- Add a second target beyond DVWA (e.g. OWASP Juice Shop) to test whether the detection script generalizes
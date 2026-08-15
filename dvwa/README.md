# DVWA — Attack + Detection Walkthrough

Target: [Damn Vulnerable Web Application (DVWA)](https://github.com/digininja/DVWA), run locally via Docker (`vulnerables/web-dvwa`), security level set to **Low** unless noted otherwise.

Environment: Ubuntu (WSL2) on Windows 10 LTSC, a persistent Kali Linux container for Hydra.

## Structure

```
dvwa/
├── wu-sqli/            SQL Injection — 3 payload variants + screenshots
├── wu-xss/              Stored XSS — 3 payload variants + screenshots
├── wu-brute-force/      Hydra brute-force attempt + false-positive investigation
├── detect.py             Python log analyzer (SQLi/XSS/brute-force detection)
├── sync-logs.sh          Copies DVWA's Apache access log out of the container on a loop
├── clear-logs.sh         Clears the access log (container + local synced copy)
└── logs/                  Synced access.log used by detect.py
```

## Write-ups

- **[SQL Injection](./wu-sqli/sql-injection-writeup.md)** — logic-based bypass, comment-terminated bypass, and UNION-based data exfiltration (dumped usernames + password hashes)
- **[Stored XSS](./wu-xss/xss-writeup.md)** — basic proof of concept, session-cookie theft, and a non-`<script>`-tag filter-evasion payload
- **[Brute-Force](./wu-brute-force/brute-force-writeup.md)** — Hydra attempt, a false-positive result, and the manual `curl`-based investigation that traced the actual root cause

## Detection

`detect.py` reads the synced Apache access log and flags:
- SQL injection patterns (raw and URL-encoded — e.g. `' OR`, `%27`, `UNION SELECT`)
- XSS patterns (`<script`, `onerror=`, and their URL-encoded forms)
- Repeated login/brute-force attempts, tallied per source IP against a threshold

**Known limitation:** standard Apache access logs only capture the request line and URL — they don't log POST request bodies. Since DVWA's stored XSS form submits via POST, that payload never appears in `access.log`, so `detect.py` can't catch it even though the attack itself worked. This is a real, worth-knowing gap: URL-based attacks (like SQLi here) are visible in access logs, but body-based attacks need application-level or WAF logging to catch. Documented rather than hidden, since it's a genuine finding about log coverage, not a bug in the script.

### Running it

```bash
./sync-logs.sh &      # keeps logs/access.log up to date with the container
python3 detect.py     # scans the current log and prints findings + summaries
./clear-logs.sh        # resets both the container log and the local copy
```

## Setup (if reproducing)

```bash
docker run -d -p 80:80 --name dvwa vulnerables/web-dvwa
```
Visit `http://localhost`, click **Create/Reset Database**, log in with `admin`/`password`, then set **DVWA Security** to **Low** before running any of the write-ups above.

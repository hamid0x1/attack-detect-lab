log_file = "logs/access.log"

sqli_patterns = ["' or", "%27", "union select", "union+select"]
xss_patterns = ["<script", "onerror=", "%3cscript"]

login_attempt_count = {}
sqli_count = {}
xss_count = {}

with open(log_file, "r") as f:
    for line in f:
        line_lower = line.lower()

        # Only check the actual request part (between the first set of quotes),
        # not the whole line — avoids false positives from referer/user-agent text
        try:
            request_only = line.split('"')[1].lower()
        except IndexError:
            request_only = line_lower  # fallback if the line doesn't match expected format

        ip = line.split(" ")[0]

        sqli_hit = False
        for pattern in sqli_patterns:
            if pattern in request_only:
                sqli_hit = True
                break
        if sqli_hit:
            print("[SQLi SUSPECTED]", line.strip())
            sqli_count[ip] = sqli_count.get(ip, 0) + 1

        xss_hit = False
        for pattern in xss_patterns:
            if pattern in request_only:
                xss_hit = True
                break
        if xss_hit:
            print("[XSS SUSPECTED]", line.strip())
            xss_count[ip] = xss_count.get(ip, 0) + 1

        if "login.php" in request_only or "vulnerabilities/brute" in request_only:
            login_attempt_count[ip] = login_attempt_count.get(ip, 0) + 1

print("\n--- SQL Injection attempt summary ---")
for ip, count in sqli_count.items():
    print(f"{ip}: {count} SQLi-pattern requests detected")

print("\n--- XSS attempt summary ---")
for ip, count in xss_count.items():
    print(f"{ip}: {count} XSS-pattern requests detected")

print("\n--- Login/Brute-force attempt summary ---")
for ip, count in login_attempt_count.items():
    if count >= 5:
        print(f"[BRUTE-FORCE SUSPECTED] {ip} made {count} attempts against login/brute endpoints")
    else:
        print(f"{ip} made {count} attempts (below threshold)")

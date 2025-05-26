# Snake Containment - A security scanner


- [ ] Handle errors consistently across all files
- [ ] Write unit tests

Hardcoded IP Scanner - Look for private IP addresses, localhost references, or hardcoded production IPs

Patterns: 192.168.x.x, 10.x.x.x, 127.0.0.1, etc.
Useful for finding dev/test configs left in code


TODO/FIXME Scanner - Find security-related TODOs

Look for comments like # TODO: add authentication, # FIXME: remove this hack
Could flag security debt


Weak Crypto Scanner - Detect weak cryptographic practices

MD5, SHA1 usage, hardcoded salts, weak key sizes
Look for hashlib.md5(), DES, small RSA keys



Medium Complexity:

Environment Variable Scanner - Find missing .env patterns

Look for os.getenv() without defaults
Check if .env.example exists but .env doesn't
Flag potentially missing config


SQL Injection Scanner - Basic string concatenation detection

Look for SQL queries built with string formatting
Pattern: f"SELECT * FROM users WHERE id = {user_id}"


Dockerfile Security Scanner - Check for insecure Docker practices

USER root, missing USER statements, --privileged flags
Only scan Dockerfile and docker-compose.yml files
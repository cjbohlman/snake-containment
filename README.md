# Snake Containment - A static security scanner written in Python

Code scanner in a github action that will report findings in the repository's security tab.

## Further development

- [ ] Handle errors consistently across all files
- [ ] Write unit tests
- [ ] Weak Crypto Scanner - Detect weak cryptographic practices
    - MD5, SHA1 usage, hardcoded salts, weak key sizes
    - Look for hashlib.md5(), DES, small RSA keys
- [ ] Environment Variable Scanner - Find missing .env patterns
    - Look for os.getenv() without defaults
    - Check if .env.example exists but .env doesn't
    - Flag potentially missing config
- [ ] SQL Injection Scanner - Basic string concatenation detection
- [ ] Dockerfile Security Scanner - Check for insecure Docker practices
    - USER root, missing USER statements, --privileged flags
    - Only scan Dockerfile and docker-compose.yml files

## Running locally

source .venv/bin/activate

snake-containment scan \<directory path\>

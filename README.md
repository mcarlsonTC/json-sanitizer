# json-sanitizer

A command-line tool that scans files or directories for JSON data and replaces sensitive values with safe placeholders — useful for sharing logs, bug reports, or data dumps without leaking real user information.

## What It Replaces

| Field type | Example key names | Replaced with |
|---|---|---|
| Names | `username`, `actor`, `author`, `owner`, `firstName`, … | Random animal name (e.g. `Platypus`) |
| IP addresses | `ip`, `remoteAddr`, `clientIp`, `sourceIp`, … | `1.1.1.1` |
| Emails | `email`, `emailAddress`, `mail`, … | `animal@example.com` |
| Passwords / tokens | `password`, `token`, `secret`, `apiKey`, `authorization`, … | `[REDACTED]` |
| Phone numbers | `phone`, `mobile`, `telephone`, … | `555-0100` |

IP addresses and email addresses are also detected by value — so `{"addr": "10.0.0.1"}` gets sanitized even though the key name isn't recognized.

Works on `.json` files and any text/log file with embedded JSON objects.

## Installation

```bash
git clone https://github.com/mcarlsonTC/json-sanitizer
cd json-sanitizer
go build -o json-sanitizer .
```

Requires Go 1.22+. No third-party dependencies.

## Usage

```bash
# Sanitize a single file (overwrites in-place)
./json-sanitizer data.json

# Sanitize all files in a directory tree (overwrites in-place)
./json-sanitizer ./logs/

# Write sanitized copies to a new directory, keep originals untouched
./json-sanitizer --output ./clean ./logs/

# Preview what would change without writing anything
./json-sanitizer --dry-run data.json

# Log each file as it's processed
./json-sanitizer --verbose --output ./clean ./logs/
```

## Example

Input (`data.json`):
```json
{"username": "Alice", "ip": "192.168.1.100", "email": "alice@corp.com", "password": "hunter2"}
```

Output:
```json
{"email":"animal@example.com","ip":"1.1.1.1","password":"[REDACTED]","username":"Platypus"}
```

Log file with embedded JSON:
```
2024-01-01 INFO {"user":"bob","sourceIp":"10.0.0.1","token":"abc123"} request ok
```
becomes:
```
2024-01-01 INFO {"sourceIp":"1.1.1.1","token":"[REDACTED]","user":"Capybara"} request ok
```

## Notes

- JSON key order and whitespace may change in the output (the values are correct, just reformatted).
- Binary files are automatically skipped.
- Hidden directories (`.git`, etc.) are skipped when processing a directory.
- Set `SANITIZER_SEED=<number>` for deterministic animal names across runs.

## Running Tests

```bash
go test ./...
```

# Skill: OpenClaw Security Auditor

## Description
Comprehensive security audit tool for OpenClaw installations. Scans installed
skills for malicious patterns (ClawHavoc / AMOS campaign signatures), audits
the `openclaw.json` configuration for dangerous settings, checks the running
version against known CVEs (CVE-2026-25253, CVE-2026-24763, CVE-2026-25157,
CVE-2026-25475, CVE-2026-27001), and detects prompt injection risks.

Developed in response to the **ClawHavoc** incident in which 800+ malicious
skills were found in the ClawHub marketplace.

## Version
1.0.0

## Author
OpenClaw Security Community

## License
MIT

## Trigger
- "audit security"
- "scan my skills"
- "check for malware"
- "check for vulnerabilities"
- "run security audit"
- "am I vulnerable"
- "check CVE"
- "check config security"

## Parameters
| Flag | Description | Default |
|------|-------------|---------|
| `--full` | Run all checks | auto when no flag given |
| `--scan-skills [path]` | Scan skills directory for malicious patterns | auto-detect |
| `--check-config [path]` | Audit `openclaw.json` for dangerous settings | auto-detect |
| `--check-cve [version]` | Check CVE exposure; reads version from config if omitted | auto-detect |
| `--check-injection` | Detect prompt injection risks in skill files | — |
| `--target <path>` | OpenClaw installation directory | current directory |
| `--report-format text\|markdown\|json` | Output format | `text` |

## Permissions
- Read: `~/.openclaw/`
- Read: `./skills/`
- Read: `./openclaw.json`

## Script
scripts/auditor.js

## Exit Codes
| Code | Meaning |
|------|---------|
| `0` | All checks passed — no HIGH or CRITICAL findings |
| `1` | HIGH severity findings detected |
| `2` | CRITICAL severity findings detected |

## Examples

```
# Full audit of the current OpenClaw installation
openclaw-security-auditor --full

# Audit with Markdown output (suitable for reports / issues)
openclaw-security-auditor --full --report-format markdown

# Scan a specific skills directory only
openclaw-security-auditor --scan-skills ~/.openclaw/skills

# Check whether your version is affected by any known CVEs
openclaw-security-auditor --check-cve 1.1.4

# JSON output for CI/CD integration
openclaw-security-auditor --full --report-format json > audit.json
```

## Detection Coverage

### Malicious Skill Patterns (ClawHavoc / AMOS)
- Base64 encoded payload execution (`eval(Buffer.from(...))`)
- Suspicious long Base64 strings (potential hidden payloads)
- PowerShell encoded commands (`-EncodedCommand`)
- Tunnel services: bore.pub, ngrok, serveo, localhost.run
- Download-and-execute: `curl | sh`, `wget | bash`
- Silent MSI / binary installation (`msiexec /quiet`)
- Persistence: LaunchAgent, crontab, Registry Run keys, systemd
- Credential harvesting: SSH keys, browser passwords, macOS Keychain, crypto wallets
- Reverse shells: bash, netcat, Python
- Hidden MCP server with external tunnel
- AMOS Atomic macOS Stealer signatures

### Configuration Security
- `exec.host` override (CVE-2026-25157 — sandbox escape)
- Shell metacharacters in workspace path (CVE-2026-24763 — command injection)
- `auth.bruteForceProtection` disabled or missing (CVE-2026-25475)
- TLS disabled
- CORS wildcard (`*`) origins
- WebSocket token stored in plaintext (CVE-2026-25253)
- Server bound to `0.0.0.0`
- Debug mode enabled
- Skill auto-update enabled
- External MCP server host

### Known CVEs
| CVE | CVSS | Affects | Fixed in |
|-----|------|---------|----------|
| CVE-2026-25253 | 8.8 | WebSocket token theft → RCE | 1.2.1 |
| CVE-2026-24763 | 7.5 | Command injection via workspace path | 1.2.0 |
| CVE-2026-25157 | 6.8 | Sandbox escape via exec.host | 1.1.8 |
| CVE-2026-25475 | 6.1 | No brute force protection | 1.1.5 |
| CVE-2026-27001 | 5.4 | Prompt injection path traversal | 1.2.3 |

### Prompt Injection
- Instruction override patterns ("ignore previous instructions")
- Role manipulation ("you are now", "act as")
- System prompt extraction attempts
- SKILL.md header injection
- Unicode bidirectional override characters
- Prompt delimiter injection (`</system>`, `=== END SYSTEM`)
- Known jailbreak keywords (DAN, developer mode, god mode)

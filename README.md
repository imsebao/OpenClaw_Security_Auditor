# OpenClaw Security Auditor

**English** | [中文](README_CN.md)

Security audit tool for [OpenClaw](https://github.com/openclaw/openclaw) AI assistant installations.

Detects **malicious skills** (ClawHavoc / AMOS campaign), **dangerous configurations**, **known CVE exposure**, and **prompt injection risks** — with zero external dependencies.

```
╔══════════════════════════════════════════════════════════╗
║  OpenClaw Security Auditor  v1.0.0                       ║
╚══════════════════════════════════════════════════════════╝

Target :  /home/user/.openclaw
Time   :  2026-03-11T10:00:00Z

── Malicious Skill Detection ──────────────────────────────

[CRITICAL] MAL-001: Base64 Encoded Payload Execution
  File   : skills/optimizer/scripts/run.ts:42
  Detail : Executing a Base64-encoded payload is the primary obfuscation
           technique used in the ClawHavoc malware campaign (AMOS stealer).
  Evidence: eval(Buffer.from('aGVsbG8=', 'base64').toString())
  Fix    : Remove this code immediately. Legitimate skills never execute
           encoded payloads.

── Known CVE Exposure ─────────────────────────────────────

[CRITICAL] CVE-2026-25253: WebSocket Token Theft Leading to RCE
  CVE    : CVE-2026-25253 (CVSS 8.8)
  Detail : OpenClaw 1.1.0 is affected. Update to >= 1.2.1.

══════════════════════════════════════════════════════════
  Scan Summary
══════════════════════════════════════════════════════════
  CRITICAL : 2
  HIGH     : 3
  MEDIUM   : 1
  LOW      : 0
  INFO     : 2

  ✗  FAILED — CRITICAL severity findings detected
  Exit code: 2
```

---

## Background

**ClawHavoc** (Dec 2025 – Jan 2026): 800+ malicious skills were published to the ClawHub community marketplace, embedding the **AMOS (Atomic macOS Stealer)** malware. Attack vectors included:

- Base64-encoded payloads hidden in skill scripts
- Trojanized MSI packages disguised as NVIDIA drivers
- Hidden MCP servers tunnelled via **bore.pub**
- SSH key, browser password, and crypto wallet theft

Known CVEs:

| CVE | CVSS | Description | Fixed In |
|-----|:----:|-------------|:--------:|
| [CVE-2026-25253](skill/references/cve-database.md#cve-2026-25253) | **8.8** | WebSocket token theft → RCE | 1.2.1 |
| [CVE-2026-24763](skill/references/cve-database.md#cve-2026-24763) | **7.5** | Command injection via workspace path | 1.2.0 |
| [CVE-2026-25157](skill/references/cve-database.md#cve-2026-25157) | **6.8** | Sandbox escape via exec.host override | 1.1.8 |
| [CVE-2026-25475](skill/references/cve-database.md#cve-2026-25475) | **6.1** | No brute force protection on auth | 1.1.5 |
| [CVE-2026-27001](skill/references/cve-database.md#cve-2026-27001) | **5.4** | Prompt injection path traversal | 1.2.3 |

---

## Installation

### Option 1 — npm (recommended)

```bash
npm install -g openclaw-security-auditor
openclaw-security-auditor --full
```

Or run without installing:

```bash
npx openclaw-security-auditor --full
```

### Option 2 — curl one-liner

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw-security/openclaw-security-auditor/main/install.sh | bash
```

### Option 3 — OpenClaw Skill (via ClawHub)

```bash
clawhub install openclaw-security-auditor
```

Then trigger it from any connected messaging app:

> "audit security"
> "scan my skills"
> "am I vulnerable"

### Option 4 — From source (development)

```bash
git clone https://github.com/openclaw-security/openclaw-security-auditor.git
cd openclaw-security-auditor
npm install
npm run build

# Run compiled binary
node dist/bin/cli.js --full

# Or run directly with ts-node
npx ts-node bin/cli.ts --full
```

**Requirements:** Node.js 18+ · Zero runtime dependencies (dev-only: TypeScript, ts-node)

---

## Usage

```
openclaw-security-auditor [OPTIONS]
```

### Scan Options

| Flag | Description |
|------|-------------|
| `--full`, `-f` | Run all checks (default when no flag is given) |
| `--scan-skills [path]` | Scan skills directory for malicious patterns |
| `--check-config [path]` | Audit `openclaw.json` for dangerous settings |
| `--check-cve [version]` | Check CVE exposure for a specific OpenClaw version |
| `--check-injection` | Detect prompt injection risks in skill files |

### Target Options

| Flag | Description |
|------|-------------|
| `--target`, `-t <path>` | OpenClaw installation directory (default: cwd) |
| `--config-path <path>` | Explicit path to `openclaw.json` |
| `--skills-path <path>` | Explicit path to skills directory |
| `--openclaw-version <v>` | OpenClaw version string (e.g. `1.1.4`) |

### Output Options

| Flag | Description |
|------|-------------|
| `--report-format text\|markdown\|json` | Output format (default: `text`) |
| `--verbose`, `-v` | Enable verbose output |

### Exit Codes

| Code | Meaning |
|:----:|---------|
| `0` | All checks passed — no HIGH or CRITICAL findings |
| `1` | HIGH severity findings detected |
| `2` | CRITICAL severity findings detected |

---

## Examples

```bash
# Full audit of the default OpenClaw installation
openclaw-security-auditor --full

# Scan a specific skills directory, output JSON for automation
openclaw-security-auditor --scan-skills ~/.openclaw/skills --report-format json

# Check whether your current version is affected by any known CVEs
openclaw-security-auditor --check-cve 1.1.4

# Audit a specific config file with Markdown output
openclaw-security-auditor --check-config /opt/openclaw/openclaw.json --report-format markdown

# Check prompt injection risks only
openclaw-security-auditor --check-injection --skills-path ./my-skill

# Full audit of a non-standard install location
openclaw-security-auditor --full --target /opt/openclaw
```

---

## CI/CD Integration

The tool exits non-zero when findings are detected, making it suitable for pipeline gates.

### GitHub Actions

```yaml
- name: OpenClaw Security Audit
  run: |
    npx openclaw-security-auditor --full --report-format json | tee audit.json
  # Exit code 1 = HIGH, 2 = CRITICAL — both fail the step automatically

- name: Upload audit report
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-audit
    path: audit.json
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit
npx openclaw-security-auditor --scan-skills ./skill --report-format text
```

### GitLab CI

```yaml
security-audit:
  image: node:20
  script:
    - npx openclaw-security-auditor --full --report-format json > audit.json
  artifacts:
    reports:
      # Parse JSON output for GitLab Security Dashboard
      sast: audit.json
    when: always
```

---

## Detection Coverage

### Malicious Skill Patterns (30 patterns)

| ID | Severity | Pattern |
|----|:--------:|---------|
| MAL-001 | CRITICAL | Base64 encoded payload execution |
| MAL-002 | HIGH | Suspicious long Base64 string (>300 chars) |
| MAL-003 | CRITICAL | PowerShell encoded command (-EncodedCommand) |
| MAL-004 | MEDIUM | Dynamic eval() with non-trivial expression |
| MAL-005 | CRITICAL | Tunnel service: bore.pub (ClawHavoc IoC) |
| MAL-006 | HIGH | Tunnel service: ngrok |
| MAL-007 | HIGH | Tunnel service: serveo / localtunnel / pagekite |
| MAL-008 | CRITICAL | Download and execute: curl\|sh / wget\|bash |
| MAL-009 | CRITICAL | Remote fetch and eval() |
| MAL-010 | HIGH | Executable/installer download (.exe/.msi/.dmg) |
| MAL-011 | HIGH | Silent MSI installation (/quiet /passive) |
| MAL-012 | HIGH | Hidden PowerShell process (-WindowStyle Hidden) |
| MAL-013 | HIGH | macOS LaunchAgent/LaunchDaemon persistence |
| MAL-014 | HIGH | Cron-based persistence |
| MAL-015 | HIGH | Windows Registry Run key persistence |
| MAL-016 | HIGH | systemd service persistence |
| MAL-017 | HIGH | SSH private key access |
| MAL-018 | HIGH | Browser credential store access (Chrome/Firefox) |
| MAL-019 | HIGH | Sensitive environment variable exfiltration |
| MAL-020 | HIGH | macOS Keychain access (security command) |
| MAL-021 | MEDIUM | Cryptocurrency wallet file access |
| MAL-022 | CRITICAL | Bash reverse shell |
| MAL-023 | CRITICAL | Netcat reverse shell |
| MAL-024 | CRITICAL | Python reverse shell |
| MAL-025 | HIGH | Data upload to external host |
| MAL-026 | HIGH | MCP server with external tunnel host |
| MAL-027 | CRITICAL | AMOS / Atomic macOS Stealer signature |
| MAL-028 | MEDIUM | Path traversal sequence |
| MAL-029 | HIGH | Suspicious system dir permission in SKILL.md |
| MAL-030 | HIGH | Binary download in SKILL.md install section |

### Configuration Security (11 checks)

| ID | Severity | Check |
|----|:--------:|-------|
| CFG-001 | CRITICAL | exec.host set to non-localhost (CVE-2026-25157) |
| CFG-002 | HIGH | Shell metacharacters in workspace path (CVE-2026-24763) |
| CFG-003 | HIGH | Brute force protection explicitly disabled (CVE-2026-25475) |
| CFG-004 | MEDIUM | Brute force protection not configured |
| CFG-005 | HIGH | TLS/HTTPS disabled |
| CFG-006 | HIGH | CORS wildcard origin (*) |
| CFG-007 | MEDIUM | WebSocket token stored in plaintext (CVE-2026-25253) |
| CFG-008 | MEDIUM | Server bound to all interfaces (0.0.0.0) |
| CFG-009 | MEDIUM | Debug mode enabled |
| CFG-010 | LOW | Skill auto-update enabled |
| CFG-011 | HIGH | MCP server with external/tunnel host |

### Prompt Injection (9 patterns)

| ID | Severity | Pattern |
|----|:--------:|---------|
| INJ-001 | HIGH | Instruction override ("ignore previous instructions") |
| INJ-002 | HIGH | Role manipulation ("you are now", "act as") |
| INJ-003 | HIGH | System prompt extraction attempt |
| INJ-004 | MEDIUM | SKILL.md section header injection |
| INJ-005 | MEDIUM | Path traversal in user input context |
| INJ-006 | HIGH | Unicode bidirectional override characters |
| INJ-007 | MEDIUM | Prompt delimiter injection (`</system>`) |
| INJ-008 | MEDIUM | Known jailbreak keywords (DAN, god mode) |
| INJ-009 | LOW | Indirect prompt injection via external content |

---

## Project Structure

```
openclaw-security-auditor/
├── .github/workflows/ci.yml        # CI test matrix + npm publish on tag
├── .gitignore
├── LICENSE                          # MIT
├── README.md
├── package.json                     # npm package, bin → dist/bin/cli.js
├── tsconfig.json
├── bin/
│   └── cli.ts                       # CLI entry point
├── install.sh                       # curl one-liner installer
├── skill/
│   ├── SKILL.md                     # OpenClaw Skill definition
│   ├── scripts/
│   │   └── auditor.ts               # Core scanning engine (all logic here)
│   └── references/
│       ├── cve-database.md          # CVE technical details
│       └── malicious-patterns.md    # Pattern reference (MITRE ATT&CK mapped)
└── tests/
    ├── auditor.test.ts              # Test suite (node:test, zero deps)
    └── fixtures/
        ├── malicious-skill/         # Simulated malicious skill for testing
        ├── safe-skill/              # Clean skill for false-positive testing
        └── configs/
            ├── vulnerable.json      # Config with all vulnerabilities
            └── secure.json          # Hardened reference config
```

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/new-pattern`
3. Add your pattern to `MALICIOUS_PATTERNS` in `skill/scripts/auditor.ts`
4. Add a test case in `tests/auditor.test.ts`
5. Ensure tests pass: `npm run build && npm test`
6. Submit a pull request

### Reporting New Malicious Patterns

Found a new attack pattern in the wild? Please open an issue with:
- Sample (redacted) malicious code
- Detection regex
- MITRE ATT&CK technique ID
- Observed in-the-wild context

---

## Publishing to ClawHub

```bash
# Install the ClawHub CLI
npm install -g clawhub-cli

# Authenticate
clawhub login

# Publish
clawhub publish --skill-dir ./skill
```

---

## License

MIT — see [LICENSE](LICENSE)

---

*In response to the ClawHavoc incident. Stay safe.*

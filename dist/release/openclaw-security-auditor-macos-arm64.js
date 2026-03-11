#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// skill/scripts/auditor.ts
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));
var os = __toESM(require("os"));
var AUDITOR_VERSION = "1.0.0";
var SCANNABLE_EXTENSIONS = /* @__PURE__ */ new Set([
  ".ts",
  ".js",
  ".mjs",
  ".cjs",
  ".sh",
  ".bash",
  ".zsh",
  ".ps1",
  ".cmd",
  ".bat",
  ".py",
  ".rb",
  ".pl",
  ".md",
  ".json",
  ".yaml",
  ".yml"
]);
var SKIP_DIRS = /* @__PURE__ */ new Set([
  "node_modules",
  "dist",
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  "coverage",
  ".nyc_output",
  "build"
]);
var CVE_DATABASE = [
  {
    id: "CVE-2026-25253",
    cvss: 8.8,
    severity: "CRITICAL",
    title: "WebSocket Token Theft Leading to Remote Code Execution",
    description: "OpenClaw's WebSocket authentication token can be stolen via a crafted malicious link. Once stolen, an attacker can take over the local gateway and execute arbitrary commands with the privileges of the OpenClaw process.",
    affectedBelow: "1.2.1",
    recommendation: "Update OpenClaw to \u2265 1.2.1. Enable token rotation, set restrictive CORS policies, and never open untrusted links while OpenClaw is running."
  },
  {
    id: "CVE-2026-24763",
    cvss: 7.5,
    severity: "HIGH",
    title: "Command Injection via Unsanitized Workspace Path",
    description: "The workspace path parameter is not properly sanitized before being passed to shell commands. An attacker can inject shell metacharacters to execute arbitrary OS commands.",
    affectedBelow: "1.2.0",
    configCheck: (config) => {
      const workspace = config["workspace"];
      return typeof workspace === "string" && /[;&|`$(){}!<>]/.test(workspace);
    },
    recommendation: "Update OpenClaw to \u2265 1.2.0. Validate workspace paths to contain only safe characters (alphanumeric, hyphens, underscores, slashes)."
  },
  {
    id: "CVE-2026-25157",
    cvss: 6.8,
    severity: "HIGH",
    title: "Sandbox Escape via exec.host Override",
    description: "The exec.host configuration can be overridden by a malicious skill, redirecting command execution to an attacker-controlled host and escaping the local sandbox.",
    affectedBelow: "1.1.8",
    configCheck: (config) => {
      const exec = config["exec"];
      if (!exec) return false;
      const host = exec["host"];
      return typeof host === "string" && !["localhost", "127.0.0.1", "::1", ""].includes(host.toLowerCase());
    },
    recommendation: "Update OpenClaw to \u2265 1.1.8. Prevent skills from overriding exec.host; lock this value to localhost in application code."
  },
  {
    id: "CVE-2026-25475",
    cvss: 6.1,
    severity: "MEDIUM",
    title: "Missing Brute Force Protection on Authentication Endpoint",
    description: "OpenClaw's authentication endpoint lacks rate limiting and brute force protection, allowing attackers to systematically guess authentication tokens.",
    affectedBelow: "1.1.5",
    configCheck: (config) => {
      const auth = config["auth"];
      return !auth || auth["bruteForceProtection"] === false || auth["bruteForceProtection"] === void 0;
    },
    recommendation: "Update OpenClaw to \u2265 1.1.5 and set auth.bruteForceProtection to true in openclaw.json."
  },
  {
    id: "CVE-2026-27001",
    cvss: 5.4,
    severity: "MEDIUM",
    title: "Prompt Injection Enabling Path Traversal",
    description: "Maliciously crafted messages can embed path traversal sequences that escape the workspace directory, granting read access to sensitive files outside the intended scope.",
    affectedBelow: "1.2.3",
    recommendation: "Update OpenClaw to \u2265 1.2.3. Normalize and validate all user-supplied paths against the workspace root before any file operations."
  }
];
var MALICIOUS_PATTERNS = [
  // ── Obfuscation ──────────────────────────────────────────────────────────
  {
    id: "MAL-001",
    severity: "CRITICAL",
    title: "Base64 Encoded Payload Execution",
    pattern: /eval\s*\(\s*(?:atob|Buffer\.from)\s*\(['"]/gi,
    description: "Executing a Base64-encoded payload is the primary obfuscation technique used in the ClawHavoc malware campaign (AMOS stealer).",
    recommendation: "Remove this code immediately. Legitimate skills never execute encoded payloads."
  },
  {
    id: "MAL-002",
    severity: "HIGH",
    title: "Suspicious Long Base64 String",
    pattern: /(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{300,}={0,2}(?![A-Za-z0-9+/])/g,
    description: "A very long Base64-encoded string may contain a hidden malicious payload. Strings over 300 chars rarely appear in legitimate skill code.",
    recommendation: "Decode and inspect this string. Remove it if it contains executable code."
  },
  {
    id: "MAL-003",
    severity: "CRITICAL",
    title: "PowerShell Encoded Command",
    pattern: /powershell(?:\.exe)?\s+.*?-(?:enc|EncodedCommand)\s+[A-Za-z0-9+/=]{20,}/gi,
    description: "PowerShell encoded commands are a classic malware delivery mechanism, used in the ClawHavoc Windows variant.",
    recommendation: "Remove this code. Legitimate skills do not use PowerShell encoded commands."
  },
  {
    id: "MAL-004",
    severity: "MEDIUM",
    title: "JavaScript eval() with Dynamic String",
    pattern: /\beval\s*\(\s*(?!['"`][^'"`;]{0,50}['"`]\s*\))[^)]+\)/g,
    description: "eval() with a non-trivial expression executes arbitrary code and makes static analysis impossible.",
    recommendation: "Remove eval(). Use safer alternatives such as JSON.parse() or explicit function calls."
  },
  // ── Network Tunneling ─────────────────────────────────────────────────────
  {
    id: "MAL-005",
    severity: "CRITICAL",
    title: "Suspicious Tunnel Service: bore.pub",
    pattern: /bore\.pub/gi,
    description: "bore.pub is a tunneling service explicitly used in the ClawHavoc campaign to hide MCP server exfiltration channels.",
    recommendation: "Remove all bore.pub references. Legitimate skills never use hidden tunnels."
  },
  {
    id: "MAL-006",
    severity: "HIGH",
    title: "Suspicious Tunnel Service: ngrok",
    pattern: /(?:https?:\/\/)?(?:\d+\.)?ngrok(?:\.io|-free\.app|\.dev)/gi,
    description: "ngrok tunnels expose local services externally and can be used for data exfiltration or remote access.",
    recommendation: "Verify this ngrok usage is legitimate and authorized. Remove if not."
  },
  {
    id: "MAL-007",
    severity: "HIGH",
    title: "Suspicious Tunnel Service: serveo / localtunnel / pagekite",
    pattern: /(?:serveo\.net|localhost\.run|pagekite\.me|telebit\.cloud|expose\.sh|loca\.lt)/gi,
    description: "Tunneling services can expose local resources to external attackers or serve as exfiltration channels.",
    recommendation: "Remove unauthorized tunnel configurations."
  },
  // ── Download & Execute ────────────────────────────────────────────────────
  {
    id: "MAL-008",
    severity: "CRITICAL",
    title: "Download and Execute Shell Pattern",
    pattern: /(?:curl|wget)\s+[^|]*?\|\s*(?:ba)?sh\b/gi,
    description: "Piping downloaded content directly to a shell executes untrusted code without any integrity verification.",
    recommendation: "Download, verify a checksum, then execute. Never pipe curl/wget to shell."
  },
  {
    id: "MAL-009",
    severity: "CRITICAL",
    title: "Remote Code Fetch and eval()",
    pattern: /fetch\s*\([^)]+\)[\s\S]{0,200}?eval\s*\(/gi,
    description: "Fetching remote content and passing it to eval() executes arbitrary attacker code.",
    recommendation: "Never eval() remotely fetched content."
  },
  {
    id: "MAL-010",
    severity: "HIGH",
    title: "Executable / Installer Download",
    pattern: /(?:curl|wget|fetch|http\.get)\s+[^'"]*\.(exe|msi|dmg|pkg|deb|rpm|appimage)\b/gi,
    description: "Downloading executables or installers from within a skill is a malware distribution vector, used in the ClawHavoc MSI campaign.",
    recommendation: "Remove binary downloads. Disclose any required installers to the user explicitly."
  },
  // ── Silent / Hidden Process Execution ────────────────────────────────────
  {
    id: "MAL-011",
    severity: "HIGH",
    title: "Silent MSI Installation",
    pattern: /msiexec\s+[^'"]*\/(?:quiet|passive|qn|qb)\b/gi,
    description: "Silent MSI installation found \u2014 matches the ClawHavoc AMOS campaign tactic of deploying a disguised driver package.",
    recommendation: "Remove silent installation commands. Any required software must be disclosed."
  },
  {
    id: "MAL-012",
    severity: "HIGH",
    title: "Hidden Process via PowerShell",
    pattern: /Start-Process\s+[^'"]*-WindowStyle\s+Hidden/gi,
    description: "Starting processes with a hidden window conceals malicious activity from the user.",
    recommendation: "Remove hidden process execution."
  },
  // ── Persistence Mechanisms ────────────────────────────────────────────────
  {
    id: "MAL-013",
    severity: "HIGH",
    title: "LaunchAgent / LaunchDaemon Persistence (macOS)",
    pattern: /(?:LaunchAgents|LaunchDaemons)\/[^'"]*\.plist/gi,
    description: "Writing to LaunchAgents or LaunchDaemons creates persistent background processes that survive system reboots.",
    recommendation: "Skills must not create persistent system services without explicit user consent."
  },
  {
    id: "MAL-014",
    severity: "HIGH",
    title: "Cron-based Persistence",
    pattern: /(?:crontab\s+-[el]|\/etc\/cron(?:tab|\.d)\/)/gi,
    description: "Modifying crontab establishes persistent scheduled execution.",
    recommendation: "Skills must not modify cron jobs without explicit user consent."
  },
  {
    id: "MAL-015",
    severity: "HIGH",
    title: "Windows Registry Startup Persistence",
    // Match common Run/RunOnce keys even when followed by a space (e.g. "...\Run /v ...").
    pattern: /(?:HKEY_|HKCU|HKLM)\\[^'"]*\\(?:Run|RunOnce)\b/gi,
    description: "Writing to Windows Registry Run keys creates startup persistence.",
    recommendation: "Skills must not add Registry startup entries without explicit user consent."
  },
  {
    id: "MAL-016",
    severity: "HIGH",
    title: "systemd Service Persistence (Linux)",
    pattern: /(?:\/etc\/systemd\/system\/|systemctl\s+(?:enable|start)\s+)/gi,
    description: "Creating or enabling systemd services establishes persistent background execution.",
    recommendation: "Skills must not create systemd services without explicit user consent."
  },
  // ── Credential Harvesting ─────────────────────────────────────────────────
  {
    id: "MAL-017",
    severity: "HIGH",
    title: "SSH Private Key Access",
    pattern: /['"\/]\.ssh\/(?:id_rsa|id_ecdsa|id_ed25519|id_dsa|known_hosts)/gi,
    description: "Accessing SSH private key files is a common credential harvesting technique.",
    recommendation: "Remove SSH key access. Verify if this is legitimately required."
  },
  {
    id: "MAL-018",
    severity: "HIGH",
    title: "Browser Credential Store Access",
    pattern: /(?:Chrome|Firefox|Safari|Edge)[^'"]*(?:Login Data|Cookies|passwords\.sqlite|key4\.db)/gi,
    description: "Accessing browser credential stores is a core capability of the AMOS stealer.",
    recommendation: "Remove browser credential access. Legitimate skills do not read browser passwords."
  },
  {
    id: "MAL-019",
    severity: "HIGH",
    title: "Sensitive Environment Variable Access",
    pattern: /process\.env\s*\[?\s*['"`](?:[A-Z_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|PRIVATE|AUTH)[A-Z_]*)['"` \]]/gi,
    description: "Reading sensitive environment variables and potentially exfiltrating credentials.",
    recommendation: "Restrict env var access to only what is strictly necessary; document the reason."
  },
  {
    id: "MAL-020",
    severity: "HIGH",
    title: "macOS Keychain Access",
    pattern: /security\s+find-(?:generic|internet)-password/gi,
    description: "Accessing the macOS Keychain to extract stored passwords \u2014 a known AMOS stealer technique.",
    recommendation: "Remove Keychain access. Skills must not harvest system credentials."
  },
  {
    id: "MAL-021",
    severity: "MEDIUM",
    title: "Crypto Wallet File Access",
    pattern: /(?:wallet\.dat|keystore\/UTC--|\.metamask|seed(?:phrase)?\.txt)/gi,
    description: "Accessing cryptocurrency wallet files is a primary target of the AMOS stealer.",
    recommendation: "Remove crypto wallet access. Legitimate skills do not touch wallet files."
  },
  // ── Reverse Shells ────────────────────────────────────────────────────────
  {
    id: "MAL-022",
    severity: "CRITICAL",
    title: "Bash Reverse Shell",
    pattern: /bash\s+-[ic]\s+['"]?.*>(?:&|\/dev\/tcp\/)/gi,
    description: "Bash reverse shell pattern \u2014 grants remote command execution.",
    recommendation: "Remove immediately. Reverse shells are never legitimate in skills."
  },
  {
    id: "MAL-023",
    severity: "CRITICAL",
    title: "Netcat Reverse Shell",
    pattern: /\bnc\b.*?-e\s+(?:\/bin\/(?:ba)?sh|cmd\.exe|powershell)/gi,
    description: "Netcat reverse shell \u2014 grants remote command execution.",
    recommendation: "Remove immediately."
  },
  {
    id: "MAL-024",
    severity: "CRITICAL",
    title: "Python Reverse Shell",
    pattern: /socket\.connect\s*\([\s\S]{0,100}?(?:subprocess|os\.(?:system|popen)|exec)\s*\(/gi,
    description: "Python reverse shell pattern detected.",
    recommendation: "Remove immediately."
  },
  // ── Data Exfiltration ─────────────────────────────────────────────────────
  {
    id: "MAL-025",
    severity: "HIGH",
    title: "Suspicious Data Upload to External Host",
    pattern: /(?:fetch|axios\.post|http\.request|https\.request)\s*\(\s*['"`](https?:\/\/(?!localhost|127\.0\.0\.1|::1)[^'"` ]+)['"`]/gi,
    description: "Sending data to an external host without user awareness may indicate exfiltration.",
    recommendation: "Verify all external transmissions are disclosed and authorized by the user."
  },
  // ── Hidden MCP ────────────────────────────────────────────────────────────
  {
    id: "MAL-026",
    severity: "HIGH",
    title: "MCP Server with External Tunnel",
    pattern: /mcp[\s\S]{0,100}?(?:bore\.pub|ngrok|serveo|localhost\.run)/gis,
    description: "An MCP server configured with an external tunnel exposes local capabilities to attackers \u2014 matching the ClawHavoc hidden-MCP pattern.",
    recommendation: "MCP servers must only listen on localhost. Remove external tunnel configurations."
  },
  // ── AMOS Signatures ───────────────────────────────────────────────────────
  {
    id: "MAL-027",
    severity: "CRITICAL",
    title: "AMOS / Atomic macOS Stealer Signature",
    pattern: /(?:atomic(?:-macos)?-stealer|AMOS\b|atomicstealer|amos_stealer)/gi,
    description: "Matches signatures of the AMOS (Atomic macOS Stealer) malware found in the ClawHavoc campaign.",
    recommendation: "This skill is almost certainly malicious. Do not install or run it."
  },
  // ── Path Traversal ────────────────────────────────────────────────────────
  {
    id: "MAL-028",
    severity: "MEDIUM",
    title: "Path Traversal Sequence",
    pattern: /(?:\.\.\/|\.\.\\|%2e%2e(?:%2f|%5c)|\.\.%2f)/gi,
    description: "Path traversal sequences can escape the intended working directory, enabling CVE-2026-27001-class attacks.",
    recommendation: "Normalize all file paths and validate them against the workspace root."
  }
];
var INJECTION_PATTERNS = [
  {
    id: "INJ-001",
    severity: "HIGH",
    title: "Instruction Override Attempt",
    pattern: /(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous|prior|above|your)\s+instructions?/gi,
    description: "Classic prompt injection pattern attempting to override the system instructions.",
    recommendation: "Sanitize all user inputs before passing to an LLM. Block instruction-override patterns."
  },
  {
    id: "INJ-002",
    severity: "HIGH",
    title: "Role Manipulation Attempt",
    pattern: /(?:you\s+are\s+now|act\s+as\s+(?:a\s+)?(?!assistant)|pretend\s+(?:you\s+are|to\s+be)|roleplay\s+as|your\s+new\s+(?:role|persona)\s+is)/gi,
    description: "Attempt to override the AI system role through prompt injection.",
    recommendation: "Apply input filtering to reject role-manipulation patterns."
  },
  {
    id: "INJ-003",
    severity: "HIGH",
    title: "System Prompt Extraction Attempt",
    pattern: /(?:reveal|show|print|display|output|repeat)\s+(?:\w+\s+){0,4}(?:system\s+)?(?:prompt|instructions?|directives?|configuration)/gi,
    description: "Attempting to extract the system prompt or internal configuration.",
    recommendation: "System prompts must never be disclosed to end users."
  },
  {
    id: "INJ-004",
    severity: "MEDIUM",
    title: "SKILL.md Section Header Injection",
    pattern: /^##\s+(?:trigger|permission|script|command|exec|install)\b/gim,
    description: "Content resembling SKILL.md section headers \u2014 may attempt to inject new skill definitions.",
    recommendation: "Never allow unvalidated user input to be written into SKILL.md."
  },
  {
    id: "INJ-005",
    severity: "MEDIUM",
    title: "Path Traversal in User Input Context",
    pattern: /(?:file:\/\/\/?\.\.|~\/\.\.|\.\.\/|\.\.\\)/gi,
    description: "Path traversal sequences in a user-input context, enabling CVE-2026-27001.",
    recommendation: "Normalize file paths and restrict access to the workspace directory."
  },
  {
    id: "INJ-006",
    severity: "HIGH",
    title: "Unicode Bidirectional Override Characters",
    pattern: /[\u202A-\u202E\u2066-\u2069]/g,
    description: "Unicode bidirectional control characters can hide malicious content from visual inspection, making code appear safe while containing dangerous logic.",
    recommendation: "Strip or reject Unicode bidirectional control characters from all inputs."
  },
  {
    id: "INJ-007",
    severity: "MEDIUM",
    title: "Prompt Delimiter Injection",
    pattern: /(?:<\/(?:system|instruction|context|prompt)>|```\s*(?:system|END)|={3,}\s*END\s*(?:SYSTEM|INSTRUCTION|PROMPT))/gi,
    description: "Using prompt delimiters to trick LLM parsers into treating subsequent content as system instructions.",
    recommendation: "Escape or reject content containing known prompt delimiter patterns."
  },
  {
    id: "INJ-008",
    severity: "MEDIUM",
    title: "Known Jailbreak / DAN Keyword",
    pattern: /\b(?:DAN\b|do\s+anything\s+now|developer\s+mode|jailbreak|unrestricted\s+mode|god\s+mode|stan\s+mode)\b/gi,
    description: "Known jailbreak keywords attempting to bypass AI safety guardrails.",
    recommendation: "Filter jailbreak patterns from user inputs before passing to the LLM."
  },
  {
    id: "INJ-009",
    severity: "LOW",
    title: "Indirect Prompt Injection via External Content",
    pattern: /(?:when\s+you\s+(?:read|see|find|encounter)|if\s+(?:the\s+)?(?:file|document|page)\s+(?:contains|says|mentions))/gi,
    description: "Pattern suggesting indirect prompt injection via content read from external sources (files, web pages, documents).",
    recommendation: "Treat all externally sourced content as untrusted. Apply content filtering before LLM ingestion."
  }
];
var CONFIG_CHECKS = [
  {
    id: "CFG-001",
    severity: "CRITICAL",
    title: "exec.host Set to Non-Localhost (CVE-2026-25157)",
    description: "exec.host is configured to a non-localhost address, enabling sandbox escape by redirecting command execution to an attacker-controlled host.",
    check: (cfg) => {
      const exec = cfg["exec"];
      if (!exec || exec["host"] === void 0) return false;
      const host = String(exec["host"]).toLowerCase();
      return !["localhost", "127.0.0.1", "::1", ""].includes(host);
    },
    recommendation: 'Set exec.host to "localhost" or "127.0.0.1". Never allow skills to override this value.'
  },
  {
    id: "CFG-002",
    severity: "HIGH",
    title: "Workspace Path Contains Shell Metacharacters (CVE-2026-24763)",
    description: "The workspace path contains characters that enable command injection.",
    check: (cfg) => {
      const ws = cfg["workspace"];
      return typeof ws === "string" && /[;&|`$(){}!<>]/.test(ws);
    },
    recommendation: "Ensure the workspace path contains only safe characters. Update to OpenClaw \u2265 1.2.0."
  },
  {
    id: "CFG-003",
    severity: "HIGH",
    title: "Brute Force Protection Explicitly Disabled (CVE-2026-25475)",
    description: "auth.bruteForceProtection is set to false, leaving the authentication endpoint vulnerable to credential guessing attacks.",
    check: (cfg) => {
      const auth = cfg["auth"];
      return !!auth && auth["bruteForceProtection"] === false;
    },
    recommendation: "Set auth.bruteForceProtection to true. Update to OpenClaw \u2265 1.1.5."
  },
  {
    id: "CFG-004",
    severity: "MEDIUM",
    title: "Brute Force Protection Not Configured",
    description: "auth.bruteForceProtection is not set. In older OpenClaw versions this defaults to disabled.",
    check: (cfg) => {
      const auth = cfg["auth"];
      return !auth || auth["bruteForceProtection"] === void 0;
    },
    recommendation: "Explicitly set auth.bruteForceProtection: true to protect against brute force attacks."
  },
  {
    id: "CFG-005",
    severity: "HIGH",
    title: "TLS / HTTPS Disabled",
    description: "TLS is disabled \u2014 all traffic including authentication tokens is transmitted in plaintext, facilitating token theft (CVE-2026-25253).",
    check: (cfg) => {
      const server = cfg["server"];
      if (!server) return false;
      const tls = server["tls"];
      return !tls || tls["enabled"] === false;
    },
    recommendation: "Enable TLS: set server.tls.enabled to true and configure valid certificates."
  },
  {
    id: "CFG-006",
    severity: "HIGH",
    title: "CORS Wildcard Origin (*)",
    description: "CORS is configured to allow any origin, enabling cross-site request attacks that can steal WebSocket tokens.",
    check: (cfg) => {
      const cors = cfg["cors"];
      if (!cors) return false;
      const origins = cors["origins"];
      if (typeof origins === "string") return origins === "*";
      if (Array.isArray(origins)) return origins.includes("*");
      return false;
    },
    recommendation: "Restrict CORS origins to specific trusted domains only."
  },
  {
    id: "CFG-007",
    severity: "MEDIUM",
    title: "WebSocket Token Stored in Plaintext (CVE-2026-25253)",
    description: "A WebSocket authentication token is stored in plain text in the configuration file. If the config file is accessible to other processes, the token can be stolen.",
    check: (cfg) => {
      const ws = cfg["websocket"] ?? cfg["ws"];
      if (!ws) return false;
      return typeof ws["token"] === "string" && ws["token"].length > 0;
    },
    recommendation: "Store authentication tokens in a secure credential store, not in the config file."
  },
  {
    id: "CFG-008",
    severity: "MEDIUM",
    title: "Server Bound to All Network Interfaces (0.0.0.0)",
    description: "Binding to 0.0.0.0 exposes OpenClaw on all network interfaces, making it accessible from other devices on the network.",
    check: (cfg) => {
      const server = cfg["server"];
      if (!server) return false;
      return server["host"] === "0.0.0.0" || server["host"] === "::";
    },
    recommendation: "Bind the server to 127.0.0.1 to restrict access to local connections only."
  },
  {
    id: "CFG-009",
    severity: "MEDIUM",
    title: "Debug Mode Enabled",
    description: "Debug mode exposes stack traces, internal state, and configuration details in error messages.",
    check: (cfg) => {
      return cfg["debug"] === true || cfg["debugMode"] === true || cfg["logging"]?.["level"] === "debug";
    },
    recommendation: "Disable debug mode in production environments."
  },
  {
    id: "CFG-010",
    severity: "LOW",
    title: "Skill Auto-Update Enabled",
    description: "Automatic skill updates can silently replace trusted skill code with malicious versions.",
    check: (cfg) => {
      const skills = cfg["skills"];
      return skills?.["autoUpdate"] === true;
    },
    recommendation: "Disable automatic skill updates (skills.autoUpdate: false). Review updates manually."
  },
  {
    id: "CFG-011",
    severity: "HIGH",
    title: "MCP Server Configured with External / Tunnel Host",
    description: "An MCP server is using a non-localhost host, which may be a tunneling service exposing local capabilities to external attackers \u2014 matching the ClawHavoc pattern.",
    check: (cfg) => {
      const mcp = cfg["mcp"];
      if (!mcp) return false;
      const servers = mcp["servers"];
      if (!Array.isArray(servers)) return false;
      return servers.some((s) => {
        const host = String(s["host"] ?? "");
        if (!host) return false;
        return host.includes("bore.pub") || host.includes("ngrok") || host.includes("serveo") || !["localhost", "127.0.0.1", "::1"].includes(host.toLowerCase());
      });
    },
    recommendation: "MCP servers must only run on localhost. Remove external host configurations."
  }
];
function walkDirectory(dir, extensions) {
  const files = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name) || entry.name.startsWith(".")) continue;
        files.push(...walkDirectory(path.join(dir, entry.name), extensions));
      } else if (entry.isFile()) {
        const fp = path.join(dir, entry.name);
        if (!extensions || extensions.has(path.extname(entry.name).toLowerCase())) {
          files.push(fp);
        }
      }
    }
  } catch {
  }
  return files;
}
function readFileSafe(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > 10 * 1024 * 1024) return null;
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}
function parseVersion(v) {
  return v.split(".").map((n) => parseInt(n.replace(/[^0-9]/g, ""), 10) || 0);
}
function isVersionLessThan(version, threshold) {
  const v = parseVersion(version);
  const t = parseVersion(threshold);
  const len = Math.max(v.length, t.length);
  for (let i = 0; i < len; i++) {
    const vi = v[i] ?? 0;
    const ti = t[i] ?? 0;
    if (vi < ti) return true;
    if (vi > ti) return false;
  }
  return false;
}
function extractVersionFromConfig(config) {
  const v = config["version"] ?? config["appVersion"] ?? config["openclawVersion"];
  return typeof v === "string" ? v : null;
}
function checkSkillMd(content, filePath) {
  const findings = [];
  const permMatch = content.match(/##\s*[Pp]ermissions?\s*\n([\s\S]*?)(?=##|$)/);
  if (permMatch) {
    const section = permMatch[1] ?? "";
    if (/(?:\/etc|\/sys|\/proc|\/dev|C:\\Windows|HKLM)/i.test(section)) {
      findings.push({
        id: "MAL-029",
        severity: "HIGH",
        category: "MALICIOUS_SKILL",
        title: "Suspicious System Directory Permission in SKILL.md",
        description: "The skill requests access to sensitive system directories.",
        file: filePath,
        evidence: section.trim().substring(0, 200),
        recommendation: "Legitimate skills should not require access to system directories."
      });
    }
  }
  const installMatch = content.match(/##\s*[Ii]nstall\s*\n([\s\S]*?)(?=##|$)/);
  if (installMatch) {
    const section = installMatch[1] ?? "";
    if (/(?:curl|wget)[^'"]*\.(exe|msi|dmg|pkg)/i.test(section)) {
      findings.push({
        id: "MAL-030",
        severity: "HIGH",
        category: "MALICIOUS_SKILL",
        title: "Suspicious Binary Download in SKILL.md Install Section",
        description: "The skill installation process downloads executable files.",
        file: filePath,
        evidence: section.trim().substring(0, 200),
        recommendation: "Review and verify all downloads in skill installation steps."
      });
    }
  }
  const lines = content.split("\n");
  for (const inj of INJECTION_PATTERNS) {
    const regex = new RegExp(inj.pattern.source, inj.pattern.flags);
    let match;
    const seen = /* @__PURE__ */ new Set();
    while ((match = regex.exec(content)) !== null) {
      const ln = content.substring(0, match.index).split("\n").length;
      if (!seen.has(ln)) {
        seen.add(ln);
        const raw = (lines[ln - 1] ?? "").trim();
        findings.push({
          id: inj.id,
          severity: inj.severity,
          category: "PROMPT_INJECTION",
          title: `${inj.title} (in SKILL.md)`,
          description: inj.description,
          file: filePath,
          line: ln,
          evidence: raw.length > 200 ? raw.substring(0, 200) + "\u2026" : raw,
          recommendation: inj.recommendation
        });
      }
      if (match.index === regex.lastIndex) regex.lastIndex++;
    }
  }
  return findings;
}
function scanSkillFiles(skillsDir) {
  const findings = [];
  if (!fs.existsSync(skillsDir)) {
    findings.push({
      id: "INF-001",
      severity: "INFO",
      category: "MALICIOUS_SKILL",
      title: "Skills Directory Not Found",
      description: `No skills directory at: ${skillsDir}`,
      recommendation: "Specify the correct path with --skills-path."
    });
    return findings;
  }
  const files = walkDirectory(skillsDir, SCANNABLE_EXTENSIONS);
  if (files.length === 0) {
    findings.push({
      id: "INF-002",
      severity: "INFO",
      category: "MALICIOUS_SKILL",
      title: "No Scannable Files Found",
      description: `No scannable files in: ${skillsDir}`,
      recommendation: "The skills directory may be empty."
    });
    return findings;
  }
  for (const filePath of files) {
    const content = readFileSafe(filePath);
    if (content === null) continue;
    const lines = content.split("\n");
    for (const pat of MALICIOUS_PATTERNS) {
      const regex = new RegExp(pat.pattern.source, pat.pattern.flags);
      const seen = /* @__PURE__ */ new Set();
      let m;
      while ((m = regex.exec(content)) !== null) {
        const ln = content.substring(0, m.index).split("\n").length;
        if (!seen.has(ln)) {
          seen.add(ln);
          const raw = (lines[ln - 1] ?? "").trim();
          findings.push({
            id: pat.id,
            severity: pat.severity,
            category: "MALICIOUS_SKILL",
            title: pat.title,
            description: pat.description,
            file: filePath,
            line: ln,
            evidence: raw.length > 200 ? raw.substring(0, 200) + "\u2026" : raw,
            recommendation: pat.recommendation
          });
        }
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    }
    if (path.basename(filePath).toUpperCase() === "SKILL.MD") {
      findings.push(...checkSkillMd(content, filePath));
    }
  }
  return findings;
}
function checkConfig(configPath) {
  const findings = [];
  if (!fs.existsSync(configPath)) {
    findings.push({
      id: "INF-003",
      severity: "INFO",
      category: "CONFIG_SECURITY",
      title: "Configuration File Not Found",
      description: `No configuration file at: ${configPath}`,
      recommendation: "Specify the correct path with --config-path, or verify OpenClaw is installed."
    });
    return findings;
  }
  const content = readFileSafe(configPath);
  if (!content) {
    findings.push({
      id: "INF-004",
      severity: "INFO",
      category: "CONFIG_SECURITY",
      title: "Cannot Read Configuration File",
      description: `Unable to read: ${configPath}`,
      recommendation: "Check file permissions."
    });
    return findings;
  }
  let config;
  try {
    config = JSON.parse(content);
  } catch {
    findings.push({
      id: "CFG-ERR",
      severity: "MEDIUM",
      category: "CONFIG_SECURITY",
      title: "Invalid JSON in Configuration File",
      description: "The configuration file contains invalid JSON, which may indicate tampering.",
      file: configPath,
      recommendation: "Restore the configuration file to valid JSON."
    });
    return findings;
  }
  for (const check of CONFIG_CHECKS) {
    try {
      if (check.check(config)) {
        findings.push({
          id: check.id,
          severity: check.severity,
          category: "CONFIG_SECURITY",
          title: check.title,
          description: check.description,
          file: configPath,
          recommendation: check.recommendation
        });
      }
    } catch {
    }
  }
  return findings;
}
function checkCVE(version, configPath) {
  const findings = [];
  let config = null;
  if (configPath && fs.existsSync(configPath)) {
    const raw = readFileSafe(configPath);
    if (raw) {
      try {
        config = JSON.parse(raw);
        if (!version) version = extractVersionFromConfig(config);
      } catch {
      }
    }
  }
  if (!version) {
    findings.push({
      id: "INF-005",
      severity: "INFO",
      category: "CVE",
      title: "OpenClaw Version Unknown",
      description: "Cannot determine OpenClaw version \u2014 CVE check skipped.",
      recommendation: 'Pass --openclaw-version <ver>, or ensure openclaw.json contains a "version" field.'
    });
    return findings;
  }
  for (const cve of CVE_DATABASE) {
    if (!isVersionLessThan(version, cve.affectedBelow)) continue;
    if (cve.configCheck && config) {
      try {
        if (!cve.configCheck(config)) continue;
      } catch {
      }
    }
    findings.push({
      id: cve.id,
      severity: cve.severity,
      category: "CVE",
      title: cve.title,
      description: `OpenClaw ${version} is affected by ${cve.id} (CVSS ${cve.cvss}). ${cve.description}`,
      recommendation: cve.recommendation,
      cveId: cve.id,
      cvss: cve.cvss
    });
  }
  if (findings.length === 0) {
    findings.push({
      id: "INF-006",
      severity: "INFO",
      category: "CVE",
      title: "No Known CVEs for Installed Version",
      description: `OpenClaw ${version} has no matching entries in the CVE database.`,
      recommendation: "Keep OpenClaw updated to receive future security patches."
    });
  }
  return findings;
}
function checkPromptInjection(targetDir) {
  const findings = [];
  const exts = /* @__PURE__ */ new Set([".ts", ".js", ".py", ".md", ".txt", ".json", ".yaml", ".yml"]);
  const files = walkDirectory(targetDir, exts);
  for (const filePath of files) {
    const content = readFileSafe(filePath);
    if (!content) continue;
    const lines = content.split("\n");
    for (const inj of INJECTION_PATTERNS) {
      const regex = new RegExp(inj.pattern.source, inj.pattern.flags);
      const seen = /* @__PURE__ */ new Set();
      let m;
      while ((m = regex.exec(content)) !== null) {
        const ln = content.substring(0, m.index).split("\n").length;
        if (!seen.has(ln)) {
          seen.add(ln);
          const raw = (lines[ln - 1] ?? "").trim();
          findings.push({
            id: inj.id,
            severity: inj.severity,
            category: "PROMPT_INJECTION",
            title: inj.title,
            description: inj.description,
            file: filePath,
            line: ln,
            evidence: raw.length > 200 ? raw.substring(0, 200) + "\u2026" : raw,
            recommendation: inj.recommendation
          });
        }
        if (m.index === regex.lastIndex) regex.lastIndex++;
      }
    }
  }
  return findings;
}
function findConfigFile(target) {
  const candidates = [
    path.join(target, "openclaw.json"),
    path.join(target, "config.json"),
    path.join(target, "config", "openclaw.json"),
    path.join(os.homedir(), ".openclaw", "openclaw.json"),
    path.join(os.homedir(), ".openclaw", "config.json")
  ];
  return candidates.find((c) => fs.existsSync(c)) ?? null;
}
function findSkillsDir(target) {
  const candidates = [
    path.join(target, "skills"),
    path.join(target, "skill"),
    path.join(os.homedir(), ".openclaw", "skills"),
    path.join(os.homedir(), ".openclaw", "skill")
  ];
  return candidates.find((c) => fs.existsSync(c)) ?? null;
}
function runScan(options) {
  const allFindings = [];
  const configPath = options.configPath ?? findConfigFile(options.target);
  const skillsPath = options.skillsPath ?? findSkillsDir(options.target);
  let version = options.openclawVersion ?? null;
  if (!version && configPath && fs.existsSync(configPath)) {
    const raw = readFileSafe(configPath);
    if (raw) {
      try {
        version = extractVersionFromConfig(JSON.parse(raw));
      } catch {
      }
    }
  }
  if (options.scanSkills) {
    const dir = skillsPath ?? options.target;
    allFindings.push(...scanSkillFiles(dir));
  }
  if (options.checkConfig && configPath) {
    allFindings.push(...checkConfig(configPath));
  } else if (options.checkConfig && !configPath) {
    allFindings.push({
      id: "INF-003",
      severity: "INFO",
      category: "CONFIG_SECURITY",
      title: "Configuration File Not Found",
      description: "Could not locate openclaw.json in the target directory.",
      recommendation: "Specify the correct path with --config-path."
    });
  }
  if (options.checkCve) {
    allFindings.push(...checkCVE(version, configPath));
  }
  if (options.checkPromptInjection) {
    const dir = skillsPath ?? options.target;
    allFindings.push(...checkPromptInjection(dir));
  }
  const summary = {
    critical: allFindings.filter((f) => f.severity === "CRITICAL").length,
    high: allFindings.filter((f) => f.severity === "HIGH").length,
    medium: allFindings.filter((f) => f.severity === "MEDIUM").length,
    low: allFindings.filter((f) => f.severity === "LOW").length,
    info: allFindings.filter((f) => f.severity === "INFO").length,
    total: allFindings.length
  };
  const exitCode = summary.critical > 0 ? 2 : summary.high > 0 ? 1 : 0;
  return {
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    version: AUDITOR_VERSION,
    target: options.target,
    findings: allFindings,
    summary,
    exitCode
  };
}
var SEV_ICON = {
  CRITICAL: "\u{1F6A8}",
  HIGH: "\u26A0\uFE0F ",
  MEDIUM: "\u{1F536}",
  LOW: "\u{1F537}",
  INFO: "\u2139\uFE0F "
};
var ANSI = {
  reset: "\x1B[0m",
  bold: "\x1B[1m",
  dim: "\x1B[2m",
  red: "\x1B[31m",
  yellow: "\x1B[33m",
  magenta: "\x1B[35m",
  cyan: "\x1B[36m",
  white: "\x1B[37m"
};
function ansiSev(sev) {
  return { CRITICAL: ANSI.magenta, HIGH: ANSI.red, MEDIUM: ANSI.yellow, LOW: ANSI.cyan, INFO: ANSI.dim }[sev] ?? "";
}
function generateTextReport(result, useColor = true) {
  const c = useColor ? (s, sev) => `${ansiSev(sev)}${s}${ANSI.reset}` : (s) => s;
  const b = useColor ? (s) => `${ANSI.bold}${s}${ANSI.reset}` : (s) => s;
  const d = useColor ? (s) => `${ANSI.dim}${s}${ANSI.reset}` : (s) => s;
  const out = [];
  out.push(b("\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557"));
  out.push(b(`\u2551  OpenClaw Security Auditor  v${result.version.padEnd(28)}\u2551`));
  out.push(b("\u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D"));
  out.push("");
  out.push(`${d("Target :")}  ${result.target}`);
  out.push(`${d("Time   :")}  ${result.timestamp}`);
  out.push("");
  const actionable = result.findings.filter((f) => f.severity !== "INFO");
  if (actionable.length === 0) {
    out.push("  \u2705  No security findings detected.");
    out.push("");
  } else {
    const catLabels = {
      MALICIOUS_SKILL: "Malicious Skill Detection",
      CONFIG_SECURITY: "Configuration Security",
      CVE: "Known CVE Exposure",
      PROMPT_INJECTION: "Prompt Injection Risk"
    };
    for (const cat of ["MALICIOUS_SKILL", "CONFIG_SECURITY", "CVE", "PROMPT_INJECTION"]) {
      const group = actionable.filter((f) => f.category === cat);
      if (group.length === 0) continue;
      const label = catLabels[cat];
      out.push(b(`\u2500\u2500 ${label} ${"\u2500".repeat(Math.max(2, 50 - label.length))}`));
      out.push("");
      for (const f of group) {
        const badge = `[${f.severity}]`;
        out.push(`${c(badge, f.severity)} ${b(f.id)}: ${f.title}`);
        if (f.cveId) out.push(`  ${d("CVE    :")} ${f.cveId}${f.cvss ? ` (CVSS ${f.cvss})` : ""}`);
        if (f.file) out.push(`  ${d("File   :")} ${f.file}${f.line ? `:${f.line}` : ""}`);
        out.push(`  ${d("Detail :")} ${f.description}`);
        if (f.evidence) out.push(`  ${d("Evidence:")} ${f.evidence}`);
        out.push(`  ${d("Fix    :")} ${f.recommendation}`);
        out.push("");
      }
    }
  }
  const infoItems = result.findings.filter((f) => f.severity === "INFO");
  if (infoItems.length > 0) {
    out.push(b("\u2500\u2500 Informational \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"));
    for (const f of infoItems) {
      out.push(`  ${d("[INFO]")} ${f.title}: ${f.description}`);
    }
    out.push("");
  }
  out.push(b("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"));
  out.push(b("  Scan Summary"));
  out.push(b("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"));
  out.push(`  ${c("CRITICAL", "CRITICAL")} : ${result.summary.critical}`);
  out.push(`  ${c("HIGH    ", "HIGH")}     : ${result.summary.high}`);
  out.push(`  ${c("MEDIUM  ", "MEDIUM")}   : ${result.summary.medium}`);
  out.push(`  ${c("LOW     ", "LOW")}      : ${result.summary.low}`);
  out.push(`  ${d("INFO      ")}   : ${result.summary.info}`);
  out.push(`  ${"\u2500".repeat(28)}`);
  out.push(`  Actionable    : ${result.summary.total - result.summary.info}`);
  out.push("");
  if (result.exitCode === 0) {
    out.push("  \u2705  PASSED \u2014 no HIGH or CRITICAL findings");
  } else if (result.exitCode === 1) {
    out.push(`  ${c("\u2717  FAILED \u2014 HIGH severity findings detected", "HIGH")}`);
  } else {
    out.push(`  ${c("\u2717  FAILED \u2014 CRITICAL severity findings detected", "CRITICAL")}`);
  }
  out.push(`  Exit code: ${result.exitCode}`);
  out.push("");
  return out.join("\n");
}
function generateMarkdownReport(result) {
  const out = [];
  const statusBadge = result.exitCode === 0 ? "\u2705 PASSED" : result.exitCode === 1 ? "\u26A0\uFE0F HIGH" : "\u{1F6A8} CRITICAL";
  out.push("# OpenClaw Security Audit Report");
  out.push("");
  out.push("| Field | Value |");
  out.push("|-------|-------|");
  out.push(`| **Tool Version** | ${result.version} |`);
  out.push(`| **Scan Target** | \`${result.target}\` |`);
  out.push(`| **Timestamp** | ${result.timestamp} |`);
  out.push(`| **Result** | ${statusBadge} |`);
  out.push("");
  out.push("## Summary");
  out.push("");
  out.push("| Severity | Count |");
  out.push("|----------|------:|");
  out.push(`| \u{1F6A8} CRITICAL | ${result.summary.critical} |`);
  out.push(`| \u26A0\uFE0F HIGH | ${result.summary.high} |`);
  out.push(`| \u{1F536} MEDIUM | ${result.summary.medium} |`);
  out.push(`| \u{1F537} LOW | ${result.summary.low} |`);
  out.push(`| \u2139\uFE0F INFO | ${result.summary.info} |`);
  out.push("");
  const actionable = result.findings.filter((f) => f.severity !== "INFO");
  if (actionable.length === 0) {
    out.push("> \u2705 No security findings detected.");
    out.push("");
  } else {
    const catLabels = {
      MALICIOUS_SKILL: "Malicious Skill Detection",
      CONFIG_SECURITY: "Configuration Security",
      CVE: "Known CVE Exposure",
      PROMPT_INJECTION: "Prompt Injection Risk"
    };
    for (const cat of ["MALICIOUS_SKILL", "CONFIG_SECURITY", "CVE", "PROMPT_INJECTION"]) {
      const group = actionable.filter((f) => f.category === cat);
      if (group.length === 0) continue;
      out.push(`## ${catLabels[cat]}`);
      out.push("");
      for (const f of group) {
        const icon = SEV_ICON[f.severity];
        out.push(`### ${icon} \`${f.id}\` \u2014 ${f.title}`);
        out.push("");
        out.push(`**Severity:** \`${f.severity}\`${f.cvss ? `  |  **CVSS:** ${f.cvss}` : ""}  |  **CVE:** ${f.cveId ?? "N/A"}`);
        if (f.file) out.push(`**Location:** \`${f.file}${f.line ? ":" + f.line : ""}\``);
        out.push("");
        out.push(f.description);
        out.push("");
        if (f.evidence) {
          out.push("**Evidence:**");
          out.push("```");
          out.push(f.evidence);
          out.push("```");
          out.push("");
        }
        out.push(`**Recommendation:** ${f.recommendation}`);
        out.push("");
        out.push("---");
        out.push("");
      }
    }
  }
  const infoItems = result.findings.filter((f) => f.severity === "INFO");
  if (infoItems.length > 0) {
    out.push("## Informational");
    out.push("");
    for (const f of infoItems) {
      out.push(`- **${f.title}**: ${f.description}`);
    }
    out.push("");
  }
  out.push("---");
  out.push(
    "*Generated by [OpenClaw Security Auditor](https://github.com/openclaw-security/openclaw-security-auditor)*"
  );
  return out.join("\n");
}
function generateJsonReport(result) {
  return JSON.stringify(result, null, 2);
}
function parseArgs(argv) {
  const opts = {
    target: process.cwd(),
    scanSkills: false,
    checkConfig: false,
    checkCve: false,
    checkPromptInjection: false,
    reportFormat: "text",
    verbose: false,
    help: false,
    showVersion: false
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];
    switch (arg) {
      case "--full":
      case "-f":
        opts.scanSkills = true;
        opts.checkConfig = true;
        opts.checkCve = true;
        opts.checkPromptInjection = true;
        break;
      case "--scan-skills":
        opts.scanSkills = true;
        if (next && !next.startsWith("-")) {
          opts.skillsPath = next;
          i++;
        }
        break;
      case "--check-config":
        opts.checkConfig = true;
        if (next && !next.startsWith("-")) {
          opts.configPath = next;
          i++;
        }
        break;
      case "--check-cve":
        opts.checkCve = true;
        if (next && !next.startsWith("-")) {
          opts.openclawVersion = next;
          i++;
        }
        break;
      case "--check-injection":
        opts.checkPromptInjection = true;
        break;
      case "--target":
      case "-t":
        if (next) {
          opts.target = next;
          i++;
        }
        break;
      case "--config-path":
        if (next) {
          opts.configPath = next;
          i++;
        }
        break;
      case "--skills-path":
        if (next) {
          opts.skillsPath = next;
          i++;
        }
        break;
      case "--openclaw-version":
        if (next) {
          opts.openclawVersion = next;
          i++;
        }
        break;
      case "--report-format":
      case "-r":
        if (next && ["text", "markdown", "json"].includes(next)) {
          opts.reportFormat = next;
          i++;
        }
        break;
      case "--verbose":
      case "-v":
        opts.verbose = true;
        break;
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--version":
      case "-V":
        opts.showVersion = true;
        break;
    }
  }
  if (!opts.scanSkills && !opts.checkConfig && !opts.checkCve && !opts.checkPromptInjection && !opts.help && !opts.showVersion) {
    opts.scanSkills = true;
    opts.checkConfig = true;
    opts.checkCve = true;
    opts.checkPromptInjection = true;
  }
  return opts;
}
var HELP_TEXT = `
OpenClaw Security Auditor v${AUDITOR_VERSION}
Security audit tool for OpenClaw AI assistant installations.

USAGE
  openclaw-security-auditor [OPTIONS]
  npx ts-node skill/scripts/auditor.ts [OPTIONS]

SCAN OPTIONS
  --full, -f               Run all security checks (default when no flag given)
  --scan-skills [path]     Scan skills directory for malicious patterns
  --check-config [path]    Audit OpenClaw configuration (openclaw.json)
  --check-cve [version]    Check known CVE exposure for the specified version
  --check-injection        Check for prompt injection risks

TARGET OPTIONS
  --target, -t <path>      OpenClaw installation directory (default: cwd)
  --config-path <path>     Explicit path to openclaw.json
  --skills-path <path>     Explicit path to skills directory
  --openclaw-version <v>   OpenClaw version string (e.g. 1.1.4)

OUTPUT OPTIONS
  --report-format, -r      Output format: text | markdown | json  (default: text)
  --verbose, -v            Enable verbose output

GENERAL
  --version, -V            Print version and exit
  --help, -h               Show this help

EXIT CODES
  0   All checks passed \u2014 no HIGH or CRITICAL findings
  1   HIGH severity findings detected
  2   CRITICAL severity findings detected

EXAMPLES
  # Full audit of default OpenClaw installation
  openclaw-security-auditor --full

  # Scan a specific skills directory, output JSON
  openclaw-security-auditor --scan-skills ~/.openclaw/skills --report-format json

  # Check CVE exposure for a specific version
  openclaw-security-auditor --check-cve 1.1.4 --report-format markdown

  # Audit a specific config file
  openclaw-security-auditor --check-config /opt/openclaw/openclaw.json

  # Use in CI/CD (exits non-zero on findings)
  openclaw-security-auditor --full --report-format json > audit.json
`;
function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.showVersion) {
    process.stdout.write(`OpenClaw Security Auditor v${AUDITOR_VERSION}
`);
    process.exit(0);
  }
  if (opts.help) {
    process.stdout.write(HELP_TEXT + "\n");
    process.exit(0);
  }
  const result = runScan(opts);
  let output;
  switch (opts.reportFormat) {
    case "json":
      output = generateJsonReport(result);
      break;
    case "markdown":
      output = generateMarkdownReport(result);
      break;
    default:
      output = generateTextReport(result, process.stdout.isTTY ?? false);
  }
  process.stdout.write(output + "\n");
  process.exit(result.exitCode);
}
if (require.main === module) {
  main();
}

// bin/cli.ts
main(process.argv.slice(2));

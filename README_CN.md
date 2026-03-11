# OpenClaw 安全审计工具

[English](README.md) | **中文**

[OpenClaw](https://github.com/openclaw/openclaw) AI 助手安装环境的安全审计工具。

检测**恶意技能**（ClawHavoc / AMOS 攻击活动）、**危险配置**、**已知 CVE 漏洞**和**提示词注入风险** —— 零外部依赖。

```
╔══════════════════════════════════════════════════════════╗
║  OpenClaw Security Auditor  v1.0.0                       ║
╚══════════════════════════════════════════════════════════╝

Target :  /home/user/.openclaw
Time   :  2026-03-11T10:00:00Z

── 恶意技能检测 ────────────────────────────────────────────

[CRITICAL] MAL-001: Base64 编码载荷执行
  文件   : skills/optimizer/scripts/run.ts:42
  详情   : 执行 Base64 编码载荷是 ClawHavoc 恶意软件（AMOS 窃取器）
           使用的主要混淆技术。
  证据   : eval(Buffer.from('aGVsbG8=', 'base64').toString())
  修复   : 立即删除此代码。合法技能从不执行编码载荷。

── 已知 CVE 漏洞 ──────────────────────────────────────────

[CRITICAL] CVE-2026-25253: WebSocket Token 窃取导致 RCE
  CVE    : CVE-2026-25253 (CVSS 8.8)
  详情   : OpenClaw 1.1.0 受影响，请升级到 >= 1.2.1。

══════════════════════════════════════════════════════════
  扫描汇总
══════════════════════════════════════════════════════════
  严重 (CRITICAL) : 2
  高危 (HIGH)     : 3
  中危 (MEDIUM)   : 1
  低危 (LOW)      : 0
  信息 (INFO)     : 2

  ✗  失败 — 检测到严重级别风险
  退出码: 2
```

---

## 背景

**ClawHavoc**（2025 年 12 月 – 2026 年 1 月）：800 余个恶意技能被发布到 ClawHub 社区市场，内嵌 **AMOS（Atomic macOS Stealer）** 恶意软件。攻击手段包括：

- 隐藏在技能脚本中的 Base64 编码载荷
- 伪装成 NVIDIA 驱动的木马化 MSI 安装包
- 通过 **bore.pub** 隧道的隐蔽 MCP 服务器
- SSH 密钥、浏览器密码及加密货币钱包窃取

已知 CVE：

| CVE | CVSS | 描述 | 修复版本 |
|-----|:----:|------|:--------:|
| [CVE-2026-25253](skill/references/cve-database.md#cve-2026-25253) | **8.8** | WebSocket Token 窃取 → RCE | 1.2.1 |
| [CVE-2026-24763](skill/references/cve-database.md#cve-2026-24763) | **7.5** | 工作区路径命令注入 | 1.2.0 |
| [CVE-2026-25157](skill/references/cve-database.md#cve-2026-25157) | **6.8** | exec.host 覆盖导致沙箱逃逸 | 1.1.8 |
| [CVE-2026-25475](skill/references/cve-database.md#cve-2026-25475) | **6.1** | 认证无暴力破解保护 | 1.1.5 |
| [CVE-2026-27001](skill/references/cve-database.md#cve-2026-27001) | **5.4** | 提示词注入路径遍历 | 1.2.3 |

---

## 安装

### 方式一 — npm（推荐）

```bash
npm install -g openclaw-security-auditor
openclaw-security-auditor --full
```

免安装运行：

```bash
npx openclaw-security-auditor --full
```

### 方式二 — curl 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/openclaw-security/openclaw-security-auditor/main/install.sh | bash
```

### 方式三 — OpenClaw 技能（通过 ClawHub）

```bash
clawhub install openclaw-security-auditor
```

安装后，在任意已连接的消息应用中触发：

> "审计安全"
> "扫描我的技能"
> "我有漏洞吗"

### 方式四 — 从源码安装（开发模式）

```bash
git clone https://github.com/imsebao/OpenClaw_Security_Auditor.git
cd OpenClaw_Security_Auditor
npm install
npm run build

# 运行编译后的二进制文件
node dist/bin/cli.js --full

# 或使用 ts-node 直接运行
npx ts-node bin/cli.ts --full
```

**环境要求：** Node.js 18+ · 零运行时依赖（仅开发依赖：TypeScript、ts-node）

---

## 使用方法

```
openclaw-security-auditor [选项]
```

### 扫描选项

| 参数 | 说明 |
|------|------|
| `--full`, `-f` | 运行所有检查（无参数时的默认行为） |
| `--scan-skills [路径]` | 扫描技能目录中的恶意模式 |
| `--check-config [路径]` | 审计 `openclaw.json` 中的危险配置 |
| `--check-cve [版本]` | 检查指定 OpenClaw 版本的 CVE 暴露情况 |
| `--check-injection` | 检测技能文件中的提示词注入风险 |

### 目标选项

| 参数 | 说明 |
|------|------|
| `--target`, `-t <路径>` | OpenClaw 安装目录（默认：当前目录） |
| `--config-path <路径>` | 显式指定 `openclaw.json` 路径 |
| `--skills-path <路径>` | 显式指定技能目录路径 |
| `--openclaw-version <版本>` | OpenClaw 版本号（如 `1.1.4`） |

### 输出选项

| 参数 | 说明 |
|------|------|
| `--report-format text\|markdown\|json` | 输出格式（默认：`text`） |
| `--verbose`, `-v` | 启用详细输出 |

### 退出码

| 退出码 | 含义 |
|:------:|------|
| `0` | 所有检查通过 — 无高危或严重风险 |
| `1` | 检测到高危（HIGH）风险 |
| `2` | 检测到严重（CRITICAL）风险 |

---

## 使用示例

```bash
# 对默认 OpenClaw 安装进行全面审计
openclaw-security-auditor --full

# 扫描指定技能目录，输出 JSON 格式便于自动化处理
openclaw-security-auditor --scan-skills ~/.openclaw/skills --report-format json

# 检查当前版本是否受任何已知 CVE 影响
openclaw-security-auditor --check-cve 1.1.4

# 审计指定配置文件，输出 Markdown 格式
openclaw-security-auditor --check-config /opt/openclaw/openclaw.json --report-format markdown

# 仅检查提示词注入风险
openclaw-security-auditor --check-injection --skills-path ./my-skill

# 对非标准安装路径进行全面审计
openclaw-security-auditor --full --target /opt/openclaw
```

---

## CI/CD 集成

工具在检测到风险时以非零状态退出，适合用于流水线门禁。

### GitHub Actions

```yaml
- name: OpenClaw 安全审计
  run: |
    npx openclaw-security-auditor --full --report-format json | tee audit.json
  # 退出码 1 = HIGH，2 = CRITICAL — 均会自动使步骤失败

- name: 上传审计报告
  uses: actions/upload-artifact@v4
  if: always()
  with:
    name: security-audit
    path: audit.json
```

### Pre-commit 钩子

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
      sast: audit.json
    when: always
```

---

## 检测覆盖范围

### 恶意技能模式（30 种）

| ID | 严重级别 | 模式描述 |
|----|:--------:|---------|
| MAL-001 | CRITICAL | Base64 编码载荷执行 |
| MAL-002 | HIGH | 可疑的长 Base64 字符串（>300 字符） |
| MAL-003 | CRITICAL | PowerShell 编码命令（-EncodedCommand） |
| MAL-004 | MEDIUM | 含非简单表达式的动态 eval() |
| MAL-005 | CRITICAL | 隧道服务：bore.pub（ClawHavoc 攻击指标） |
| MAL-006 | HIGH | 隧道服务：ngrok |
| MAL-007 | HIGH | 隧道服务：serveo / localtunnel / pagekite |
| MAL-008 | CRITICAL | 下载并执行：curl\|sh / wget\|bash |
| MAL-009 | CRITICAL | 远程获取并 eval() |
| MAL-010 | HIGH | 可执行文件/安装包下载（.exe/.msi/.dmg） |
| MAL-011 | HIGH | 静默 MSI 安装（/quiet /passive） |
| MAL-012 | HIGH | 隐藏 PowerShell 进程（-WindowStyle Hidden） |
| MAL-013 | HIGH | macOS LaunchAgent/LaunchDaemon 持久化 |
| MAL-014 | HIGH | 基于 Cron 的持久化 |
| MAL-015 | HIGH | Windows 注册表 Run 键持久化 |
| MAL-016 | HIGH | systemd 服务持久化 |
| MAL-017 | HIGH | SSH 私钥访问 |
| MAL-018 | HIGH | 浏览器凭证存储访问（Chrome/Firefox） |
| MAL-019 | HIGH | 敏感环境变量泄露 |
| MAL-020 | HIGH | macOS Keychain 访问（security 命令） |
| MAL-021 | MEDIUM | 加密货币钱包文件访问 |
| MAL-022 | CRITICAL | Bash 反弹 Shell |
| MAL-023 | CRITICAL | Netcat 反弹 Shell |
| MAL-024 | CRITICAL | Python 反弹 Shell |
| MAL-025 | HIGH | 数据上传至外部主机 |
| MAL-026 | HIGH | 使用外部隧道主机的 MCP 服务器 |
| MAL-027 | CRITICAL | AMOS / Atomic macOS Stealer 特征 |
| MAL-028 | MEDIUM | 路径遍历序列 |
| MAL-029 | HIGH | SKILL.md 中可疑的系统目录权限 |
| MAL-030 | HIGH | SKILL.md 安装部分中的二进制文件下载 |

### 配置安全检查（11 项）

| ID | 严重级别 | 检查项 |
|----|:--------:|--------|
| CFG-001 | CRITICAL | exec.host 设置为非本地地址（CVE-2026-25157） |
| CFG-002 | HIGH | 工作区路径包含 Shell 元字符（CVE-2026-24763） |
| CFG-003 | HIGH | 暴力破解保护被显式禁用（CVE-2026-25475） |
| CFG-004 | MEDIUM | 未配置暴力破解保护 |
| CFG-005 | HIGH | TLS/HTTPS 已禁用 |
| CFG-006 | HIGH | CORS 通配符来源（*） |
| CFG-007 | MEDIUM | WebSocket Token 明文存储（CVE-2026-25253） |
| CFG-008 | MEDIUM | 服务器绑定至所有网络接口（0.0.0.0） |
| CFG-009 | MEDIUM | 调试模式已启用 |
| CFG-010 | LOW | 技能自动更新已启用 |
| CFG-011 | HIGH | MCP 服务器使用外部/隧道主机 |

### 提示词注入检测（9 种模式）

| ID | 严重级别 | 模式描述 |
|----|:--------:|---------|
| INJ-001 | HIGH | 指令覆盖（"ignore previous instructions"） |
| INJ-002 | HIGH | 角色操控（"you are now"、"act as"） |
| INJ-003 | HIGH | 系统提示词提取尝试 |
| INJ-004 | MEDIUM | SKILL.md 节标题注入 |
| INJ-005 | MEDIUM | 用户输入上下文中的路径遍历 |
| INJ-006 | HIGH | Unicode 双向覆盖字符 |
| INJ-007 | MEDIUM | 提示词分隔符注入（`</system>`） |
| INJ-008 | MEDIUM | 已知越狱关键词（DAN、god mode） |
| INJ-009 | LOW | 通过外部内容的间接提示词注入 |

---

## 项目结构

```
openclaw-security-auditor/
├── .github/workflows/ci.yml        # CI 测试矩阵 + 标签触发 npm 发布
├── .gitignore
├── LICENSE                          # MIT
├── README.md                        # English
├── README_CN.md                     # 中文
├── package.json                     # npm 包，bin → dist/bin/cli.js
├── tsconfig.json
├── bin/
│   └── cli.ts                       # CLI 入口
├── install.sh                       # curl 一键安装脚本
├── skill/
│   ├── SKILL.md                     # OpenClaw 技能定义
│   ├── scripts/
│   │   └── auditor.ts               # 核心扫描引擎（所有逻辑在此）
│   └── references/
│       ├── cve-database.md          # CVE 技术详情
│       └── malicious-patterns.md    # 模式参考（映射至 MITRE ATT&CK）
└── tests/
    ├── auditor.test.ts              # 测试套件（node:test，零依赖）
    └── fixtures/
        ├── malicious-skill/         # 模拟恶意技能（用于测试）
        ├── safe-skill/              # 干净技能（用于误报测试）
        └── configs/
            ├── vulnerable.json      # 包含所有漏洞的配置
            └── secure.json          # 加固参考配置
```

---

## 贡献指南

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feat/new-pattern`
3. 在 `skill/scripts/auditor.ts` 的 `MALICIOUS_PATTERNS` 中添加你的模式
4. 在 `tests/auditor.test.ts` 中添加测试用例
5. 确保测试通过：`npm run build && npm test`
6. 提交 Pull Request

### 报告新的恶意模式

在野外发现了新的攻击模式？请提交 Issue，并附上：
- 脱敏的恶意代码示例
- 检测正则表达式
- MITRE ATT&CK 技术 ID
- 实际观察到的上下文

---

## 发布到 ClawHub

```bash
# 安装 ClawHub CLI
npm install -g clawhub-cli

# 登录
clawhub login

# 发布
clawhub publish --skill-dir ./skill
```

---

## 许可证

MIT — 查看 [LICENSE](LICENSE)

---

*为应对 ClawHavoc 事件而生。保持安全。*

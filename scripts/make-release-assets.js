const fs = require('fs');
const path = require('path');

// install.sh expects per-platform/arch asset names, but the bundle is pure JS and identical.
const releaseDir = path.join('dist', 'release');
const base = path.join(releaseDir, 'openclaw-security-auditor.js');

if (!fs.existsSync(base)) {
  console.error(`Missing bundle: ${base}. Run "npm run bundle:release" first.`);
  process.exit(1);
}

fs.mkdirSync(releaseDir, { recursive: true });

const variants = [
  'openclaw-security-auditor-linux-x64.js',
  'openclaw-security-auditor-linux-arm64.js',
  'openclaw-security-auditor-macos-x64.js',
  'openclaw-security-auditor-macos-arm64.js',
];

for (const name of variants) {
  fs.copyFileSync(base, path.join(releaseDir, name));
}

process.stdout.write(`Release assets ready in ${releaseDir}\n`);


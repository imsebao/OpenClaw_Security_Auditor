const fs = require('fs');
const path = require('path');

function copyDir(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const s = path.join(src, entry.name);
    const d = path.join(dst, entry.name);
    if (entry.isDirectory()) copyDir(s, d);
    else if (entry.isFile()) fs.copyFileSync(s, d);
  }
}

const srcSkillDir = path.join('skill');
const distSkillDir = path.join('dist', 'skill');

const srcSkillMd = path.join(srcSkillDir, 'SKILL.md');
const srcRefsDir = path.join(srcSkillDir, 'references');

if (!fs.existsSync(srcSkillMd)) {
  console.error(`Missing ${srcSkillMd}`);
  process.exit(1);
}

// Ensure dist/skill exists (tsc creates dist/skill/scripts via compilation).
fs.mkdirSync(distSkillDir, { recursive: true });

// Copy references for ClawHub packaging.
if (fs.existsSync(srcRefsDir)) {
  copyDir(srcRefsDir, path.join(distSkillDir, 'references'));
}

// Copy SKILL.md but point Script to compiled JS.
let skillMd = fs.readFileSync(srcSkillMd, 'utf-8');
skillMd = skillMd.replace(/scripts\/auditor\.ts\b/g, 'scripts/auditor.js');
fs.writeFileSync(path.join(distSkillDir, 'SKILL.md'), skillMd, 'utf-8');

process.stdout.write('Prepared dist/skill for ClawHub publish\n');


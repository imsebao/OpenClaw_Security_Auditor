#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * OpenClaw Security Auditor — CLI entry point
 *
 * This thin wrapper delegates to the core engine in skill/scripts/auditor.ts.
 * Run directly:  npx ts-node bin/cli.ts [OPTIONS]
 * After build:   node dist/bin/cli.js [OPTIONS]
 */
const auditor_1 = require("../skill/scripts/auditor");
(0, auditor_1.main)(process.argv.slice(2));
//# sourceMappingURL=cli.js.map
#!/usr/bin/env node
/**
 * OpenClaw Security Auditor — CLI entry point
 *
 * This thin wrapper delegates to the core engine in skill/scripts/auditor.ts.
 * Run directly:  npx ts-node bin/cli.ts [OPTIONS]
 * After build:   node dist/bin/cli.js [OPTIONS]
 */
import { main } from '../skill/scripts/auditor';

main(process.argv.slice(2));

/**
 * OpenClaw Security Auditor - Core Scanning Engine
 *
 * Detects malicious patterns, configuration vulnerabilities,
 * known CVEs, and prompt injection risks in OpenClaw installations.
 *
 * Zero external dependencies — uses only Node.js built-in modules.
 */
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Category = 'MALICIOUS_SKILL' | 'CONFIG_SECURITY' | 'CVE' | 'PROMPT_INJECTION';
export type ReportFormat = 'text' | 'markdown' | 'json';
export interface Finding {
    id: string;
    severity: Severity;
    category: Category;
    title: string;
    description: string;
    file?: string;
    line?: number;
    evidence?: string;
    recommendation: string;
    cveId?: string;
    cvss?: number;
}
export interface ScanOptions {
    target: string;
    scanSkills: boolean;
    checkConfig: boolean;
    checkCve: boolean;
    checkPromptInjection: boolean;
    reportFormat: ReportFormat;
    verbose: boolean;
    configPath?: string;
    skillsPath?: string;
    openclawVersion?: string;
}
export interface ScanSummary {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
}
export interface ScanResult {
    timestamp: string;
    version: string;
    target: string;
    findings: Finding[];
    summary: ScanSummary;
    exitCode: 0 | 1 | 2;
}
export declare const AUDITOR_VERSION = "1.0.0";
export declare function isVersionLessThan(version: string, threshold: string): boolean;
export declare function scanSkillFiles(skillsDir: string): Finding[];
export declare function checkConfig(configPath: string): Finding[];
export declare function checkCVE(version: string | null, configPath?: string | null): Finding[];
export declare function checkPromptInjection(targetDir: string): Finding[];
export declare function runScan(options: ScanOptions): ScanResult;
export declare function generateTextReport(result: ScanResult, useColor?: boolean): string;
export declare function generateMarkdownReport(result: ScanResult): string;
export declare function generateJsonReport(result: ScanResult): string;
export interface CliOptions extends ScanOptions {
    help: boolean;
    showVersion: boolean;
}
export declare function parseArgs(argv: string[]): CliOptions;
export declare function main(argv?: string[]): void;
//# sourceMappingURL=auditor.d.ts.map
export interface Root {
  auditReportVersion: number;
  vulnerabilities: Vulnerabilities;
  metadata: Metadata;
}

export interface Vulnerabilities {
  [packageName: string]: Vulnerability;
}

export interface Vulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | Via>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: FixAvailable | boolean;
}

export interface FixAvailable {
  name: string;
  version: string;
  isSemVerMajor: boolean;
}

export interface Via {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: string;
  cwe: string[];
  cvss: Cvss;
  range: string;
}

export interface Cvss {
  score: number;
  vectorString: string;
}

export interface Metadata {
  vulnerabilities: VulnerabilityCounts;
  dependencies: Dependencies;
}

export interface VulnerabilityCounts {
  info: number;
  low: number;
  moderate: number;
  high: number;
  critical: number;
  total: number;
}

export interface Dependencies {
  prod: number;
  dev: number;
  optional: number;
  peer: number;
  peerOptional: number;
  total: number;
}

export interface CmdOutput {
  code: number;
  stdout: string;
  stderr: string;
}

export interface PackageIdPair {
  id: number;
  nodes: string[];
}

export const AuditLevels = [
  'info',
  'low',
  'moderate',
  'high',
  'critical',
] as const;
export type AuditLevel = typeof AuditLevels[number];

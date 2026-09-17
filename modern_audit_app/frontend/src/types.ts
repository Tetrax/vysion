export type AuditOptions = {
  utm_license: boolean;
  mpls_l2l: boolean;
  wan_interfaces?: string[];
};

export type AuditResult = {
  hostname: string;
  version?: string | null;
  model?: string | null;
  summary: Record<string, unknown>;
  warnings: string[];
  reports: Record<string, string>;
};








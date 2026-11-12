// Mirrors the backend's JSON (src/veritas/api/app.py, web/scanner.py, veritas/inference.py).

export type TestStatus = 'passed' | 'failed' | 'warning' | 'info' | 'defended';

export interface SecurityTest {
  id: string;
  name: string;
  category: string;
  status: TestStatus;
  score_impact: number;
  metric: string;
  observed_value: string;
  baseline: string;
  description: string;
  technical_details: string;
  remediation: string;
  auto_fixable: boolean;
  permission_required: boolean;
  remediation_type: string;
}

export interface ScanReport {
  target_input: string;
  hostname: string;
  ip_addresses: string[];
  port: number;
  protocol: string;
  scan_timestamp: string;
  scan_duration_ms: number;
  security_score: number;
  posture_verdict: string;
  posture_class: string;
  tests: SecurityTest[];
  open_ports: number[];
  vulnerabilities_count: { critical: number; high: number; medium: number; low: number; passed: number };
  recommended_preventions: Array<Record<string, unknown>>;
  applied_preventions: string[];
}

export interface Rate {
  value: number | null;
  hits: number;
  total: number;
  ci95: [number, number] | null;
}

export interface ModelInfo {
  version: string | null;
  trained_at: string | null;
  profile: string | null;
  estimator: string | null;
  threshold: number;
  n_features: number;
  training_samples: number | null;
  clean_test?: {
    recall: Rate;
    false_positive_rate: Rate;
    caveat?: string;
  } | null;
  sklearn_mismatch: boolean;
  cicflowmeter_mismatch: boolean;
  limitations: string;
}

export interface FeatureContribution {
  feature: string;
  value: number;
  /** Positive pushes toward malicious, negative toward benign. */
  contribution: number;
}

export interface FlowVerdict {
  flow_id: string;
  verdict: 'malicious' | 'benign';
  malicious_probability: number;
  threshold: number;
  missing_features: number;
  top_features?: FeatureContribution[];
  warning?: string;
}

export interface AnalysisResult {
  model_version: string | null;
  filename?: string;
  flows?: FlowVerdict[];
  results?: FlowVerdict[];
  summary: { flows: number; malicious: number };
  note?: string;
}

export interface ServerStatus {
  status: string;
  version: string;
  model_ready: boolean;
  auth_required: boolean;
  persistent_scans_count: number;
}

export interface PickedFile {
  uri: string;
  name: string;
  mimeType?: string;
  /** Present on web, where the picker hands back a real File/Blob. */
  file?: Blob;
}

export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type Verdict =
  | "benign"
  | "known_attack"
  | "suspicious_unknown"
  | "needs_review"
  | "processing_error";

export interface Detection {
  event_id: string;
  verdict: Verdict;
  severity: Severity;
  final_risk_score: number;
  reason_codes: string[];
  explanation: string;
  anomaly_score: number;
  reconstruction_error: number;
  reconstruction_score: number;
  known_attack_probability: number;
  signature_score: number;
  classifier_model_version: string;
  feature_schema_version: string;
}

export interface Alert {
  id: string;
  created_at: string;
  verdict: Verdict;
  severity: Severity;
  risk: number;
  acknowledged: boolean;
  flow: {
    event_id: string;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    timestamp_start: string;
  };
  detection: Detection;
}

export interface Incident {
  id: string;
  title: string;
  status: string;
  severity: Severity;
  source_host: string;
  created_at: string;
  updated_at: string;
  alert_ids: string[];
  grouping_reasons: string[];
}

export interface IncidentExplanation {
  text: string;
  provider: string;
  requested_provider: string;
  ai_generated: boolean;
  fallback: boolean;
  cached: boolean;
  incident_version_hash: string;
  generated_at: string;
  limitations: string[];
}

export interface Flow {
  event_id: string;
  timestamp_start: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packets_forward: number;
  packets_reverse: number;
  bytes_forward: number;
  bytes_reverse: number;
  protocol_metadata: Record<string, string | number | boolean>;
}

export interface Host {
  host: string;
  flows: number;
  destinations: number;
  alerting: boolean;
}

export interface ModelVersion {
  id: string;
  model_name: string;
  version: string;
  production: boolean;
  loaded_at: string;
  metadata: {
    feature_schema_version: string;
    model_classes: string[];
    validation_metrics: Record<string, number>;
    known_limitations: string[];
  };
}

export interface SystemStatus {
  database: string;
  sensors: number;
  flows: number;
  alerts: number;
  incidents: number;
  mode: "demo" | "production";
  queue: {
    pending: number;
    lag: number;
    consumers: number;
  };
}

export interface Page<T> {
  items: T[];
  count: number;
}

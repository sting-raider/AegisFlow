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
  alert_count: number;
  acknowledged_alerts: number;
  max_risk: number;
  grouping_reasons: string[];
  source_hosts: string[];
  destination_hosts: string[];
  reason_codes: string[];
  signature_names: string[];
  attack_stages: string[];
  escalation_count: number;
  timeline: IncidentTimelineEntry[];
  alerts?: Alert[];
  analyst_notes?: IncidentNote[];
}

export interface IncidentNote {
  id: string;
  actor: string;
  note: string;
  timestamp: string;
}

export interface IncidentTimelineEntry {
  alert_id: string;
  timestamp: string;
  verdict: Verdict;
  severity: Severity;
  risk: number;
  attack_stage: string;
  source_host: string;
  destination_host: string;
  acknowledged: boolean;
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
  timestamp_end: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  packets_forward: number;
  packets_reverse: number;
  bytes_forward: number;
  bytes_reverse: number;
  duration_ms: number;
  packet_rate: number;
  byte_rate: number;
  packet_length_mean: number;
  packet_length_std: number;
  iat_mean: number;
  iat_std: number;
  tcp_syn_count: number;
  tcp_ack_count: number;
  tcp_fin_count: number;
  tcp_rst_count: number;
  application_protocol: string | null;
  direction: string;
  source_adapter: string;
  feature_extractor_version: string;
  protocol_metadata: Record<string, string | number | boolean>;
}

export interface FlowDetail extends Flow {
  detection: Detection | null;
  alert_id: string | null;
  signatures: Array<{
    signature_id: string;
    signature_name: string;
    category: string;
    severity: Severity;
    source: string;
  }>;
}

export interface Host {
  host: string;
  flows: number;
  signature_events: number;
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
    capacity?: number;
    utilization?: number;
    backpressure?: boolean;
    backpressure_events?: number;
  };
  retention: {
    enabled: boolean;
    days?: number;
    interval_seconds?: number;
  };
  recent_health_events: HealthEvent[];
  throughput_per_second?: number;
  dropped_records?: number;
  suricata_status?: string;
  worker_latency_ms?: number | null;
}

export interface HealthEvent {
  id: string;
  service: string;
  status: string;
  timestamp: string;
  details: Record<string, unknown>;
}

export interface DriftEvent {
  id: string;
  signal: string;
  detected_at: string;
  magnitude: number;
  model_version: string;
  recommended_action?: string;
  automatic_action_allowed?: boolean;
}

export interface Page<T> {
  items: T[];
  count: number;
  total?: number;
  offset?: number;
  limit?: number;
}

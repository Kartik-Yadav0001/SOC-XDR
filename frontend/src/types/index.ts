export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type IncidentStatus = 'NEW' | 'INVESTIGATING' | 'CONTAINED' | 'REMEDIATED' | 'CLOSED';

export type RuleCategory = 'MALWARE' | 'EXFILTRATION' | 'LATERAL_MOVEMENT' | 'RECONNAISSANCE' | 'INITIAL_ACCESS' | 'PRIVILEGE_ESCALATION';

export interface SecurityEvent {
  id: string;
  event_type: string;
  source: string;
  severity: Severity;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  user?: string;
  action: string;
  raw_data?: Record<string, any>;
  tenant_id: string;
}

export interface DetectionRule {
  id: string;
  rule_code: string;
  name: string;
  description: string;
  category: RuleCategory;
  severity: Severity;
  mitre_tactic: string;
  mitre_technique: string;
  is_active: boolean;
  condition_query: string;
  created_at: string;
}

export interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  risk_score: number;
  rule_id: string;
  rule_name: string;
  mitre_tactic: string;
  mitre_technique: string;
  source_ip: string;
  destination_ip: string;
  user?: string;
  status: 'UNTRIAGED' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'RESOLVED' | 'FALSE_POSITIVE';
  created_at: string;
  event_ids: string[];
  tenant_id: string;
}

export interface IncidentTimelineEvent {
  id: string;
  timestamp: string;
  action: string;
  actor: string;
  notes?: string;
}

export interface IncidentCase {
  id: string;
  incident_number: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  alerts: SecurityAlert[];
  affected_hosts: string[];
  affected_users: string[];
  timeline: IncidentTimelineEvent[];
  tenant_id: string;
}

export interface PlaybookStep {
  id: string;
  step_number: number;
  action_type: 'ISOLATE_HOST' | 'BLOCK_IP' | 'REVOKE_TOKEN' | 'NOTIFY_SLACK' | 'COLLECT_MEMORY_DUMP';
  target: string;
  params?: Record<string, any>;
  status: 'PENDING' | 'RUNNING' | 'SUCCESS' | 'FAILED';
  output?: string;
}

export interface PlaybookExecution {
  id: string;
  playbook_name: string;
  incident_id?: string;
  triggered_by: string;
  status: 'RUNNING' | 'COMPLETED' | 'FAILED';
  started_at: string;
  completed_at?: string;
  steps: PlaybookStep[];
}

export interface ThreatIndicator {
  id: string;
  ioc_type: 'IP' | 'DOMAIN' | 'FILE_HASH' | 'URL';
  value: string;
  threat_type: string;
  confidence: number;
  severity: Severity;
  source: string;
  description: string;
  first_seen: string;
  last_seen: string;
  tags: string[];
}

export interface MitreTacticCoverage {
  tactic_id: string;
  tactic_name: string;
  rule_count: number;
  alert_count: number;
  active_threats: number;
}

export interface SystemHealthStatus {
  status: 'HEALTHY' | 'DEGRADED' | 'CRITICAL';
  database: 'CONNECTED' | 'DISCONNECTED';
  redis_cache: 'CONNECTED' | 'DISCONNECTED';
  detection_engine: 'RUNNING' | 'STOPPED';
  ingestion_rate_eps: number;
  active_websockets: number;
  uptime_seconds: number;
  cpu_usage_pct: number;
  memory_usage_pct: number;
}

export interface TenantWorkspace {
  id: string;
  name: string;
  slug: string;
  subscription_tier: 'ENTERPRISE' | 'PRO' | 'STANDARD';
  event_retention_days: number;
  active_agents_count: number;
  is_active: boolean;
}

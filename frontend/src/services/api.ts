import type { SecurityEvent, DetectionRule, SecurityAlert, IncidentCase, PlaybookExecution, ThreatIndicator, SystemHealthStatus, TenantWorkspace } from '../types';

const API_BASE_URL = 'http://localhost:8000/api/v1';

// MOCK SEED DATA FOR DEMO INTEGRATION
export const MOCK_HEALTH: SystemHealthStatus = {
  status: 'HEALTHY',
  database: 'CONNECTED',
  redis_cache: 'CONNECTED',
  detection_engine: 'RUNNING',
  ingestion_rate_eps: 1420,
  active_websockets: 8,
  uptime_seconds: 432000,
  cpu_usage_pct: 24.8,
  memory_usage_pct: 42.1
};

export const MOCK_TENANTS: TenantWorkspace[] = [
  { id: 'tenant-001', name: 'Global Finance Corp', slug: 'global-finance', subscription_tier: 'ENTERPRISE', event_retention_days: 90, active_agents_count: 450, is_active: true },
  { id: 'tenant-002', name: 'HealthCare Sentinel', slug: 'healthcare-sentinel', subscription_tier: 'ENTERPRISE', event_retention_days: 180, active_agents_count: 820, is_active: true },
  { id: 'tenant-003', name: 'Defense CyberTech', slug: 'defense-cybertech', subscription_tier: 'PRO', event_retention_days: 30, active_agents_count: 120, is_active: true }
];

export const MOCK_EVENTS: SecurityEvent[] = [
  {
    id: 'evt-1001',
    event_type: 'AUTH_FAILED_BURST',
    source: 'ActiveDirectory-DC01',
    severity: 'CRITICAL',
    timestamp: new Date(Date.now() - 120000).toISOString(),
    source_ip: '192.168.1.105',
    destination_ip: '10.0.0.5',
    user: 'admin_exec',
    action: 'KERBEROS_PREAUTH_FAILED',
    raw_data: { failed_attempts: 14, target_domain: 'CORP.INTERNAL', error_code: '0x18' },
    tenant_id: 'tenant-001'
  },
  {
    id: 'evt-1002',
    event_type: 'POWERSHELL_ENCODED_EXEC',
    source: 'EDR-Agent-Win11-44',
    severity: 'CRITICAL',
    timestamp: new Date(Date.now() - 300000).toISOString(),
    source_ip: '10.0.12.44',
    destination_ip: '185.220.101.4',
    user: 'j.doe',
    action: 'PROCESS_SPAWN',
    raw_data: { command_line: 'powershell.exe -e aW52b2tlLWV4cHJlc3Npb24...', parent_process: 'cmd.exe' },
    tenant_id: 'tenant-001'
  },
  {
    id: 'evt-1003',
    event_type: 'DNS_BEACONING_DETECTED',
    source: 'PaloAlto-FW-01',
    severity: 'HIGH',
    timestamp: new Date(Date.now() - 600000).toISOString(),
    source_ip: '10.0.12.88',
    destination_ip: '198.51.100.45',
    user: 'system',
    action: 'DNS_QUERY',
    raw_data: { query_domain: 'c2-server-beacon-49.xyz', query_type: 'TXT', bytes_sent: 14200 },
    tenant_id: 'tenant-001'
  },
  {
    id: 'evt-1004',
    event_type: 'LSASS_MEMORY_DUMP',
    source: 'SentinelAgent-SRV-DB02',
    severity: 'CRITICAL',
    timestamp: new Date(Date.now() - 900000).toISOString(),
    source_ip: '10.0.2.20',
    destination_ip: '10.0.2.20',
    user: 'NT AUTHORITY\\SYSTEM',
    action: 'PROCESS_HANDLE_OPEN',
    raw_data: { target_process: 'lsass.exe', granted_access: '0x1010', call_trace: 'dbgcore.dll+0x12a' },
    tenant_id: 'tenant-001'
  },
  {
    id: 'evt-1005',
    event_type: 'UNUSUAL_AWS_S3_EXFIL',
    source: 'CloudTrail-AWS',
    severity: 'HIGH',
    timestamp: new Date(Date.now() - 1200000).toISOString(),
    source_ip: '45.33.32.156',
    destination_ip: '52.92.16.12',
    user: 'svc_backup_user',
    action: 'GetObject',
    raw_data: { bucket_name: 'prod-customer-pii-vault', bytes_transferred: 4850000000, object_count: 12400 },
    tenant_id: 'tenant-001'
  }
];

export const MOCK_RULES: DetectionRule[] = [
  {
    id: 'rule-001',
    rule_code: 'DETECTION-001',
    name: 'Brute Force Authentication Burst',
    description: 'Detects over 10 failed login attempts within 60 seconds from a single IP',
    category: 'INITIAL_ACCESS',
    severity: 'HIGH',
    mitre_tactic: 'Initial Access (TA0001)',
    mitre_technique: 'Password Guessing (T1110.001)',
    is_active: true,
    condition_query: 'event_type == "AUTH_FAILED" HAVING count(*) > 10 WINDOW 60s BY source_ip',
    created_at: '2026-09-01T00:00:00Z'
  },
  {
    id: 'rule-002',
    rule_code: 'DETECTION-002',
    name: 'Obfuscated PowerShell Script Execution',
    description: 'Detects powershell.exe invoked with -e or -EncodedCommand flag',
    category: 'EXECUTION',
    severity: 'CRITICAL',
    mitre_tactic: 'Execution (TA0002)',
    mitre_technique: 'Command and Scripting Interpreter (T1059.001)',
    is_active: true,
    condition_query: 'process.name == "powershell.exe" AND command_line MATCHES "-[eE][nNcCoOdDeEdD]*"',
    created_at: '2026-09-02T00:00:00Z'
  },
  {
    id: 'rule-003',
    rule_code: 'DETECTION-003',
    name: 'LSASS Memory Dumping via Process Access',
    description: 'Detects unauthorized process handle opening to LSASS memory space',
    category: 'CREDENTIAL_ACCESS',
    severity: 'CRITICAL',
    mitre_tactic: 'Credential Access (TA0006)',
    mitre_technique: 'OS Credential Dumping: LSASS Memory (T1003.001)',
    is_active: true,
    condition_query: 'target_process == "lsass.exe" AND granted_access IN ("0x1010", "0x1F0FFF")',
    created_at: '2026-09-03T00:00:00Z'
  },
  {
    id: 'rule-004',
    rule_code: 'DETECTION-004',
    name: 'C2 High-Frequency DNS Beaconing',
    description: 'Detects periodic DNS queries to low-reputation top level domains',
    category: 'COMMAND_AND_CONTROL',
    severity: 'HIGH',
    mitre_tactic: 'Command and Control (TA0011)',
    mitre_technique: 'Application Layer Protocol: DNS (T1071.004)',
    is_active: true,
    condition_query: 'event_type == "DNS_QUERY" AND query_tld IN ("xyz", "top", "online") FREQUENCY > 50/hr',
    created_at: '2026-09-04T00:00:00Z'
  },
  {
    id: 'rule-005',
    rule_code: 'DETECTION-005',
    name: 'Massive S3 Cloud Data Exfiltration',
    description: 'Detects single session S3 bucket downloads exceeding 1GB',
    category: 'EXFILTRATION',
    severity: 'CRITICAL',
    mitre_tactic: 'Exfiltration (TA0010)',
    mitre_technique: 'Exfiltration to Cloud Storage (T1567.002)',
    is_active: true,
    condition_query: 'source == "CloudTrail" AND action == "GetObject" AND sum(bytes) > 1000000000',
    created_at: '2026-09-05T00:00:00Z'
  }
];

export const MOCK_ALERTS: SecurityAlert[] = [
  {
    id: 'alert-501',
    title: 'Critical: LSASS Credential Theft Attempt on Database Server',
    description: 'Process handle with PROCESS_VM_READ access opened to lsass.exe on DB02',
    severity: 'CRITICAL',
    risk_score: 95,
    rule_id: 'rule-003',
    rule_name: 'LSASS Memory Dumping via Process Access',
    mitre_tactic: 'Credential Access (TA0006)',
    mitre_technique: 'T1003.001',
    source_ip: '10.0.2.20',
    destination_ip: '10.0.2.20',
    user: 'NT AUTHORITY\\SYSTEM',
    status: 'UNTRIAGED',
    created_at: new Date(Date.now() - 900000).toISOString(),
    event_ids: ['evt-1004'],
    tenant_id: 'tenant-001'
  },
  {
    id: 'alert-502',
    title: 'High: Obfuscated PowerShell C2 Payload Execution',
    description: 'User j.doe executed base64 encoded PowerShell script spawning suspicious outbound connection',
    severity: 'CRITICAL',
    risk_score: 88,
    rule_id: 'rule-002',
    rule_name: 'Obfuscated PowerShell Script Execution',
    mitre_tactic: 'Execution (TA0002)',
    mitre_technique: 'T1059.001',
    source_ip: '10.0.12.44',
    destination_ip: '185.220.101.4',
    user: 'j.doe',
    status: 'IN_PROGRESS',
    created_at: new Date(Date.now() - 300000).toISOString(),
    event_ids: ['evt-1002'],
    tenant_id: 'tenant-001'
  },
  {
    id: 'alert-503',
    title: 'High: Cloud Data Exfiltration to External IP',
    description: '4.8 GB downloaded from S3 prod bucket in less than 5 minutes by service user',
    severity: 'HIGH',
    risk_score: 76,
    rule_id: 'rule-005',
    rule_name: 'Massive S3 Cloud Data Exfiltration',
    mitre_tactic: 'Exfiltration (TA0010)',
    mitre_technique: 'T1567.002',
    source_ip: '45.33.32.156',
    destination_ip: '52.92.16.12',
    user: 'svc_backup_user',
    status: 'ACKNOWLEDGED',
    created_at: new Date(Date.now() - 1200000).toISOString(),
    event_ids: ['evt-1005'],
    tenant_id: 'tenant-001'
  }
];

export const MOCK_INCIDENTS: IncidentCase[] = [
  {
    id: 'inc-9001',
    incident_number: 'INC-2026-0842',
    title: 'Active APT Attack: Credential Harvesting & Cloud Exfiltration Chain',
    description: 'Multi-stage intrusion chain identified: Initial access via Kerberos password spray, execution of encoded Cobalt Strike beacon, followed by LSASS memory dumping and mass cloud data download.',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    risk_score: 98,
    assigned_to: 'Alex Vance (Lead Tier-3 Analyst)',
    created_at: new Date(Date.now() - 3600000).toISOString(),
    updated_at: new Date(Date.now() - 600000).toISOString(),
    alerts: MOCK_ALERTS,
    affected_hosts: ['Win11-44.corp.internal', 'SRV-DB02.prod.internal', 'prod-customer-pii-vault'],
    affected_users: ['admin_exec', 'j.doe', 'svc_backup_user'],
    timeline: [
      { id: 't-1', timestamp: new Date(Date.now() - 3600000).toISOString(), action: 'Incident Auto-Correlated by SentinelX Engine', actor: 'SYSTEM' },
      { id: 't-2', timestamp: new Date(Date.now() - 3000000).toISOString(), action: 'SOAR Playbook Auto-Triggered: Host Isolation', actor: 'SOAR Engine' },
      { id: 't-3', timestamp: new Date(Date.now() - 1800000).toISOString(), action: 'Analyst assigned & triage initiated', actor: 'Alex Vance' },
      { id: 't-4', timestamp: new Date(Date.now() - 600000).toISOString(), action: 'Revoked compromise token & isolated DB02', actor: 'Alex Vance' }
    ],
    tenant_id: 'tenant-001'
  }
];

export const MOCK_PLAYBOOKS: PlaybookExecution[] = [
  {
    id: 'pb-exec-101',
    playbook_name: 'Automated Host Isolation & Memory Dump',
    incident_id: 'INC-2026-0842',
    triggered_by: 'SOAR Correlation Trigger',
    status: 'COMPLETED',
    started_at: new Date(Date.now() - 1800000).toISOString(),
    completed_at: new Date(Date.now() - 1750000).toISOString(),
    steps: [
      { id: 's1', step_number: 1, action_type: 'ISOLATE_HOST', target: '10.0.12.44', status: 'SUCCESS', output: 'Network interface disabled on Host Win11-44 via EDR API' },
      { id: 's2', step_number: 2, action_type: 'COLLECT_MEMORY_DUMP', target: '10.0.12.44', status: 'SUCCESS', output: 'Raw RAM snapshot captured & uploaded to Forensic Storage' },
      { id: 's3', step_number: 3, action_type: 'REVOKE_TOKEN', target: 'j.doe', status: 'SUCCESS', output: 'Active Azure AD & Okta sessions terminated' },
      { id: 's4', step_number: 4, action_type: 'NOTIFY_SLACK', target: '#sec-alerts-critical', status: 'SUCCESS', output: 'Slack notification dispatched to SOC Response team' }
    ]
  },
  {
    id: 'pb-exec-102',
    playbook_name: 'Firewall IP Blacklist & Threat Feed Push',
    incident_id: 'INC-2026-0842',
    triggered_by: 'Analyst Triage Action',
    status: 'COMPLETED',
    started_at: new Date(Date.now() - 1200000).toISOString(),
    completed_at: new Date(Date.now() - 1180000).toISOString(),
    steps: [
      { id: 's1', step_number: 1, action_type: 'BLOCK_IP', target: '185.220.101.4', status: 'SUCCESS', output: 'Added 185.220.101.4 to Palo Alto FW perimeter drop rule' },
      { id: 's2', step_number: 2, action_type: 'BLOCK_IP', target: '45.33.32.156', status: 'SUCCESS', output: 'Added 45.33.32.156 to AWS WAF IP Set blocklist' }
    ]
  }
];

export const MOCK_INTEL: ThreatIndicator[] = [
  {
    id: 'ioc-701',
    ioc_type: 'IP',
    value: '185.220.101.4',
    threat_type: 'Cobalt Strike C2 Node',
    confidence: 98,
    severity: 'CRITICAL',
    source: 'AlienVault OTX / MISP',
    description: 'Active Tor exit node associated with FIN7 APT campaign targeting financial institutions',
    first_seen: '2026-08-15T10:00:00Z',
    last_seen: '2026-10-04T12:00:00Z',
    tags: ['CobaltStrike', 'FIN7', 'TorExit', 'C2']
  },
  {
    id: 'ioc-702',
    ioc_type: 'FILE_HASH',
    value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    threat_type: 'Mimikatz Variant Malware',
    confidence: 100,
    severity: 'CRITICAL',
    source: 'VirusTotal Enterprise',
    description: 'Custom compiled LSASS credential stealer payload with anti-sandbox evasion',
    first_seen: '2026-09-01T08:30:00Z',
    last_seen: '2026-10-04T15:20:00Z',
    tags: ['Mimikatz', 'CredentialTheft', 'SHA256']
  },
  {
    id: 'ioc-703',
    ioc_type: 'DOMAIN',
    value: 'c2-server-beacon-49.xyz',
    threat_type: 'Dynamic DNS Beacon',
    confidence: 90,
    severity: 'HIGH',
    source: 'CrowdStrike Intelligence',
    description: 'Malicious domain hosting dynamic C2 infrastructure for ransomware staging',
    first_seen: '2026-09-20T14:10:00Z',
    last_seen: '2026-10-04T16:00:00Z',
    tags: ['C2', 'Ransomware', 'FastFlux']
  }
];

// API Helper class with fallback
export class SentinelApi {
  static async getHealth(): Promise<SystemHealthStatus> {
    try {
      const res = await fetch(`${API_BASE_URL}/health/system`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback to mock data
    }
    return MOCK_HEALTH;
  }

  static async getEvents(): Promise<SecurityEvent[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/events`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_EVENTS;
  }

  static async getRules(): Promise<DetectionRule[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/rules`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_RULES;
  }

  static async getAlerts(): Promise<SecurityAlert[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/alerts`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_ALERTS;
  }

  static async getIncidents(): Promise<IncidentCase[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/incidents`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_INCIDENTS;
  }

  static async getPlaybooks(): Promise<PlaybookExecution[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/soar/executions`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_PLAYBOOKS;
  }

  static async getThreatIntel(): Promise<ThreatIndicator[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/intel/indicators`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_INTEL;
  }

  static async getTenants(): Promise<TenantWorkspace[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/tenants`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
    } catch (e) {}
    return MOCK_TENANTS;
  }
}

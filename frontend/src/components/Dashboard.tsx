import React from 'react';
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  CheckCircle2, 
  Clock, 
  Zap, 
  TrendingUp, 
  Layers 
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import type { SecurityAlert, IncidentCase, SecurityEvent, MitreTacticCoverage } from '../types';

interface DashboardProps {
  alerts: SecurityAlert[];
  incidents: IncidentCase[];
  events: SecurityEvent[];
  onSelectAlert: (alert: SecurityAlert) => void;
  onSelectIncident: (incident: IncidentCase) => void;
}

const mockChartData = [
  { time: '00:00', events: 12000, alerts: 14 },
  { time: '04:00', events: 18000, alerts: 22 },
  { time: '08:00', events: 45000, alerts: 58 },
  { time: '12:00', events: 62000, alerts: 84 },
  { time: '16:00', events: 51000, alerts: 61 },
  { time: '20:00', events: 34000, alerts: 32 },
  { time: 'NOW',   events: 28000, alerts: 19 },
];

const mockPieData = [
  { name: 'Critical', value: 35, color: '#FF0844' },
  { name: 'High', value: 45, color: '#FF6B00' },
  { name: 'Medium', value: 15, color: '#F59E0B' },
  { name: 'Low', value: 5, color: '#00E676' },
];

const mitreCoverage: MitreTacticCoverage[] = [
  { tactic_id: 'TA0001', tactic_name: 'Initial Access', rule_count: 8, alert_count: 12, active_threats: 3 },
  { tactic_id: 'TA0002', tactic_name: 'Execution', rule_count: 14, alert_count: 24, active_threats: 5 },
  { tactic_id: 'TA0003', tactic_name: 'Persistence', rule_count: 10, alert_count: 8, active_threats: 1 },
  { tactic_id: 'TA0004', tactic_name: 'Privilege Escalation', rule_count: 12, alert_count: 15, active_threats: 4 },
  { tactic_id: 'TA0005', tactic_name: 'Defense Evasion', rule_count: 16, alert_count: 18, active_threats: 2 },
  { tactic_id: 'TA0006', tactic_name: 'Credential Access', rule_count: 11, alert_count: 29, active_threats: 6 },
  { tactic_id: 'TA0007', tactic_name: 'Discovery', rule_count: 6, alert_count: 4, active_threats: 0 },
  { tactic_id: 'TA0008', tactic_name: 'Lateral Movement', rule_count: 9, alert_count: 11, active_threats: 2 },
  { tactic_id: 'TA0009', tactic_name: 'Collection', rule_count: 5, alert_count: 3, active_threats: 0 },
  { tactic_id: 'TA0010', tactic_name: 'Exfiltration', rule_count: 7, alert_count: 16, active_threats: 3 },
  { tactic_id: 'TA0011', tactic_name: 'Command & Control', rule_count: 13, alert_count: 22, active_threats: 4 },
  { tactic_id: 'TA0040', tactic_name: 'Impact', rule_count: 4, alert_count: 2, active_threats: 0 },
];

export const Dashboard: React.FC<DashboardProps> = ({
  alerts,
  incidents,
  events,
  onSelectAlert,
  onSelectIncident
}) => {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem', padding: '1.5rem' }}>
      
      {/* Top Banner KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1.25rem' }}>
        
        {/* KPI 1: Telemetry Stream */}
        <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #00F2FE' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>EVENT INGESTION RATE</span>
            <Activity style={{ width: '18px', height: '18px', color: '#00F2FE' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, marginTop: '0.5rem', color: '#F1F5F9' }}>
            1,420 <span style={{ fontSize: '0.85rem', color: '#00F2FE', fontWeight: 600 }}>EPS</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#00E676', marginTop: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
            <TrendingUp style={{ width: '12px', height: '12px' }} /> +14.2% vs last hour
          </div>
        </div>

        {/* KPI 2: Active Alerts */}
        <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #FF0844' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>ACTIVE ALERTS</span>
            <AlertTriangle style={{ width: '18px', height: '18px', color: '#FF0844' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, marginTop: '0.5rem', color: '#FF4D6D' }}>
            {alerts.length} <span style={{ fontSize: '0.85rem', color: '#94A3B8', fontWeight: 600 }}>(2 Critical)</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#FF0844', marginTop: '0.35rem' }}>
            Action Required: Triage Priority 1
          </div>
        </div>

        {/* KPI 3: Open Incidents */}
        <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #FF6B00' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>OPEN INCIDENT CASES</span>
            <ShieldAlert style={{ width: '18px', height: '18px', color: '#FF6B00' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, marginTop: '0.5rem', color: '#FF9E00' }}>
            {incidents.length} <span style={{ fontSize: '0.85rem', color: '#94A3B8', fontWeight: 600 }}>Active</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
            INC-2026-0842 (Correlated Chain)
          </div>
        </div>

        {/* KPI 4: Enterprise Risk Score */}
        <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #A855F7' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>WORKSPACE RISK INDEX</span>
            <Zap style={{ width: '18px', height: '18px', color: '#A855F7' }} />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, marginTop: '0.5rem', color: '#C084FC' }}>
            84 <span style={{ fontSize: '0.85rem', color: '#FF0844', fontWeight: 700 }}>/ 100</span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#C084FC', marginTop: '0.35rem' }}>
            Elevated Threat Environment
          </div>
        </div>

        {/* KPI 5: SLA Performance */}
        <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #00E676' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 600 }}>RESPONSE SLA (MTTD / MTTR)</span>
            <Clock style={{ width: '18px', height: '18px', color: '#00E676' }} />
          </div>
          <div style={{ fontSize: '1.4rem', fontWeight: 800, marginTop: '0.5rem', color: '#F1F5F9', display: 'flex', gap: '0.75rem' }}>
            <span>4.2m <span style={{ fontSize: '0.65rem', color: '#00E676' }}>MTTD</span></span>
            <span>|</span>
            <span>12.8m <span style={{ fontSize: '0.65rem', color: '#00F2FE' }}>MTTR</span></span>
          </div>
          <div style={{ fontSize: '0.75rem', color: '#00E676', marginTop: '0.35rem' }}>
            100% within SLA thresholds
          </div>
        </div>

      </div>

      {/* MITRE ATT&CK Matrix Heatmap Bar */}
      <div className="glass-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <div>
            <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Layers style={{ width: '18px', height: '18px', color: '#00F2FE' }} />
              MITRE ATT&CK® Enterprise Coverage & Active Tactic Heatmap
            </h3>
            <p style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Real-time rule coverage mapping and correlated threat density across MITRE ATT&CK v14 tactics</p>
          </div>
          <span style={{ fontSize: '0.75rem', background: 'rgba(0, 242, 254, 0.1)', color: '#00F2FE', padding: '0.25rem 0.6rem', borderRadius: '6px', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
            104 Rules Mapped
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem' }}>
          {mitreCoverage.map((item) => (
            <div
              key={item.tactic_id}
              style={{
                background: item.active_threats > 3 ? 'rgba(255, 8, 68, 0.12)' : item.active_threats > 0 ? 'rgba(255, 107, 0, 0.12)' : 'rgba(15, 23, 42, 0.6)',
                border: item.active_threats > 3 ? '1px solid rgba(255, 8, 68, 0.4)' : item.active_threats > 0 ? '1px solid rgba(255, 107, 0, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
                borderRadius: '8px',
                padding: '0.75rem 0.6rem',
                textAlign: 'center',
                transition: 'transform 0.2s ease'
              }}
            >
              <div style={{ fontSize: '0.65rem', color: '#64748B', fontWeight: 700 }}>{item.tactic_id}</div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, color: '#F1F5F9', margin: '0.2rem 0' }}>{item.tactic_name}</div>
              <div style={{ display: 'flex', justifyContent: 'center', gap: '0.4rem', marginTop: '0.4rem', fontSize: '0.65rem' }}>
                <span style={{ color: '#00F2FE' }}>{item.rule_count} rules</span>
                {item.active_threats > 0 && (
                  <span style={{ color: item.active_threats > 3 ? '#FF4D6D' : '#FF9E00', fontWeight: 800 }}>
                    {item.active_threats} alerts
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Analytics Charts Section */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.25rem' }}>
        
        {/* Chart 1: Telemetry Volume & Alerts Over Time */}
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '1rem', color: '#F1F5F9' }}>
            24-Hour Telemetry Volume & Alert Ingestion Pattern
          </h3>
          <div style={{ width: '100%', height: '260px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={mockChartData}>
                <defs>
                  <linearGradient id="colorEvents" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00F2FE" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#00F2FE" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#FF0844" stopOpacity={0.6}/>
                    <stop offset="95%" stopColor="#FF0844" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#64748B" fontSize={12} />
                <YAxis stroke="#64748B" fontSize={12} />
                <Tooltip contentStyle={{ background: '#0B0F19', borderColor: 'rgba(255,255,255,0.1)', color: '#FFF' }} />
                <Area type="monotone" dataKey="events" stroke="#00F2FE" fillOpacity={1} fill="url(#colorEvents)" name="Events" />
                <Area type="monotone" dataKey="alerts" stroke="#FF0844" fillOpacity={1} fill="url(#colorAlerts)" name="Triggered Alerts" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Chart 2: Threat Severity Breakdown */}
        <div className="glass-card" style={{ padding: '1.25rem', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 700, marginBottom: '0.5rem', color: '#F1F5F9', width: '100%', textAlign: 'left' }}>
            Severity Breakdown
          </h3>
          <div style={{ width: '100%', height: '200px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={mockPieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} paddingAngle={5} dataKey="value">
                  {mockPieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0B0F19', borderColor: 'rgba(255,255,255,0.1)' }} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', justifyContent: 'center', fontSize: '0.75rem' }}>
            {mockPieData.map(d => (
              <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: d.color }} />
                <span style={{ color: '#94A3B8' }}>{d.name} ({d.value}%)</span>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Active Triage Feed Section */}
      <div className="glass-card" style={{ padding: '1.25rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ fontSize: '1.05rem', fontWeight: 700, color: '#F1F5F9' }}>
            High-Priority Security Triage Queue
          </h3>
          <span style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Showing top active threats</span>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#64748B', fontSize: '0.75rem' }}>
                <th style={{ padding: '0.75rem' }}>SEVERITY</th>
                <th style={{ padding: '0.75rem' }}>ALERT TITLE</th>
                <th style={{ padding: '0.75rem' }}>MITRE TACTIC</th>
                <th style={{ padding: '0.75rem' }}>SOURCE IP</th>
                <th style={{ padding: '0.75rem' }}>RISK SCORE</th>
                <th style={{ padding: '0.75rem' }}>STATUS</th>
                <th style={{ padding: '0.75rem', textAlign: 'right' }}>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert) => (
                <tr
                  key={alert.id}
                  style={{
                    borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                    transition: 'background 0.2s',
                    cursor: 'pointer'
                  }}
                  onClick={() => onSelectAlert(alert)}
                >
                  <td style={{ padding: '0.75rem' }}>
                    <span className={`badge badge-${alert.severity.toLowerCase()}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', fontWeight: 600, color: '#F1F5F9' }}>
                    {alert.title}
                  </td>
                  <td style={{ padding: '0.75rem', color: '#00F2FE' }}>
                    {alert.mitre_tactic}
                  </td>
                  <td style={{ padding: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94A3B8' }}>
                    {alert.source_ip}
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{ fontWeight: 800, color: alert.risk_score > 80 ? '#FF0844' : '#FF6B00' }}>
                      {alert.risk_score}/100
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span style={{
                      padding: '0.2rem 0.5rem',
                      borderRadius: '4px',
                      fontSize: '0.7rem',
                      fontWeight: 700,
                      background: alert.status === 'UNTRIAGED' ? 'rgba(255, 8, 68, 0.15)' : 'rgba(0, 242, 254, 0.15)',
                      color: alert.status === 'UNTRIAGED' ? '#FF4D6D' : '#00F2FE'
                    }}>
                      {alert.status}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                    <button
                      className="glass-button"
                      style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectAlert(alert);
                      }}
                    >
                      Investigate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  );
};

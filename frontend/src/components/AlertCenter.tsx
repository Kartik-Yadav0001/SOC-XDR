import React, { useState } from 'react';
import { AlertTriangle, Filter, CheckCircle2, UserCheck, ShieldAlert, Cpu, ArrowRight } from 'lucide-react';
import type { SecurityAlert, Severity } from '../types';

interface AlertCenterProps {
  alerts: SecurityAlert[];
  onUpdateAlertStatus: (alertId: string, status: SecurityAlert['status']) => void;
  onTriggerSoar: (alert: SecurityAlert) => void;
}

export const AlertCenter: React.FC<AlertCenterProps> = ({
  alerts,
  onUpdateAlertStatus,
  onTriggerSoar
}) => {
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [activeAlert, setActiveAlert] = useState<SecurityAlert | null>(alerts[0] || null);

  const filteredAlerts = alerts.filter(a => selectedSeverity === 'ALL' || a.severity === selectedSeverity);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <AlertTriangle style={{ width: '22px', height: '22px', color: '#FF0844' }} />
            Security Alert Triage Center
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Prioritized threat alerts correlated by detection engine rules with automated risk scoring</p>
        </div>
      </div>

      {/* Toolbar */}
      <div className="glass-card" style={{ padding: '0.85rem 1.25rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <Filter style={{ width: '16px', height: '16px', color: '#94A3B8' }} />
        <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Filter Severity:</span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setSelectedSeverity(sev)}
            style={{
              padding: '0.35rem 0.65rem',
              borderRadius: '6px',
              border: 'none',
              background: selectedSeverity === sev ? 'linear-gradient(135deg, #FF0844, #FF6B00)' : 'rgba(15, 23, 42, 0.6)',
              color: selectedSeverity === sev ? '#FFF' : '#94A3B8',
              fontWeight: selectedSeverity === sev ? 800 : 500,
              fontSize: '0.75rem',
              cursor: 'pointer'
            }}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Main Split Layout: Left List, Right Detail Inspector */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: '1.25rem' }}>
        
        {/* Left Alert List */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {filteredAlerts.map((alert) => (
            <div
              key={alert.id}
              className="glass-card"
              onClick={() => setActiveAlert(alert)}
              style={{
                padding: '1.1rem',
                cursor: 'pointer',
                borderLeft: `4px solid ${alert.severity === 'CRITICAL' ? '#FF0844' : '#FF6B00'}`,
                background: activeAlert?.id === alert.id ? 'rgba(0, 242, 254, 0.08)' : 'var(--bg-card)',
                borderColor: activeAlert?.id === alert.id ? '#00F2FE' : 'rgba(255,255,255,0.08)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                <span className={`badge badge-${alert.severity.toLowerCase()}`}>
                  {alert.severity}
                </span>
                <span style={{ fontSize: '0.8rem', fontWeight: 800, color: alert.risk_score > 80 ? '#FF0844' : '#FF6B00' }}>
                  Risk: {alert.risk_score}/100
                </span>
              </div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.35rem' }}>
                {alert.title}
              </h4>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'flex', gap: '0.75rem' }}>
                <span>SRC: {alert.source_ip}</span>
                <span>•</span>
                <span>Rule: {alert.rule_name}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Right Detail Inspector Drawer */}
        {activeAlert ? (
          <div className="glass-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
            
            {/* Header info */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span className={`badge badge-${activeAlert.severity.toLowerCase()}`}>
                  {activeAlert.severity} PRIORITY
                </span>
                <span style={{ fontSize: '0.75rem', color: '#94A3B8', fontFamily: 'var(--font-mono)' }}>
                  ID: {activeAlert.id}
                </span>
              </div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#F1F5F9', marginBottom: '0.5rem' }}>
                {activeAlert.title}
              </h3>
              <p style={{ fontSize: '0.85rem', color: '#94A3B8', lineHeight: '1.5' }}>
                {activeAlert.description}
              </p>
            </div>

            {/* Risk Index Gauge */}
            <div style={{ background: 'rgba(15, 23, 42, 0.8)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginBottom: '0.35rem', fontWeight: 700 }}>AUTONOMOUS RISK ASSESSMENT</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <div style={{ fontSize: '2rem', fontWeight: 900, color: '#FF0844' }}>{activeAlert.risk_score}</div>
                <div style={{ flex: 1 }}>
                  <div style={{ height: '8px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
                    <div style={{ width: `${activeAlert.risk_score}%`, height: '100%', background: 'linear-gradient(90deg, #FF6B00, #FF0844)' }} />
                  </div>
                  <div style={{ fontSize: '0.7rem', color: '#FF4D6D', marginTop: '0.25rem' }}>Critical Attack Surface Exposure</div>
                </div>
              </div>
            </div>

            {/* Key Indicators */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.75rem', borderRadius: '6px' }}>
                <span style={{ color: '#64748B', display: 'block', fontSize: '0.7rem' }}>MITRE ATT&CK</span>
                <span style={{ color: '#00F2FE', fontWeight: 700 }}>{activeAlert.mitre_tactic}</span>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.75rem', borderRadius: '6px' }}>
                <span style={{ color: '#64748B', display: 'block', fontSize: '0.7rem' }}>TECHNIQUE ID</span>
                <span style={{ color: '#F1F5F9', fontWeight: 700 }}>{activeAlert.mitre_technique}</span>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.75rem', borderRadius: '6px' }}>
                <span style={{ color: '#64748B', display: 'block', fontSize: '0.7rem' }}>SOURCE IP ADDRESS</span>
                <span style={{ color: '#A7F3D0', fontFamily: 'var(--font-mono)' }}>{activeAlert.source_ip}</span>
              </div>
              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.75rem', borderRadius: '6px' }}>
                <span style={{ color: '#64748B', display: 'block', fontSize: '0.7rem' }}>TARGET DESTINATION</span>
                <span style={{ color: '#A7F3D0', fontFamily: 'var(--font-mono)' }}>{activeAlert.destination_ip}</span>
              </div>
            </div>

            {/* Interactive Response Buttons */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', marginTop: '0.5rem', borderTop: '1px solid rgba(255,255,255,0.1)', paddingTop: '1rem' }}>
              <button
                className="glass-button glass-button-primary"
                onClick={() => onTriggerSoar(activeAlert)}
                style={{ justifyContent: 'center' }}
              >
                <Cpu style={{ width: '16px', height: '16px' }} /> Trigger SOAR Automated Playbook
              </button>

              <div style={{ display: 'flex', gap: '0.75rem' }}>
                <button
                  className="glass-button"
                  style={{ flex: 1, justifyContent: 'center' }}
                  onClick={() => onUpdateAlertStatus(activeAlert.id, 'IN_PROGRESS')}
                >
                  <UserCheck style={{ width: '14px', height: '14px' }} /> Assign to Me
                </button>
                <button
                  className="glass-button"
                  style={{ flex: 1, justifyContent: 'center' }}
                  onClick={() => onUpdateAlertStatus(activeAlert.id, 'RESOLVED')}
                >
                  <CheckCircle2 style={{ width: '14px', height: '14px' }} /> Mark Resolved
                </button>
              </div>
            </div>

          </div>
        ) : (
          <div className="glass-card" style={{ padding: '2rem', textAlign: 'center', color: '#64748B' }}>
            Select an alert from the queue to view full forensics
          </div>
        )}

      </div>

    </div>
  );
};

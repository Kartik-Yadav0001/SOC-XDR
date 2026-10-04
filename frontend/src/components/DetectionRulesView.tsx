import React, { useState } from 'react';
import { ShieldAlert, Plus, ToggleLeft, ToggleRight, Layers, Code, CheckCircle, Search } from 'lucide-react';
import type { DetectionRule, RuleCategory, Severity } from '../types';

interface DetectionRulesViewProps {
  rules: DetectionRule[];
  onToggleRule: (ruleId: string) => void;
}

export const DetectionRulesView: React.FC<DetectionRulesViewProps> = ({ rules, onToggleRule }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newRule, setNewRule] = useState({
    rule_code: 'DETECTION-006',
    name: 'Suspicious Lateral Movement via WMI Exec',
    description: 'Detects wmic.exe spawning remote process on domain hosts',
    category: 'LATERAL_MOVEMENT' as RuleCategory,
    severity: 'HIGH' as Severity,
    mitre_tactic: 'Lateral Movement (TA0008)',
    mitre_technique: 'T1047',
    condition_query: 'process.name == "wmic.exe" AND command_line MATCHES "/node:.*process call create"'
  });

  const filteredRules = rules.filter(r => 
    r.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.rule_code.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.mitre_tactic.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldAlert style={{ width: '22px', height: '22px', color: '#00F2FE' }} />
            Autonomous Detection Engine & Rule Catalog
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Manage SIGMA & SentinelX detection logic for real-time event correlation and alerting</p>
        </div>
        <button
          className="glass-button glass-button-primary"
          onClick={() => setShowCreateModal(true)}
        >
          <Plus style={{ width: '16px', height: '16px' }} /> Create Detection Rule
        </button>
      </div>

      {/* Toolbar */}
      <div className="glass-card" style={{ padding: '1rem', display: 'flex', gap: '1rem', alignItems: 'center' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '16px', height: '16px', color: '#64748B' }} />
          <input
            type="text"
            className="glass-input"
            placeholder="Search rules by code, name, or MITRE ATT&CK tactic..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: '100%', paddingLeft: '38px', fontSize: '0.85rem' }}
          />
        </div>
        <div style={{ fontSize: '0.8rem', color: '#94A3B8' }}>
          Total Active Rules: <span style={{ color: '#00F2FE', fontWeight: 800 }}>{rules.filter(r => r.is_active).length} / {rules.length}</span>
        </div>
      </div>

      {/* Rules Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(420px, 1fr))', gap: '1.25rem' }}>
        {filteredRules.map((rule) => (
          <div
            key={rule.id}
            className="glass-card"
            style={{
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              borderTop: `3px solid ${rule.severity === 'CRITICAL' ? '#FF0844' : rule.severity === 'HIGH' ? '#FF6B00' : '#F59E0B'}`
            }}
          >
            <div>
              {/* Top metadata */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: '#00F2FE', background: 'rgba(0, 242, 254, 0.1)', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                    {rule.rule_code}
                  </span>
                  <span className={`badge badge-${rule.severity.toLowerCase()}`}>
                    {rule.severity}
                  </span>
                </div>
                <button
                  onClick={() => onToggleRule(rule.id)}
                  style={{ background: 'transparent', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.35rem', color: rule.is_active ? '#00E676' : '#64748B' }}
                >
                  {rule.is_active ? (
                    <>
                      <ToggleRight style={{ width: '28px', height: '28px', color: '#00E676' }} />
                      <span style={{ fontSize: '0.7rem', fontWeight: 700 }}>ACTIVE</span>
                    </>
                  ) : (
                    <>
                      <ToggleLeft style={{ width: '28px', height: '28px', color: '#64748B' }} />
                      <span style={{ fontSize: '0.7rem', fontWeight: 700 }}>DISABLED</span>
                    </>
                  )}
                </button>
              </div>

              {/* Title & Description */}
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.4rem' }}>
                {rule.name}
              </h3>
              <p style={{ fontSize: '0.8rem', color: '#94A3B8', marginBottom: '0.85rem', lineHeight: '1.4' }}>
                {rule.description}
              </p>

              {/* MITRE Tag */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.75rem', color: '#4FACFE', marginBottom: '0.85rem' }}>
                <Layers style={{ width: '14px', height: '14px' }} />
                <span>{rule.mitre_tactic} ({rule.mitre_technique})</span>
              </div>

              {/* Query syntax box */}
              <div style={{ background: 'rgba(5, 8, 15, 0.8)', padding: '0.6rem 0.8rem', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.05)', fontSize: '0.75rem', fontFamily: 'var(--font-mono)', color: '#A7F3D0', wordBreak: 'break-all' }}>
                <Code style={{ width: '12px', height: '12px', display: 'inline', marginRight: '0.4rem', color: '#00F2FE' }} />
                {rule.condition_query}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Create Rule Modal */}
      {showCreateModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(7, 10, 17, 0.85)', backdropFilter: 'blur(12px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '550px', padding: '1.5rem', border: '1px solid #00F2FE' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '1rem' }}>
              Create Custom SIGMA Detection Rule
            </h3>
            
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              <div>
                <label style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'block', marginBottom: '0.3rem' }}>Rule Name</label>
                <input className="glass-input" style={{ width: '100%' }} value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'block', marginBottom: '0.3rem' }}>MITRE ATT&CK Tactic</label>
                <input className="glass-input" style={{ width: '100%' }} value={newRule.mitre_tactic} onChange={e => setNewRule({...newRule, mitre_tactic: e.target.value})} />
              </div>

              <div>
                <label style={{ fontSize: '0.75rem', color: '#94A3B8', display: 'block', marginBottom: '0.3rem' }}>Detection Logic Expression</label>
                <textarea className="glass-input" style={{ width: '100%', height: '80px', fontFamily: 'var(--font-mono)' }} value={newRule.condition_query} onChange={e => setNewRule({...newRule, condition_query: e.target.value})} />
              </div>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
              <button className="glass-button" onClick={() => setShowCreateModal(false)}>Cancel</button>
              <button className="glass-button glass-button-primary" onClick={() => {
                alert('Rule deployed to detection engine pipeline!');
                setShowCreateModal(false);
              }}>Deploy Rule</button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

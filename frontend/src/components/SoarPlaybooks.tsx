import React, { useState } from 'react';
import { Cpu, Play, CheckCircle2, Clock, AlertCircle, ShieldCheck, Terminal } from 'lucide-react';
import type { PlaybookExecution } from '../types';

interface SoarPlaybooksProps {
  playbooks: PlaybookExecution[];
  onTriggerPlaybook: (playbookName: string, target: string) => void;
}

export const SoarPlaybooks: React.FC<SoarPlaybooksProps> = ({
  playbooks,
  onTriggerPlaybook
}) => {
  const [targetIp, setTargetIp] = useState('10.0.12.44');
  const [selectedPlaybookName, setSelectedPlaybookName] = useState('Automated Host Isolation & Memory Dump');
  const [activeExec, setActiveExec] = useState<PlaybookExecution>(playbooks[0]);

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Cpu style={{ width: '22px', height: '22px', color: '#A855F7' }} />
            SOAR Automated Security Orchestration & Response Engine
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Automated threat containment playbooks, agent API integration, and audit execution trails</p>
        </div>
      </div>

      {/* Interactive Trigger Banner */}
      <div className="glass-card" style={{ padding: '1.25rem', borderLeft: '4px solid #A855F7', background: 'linear-gradient(135deg, rgba(168, 85, 247, 0.1), rgba(0, 242, 254, 0.05))' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.75rem' }}>
          ⚡ Trigger On-Demand Response Playbook
        </h3>
        
        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr auto', gap: '1rem', alignItems: 'center' }}>
          <div>
            <label style={{ fontSize: '0.7rem', color: '#94A3B8', display: 'block', marginBottom: '0.25rem' }}>Select Response Playbook</label>
            <select
              className="glass-input"
              value={selectedPlaybookName}
              onChange={(e) => setSelectedPlaybookName(e.target.value)}
              style={{ width: '100%', fontSize: '0.85rem' }}
            >
              <option value="Automated Host Isolation & Memory Dump" style={{ background: '#0B0F19' }}>
                Automated Host Isolation & Memory Dump
              </option>
              <option value="Firewall IP Blacklist & Threat Feed Push" style={{ background: '#0B0F19' }}>
                Firewall IP Blacklist & Threat Feed Push
              </option>
              <option value="Revoke Compromised Azure User Credentials" style={{ background: '#0B0F19' }}>
                Revoke Compromised Azure User Credentials
              </option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.7rem', color: '#94A3B8', display: 'block', marginBottom: '0.25rem' }}>Target Host IP / User Identity</label>
            <input
              type="text"
              className="glass-input"
              value={targetIp}
              onChange={(e) => setTargetIp(e.target.value)}
              style={{ width: '100%', fontSize: '0.85rem', fontFamily: 'var(--font-mono)' }}
            />
          </div>

          <button
            className="glass-button glass-button-primary"
            style={{ height: '42px', marginTop: '1rem' }}
            onClick={() => onTriggerPlaybook(selectedPlaybookName, targetIp)}
          >
            <Play style={{ width: '16px', height: '16px' }} /> Run Response Playbook
          </button>
        </div>
      </div>

      {/* Execution Logs List & Detail Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.25rem' }}>
        
        {/* Left History */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          <h4 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#94A3B8' }}>Execution Audit Log History</h4>
          {playbooks.map((pb) => (
            <div
              key={pb.id}
              className="glass-card"
              onClick={() => setActiveExec(pb)}
              style={{
                padding: '1rem',
                cursor: 'pointer',
                background: activeExec?.id === pb.id ? 'rgba(168, 85, 247, 0.12)' : 'var(--bg-card)',
                borderColor: activeExec?.id === pb.id ? '#A855F7' : 'rgba(255,255,255,0.08)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.35rem' }}>
                <span style={{ fontSize: '0.7rem', color: '#A855F7', fontWeight: 800 }}>{pb.id}</span>
                <span style={{ fontSize: '0.65rem', background: 'rgba(0, 230, 118, 0.15)', color: '#00E676', padding: '0.15rem 0.4rem', borderRadius: '4px', fontWeight: 700 }}>
                  {pb.status}
                </span>
              </div>
              <h5 style={{ fontSize: '0.9rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.25rem' }}>
                {pb.playbook_name}
              </h5>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
                Trigger: {pb.triggered_by}
              </div>
            </div>
          ))}
        </div>

        {/* Right Execution Step Breakdown */}
        {activeExec ? (
          <div className="glass-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', color: '#A855F7', fontFamily: 'var(--font-mono)', fontWeight: 800 }}>
                  EXECUTION TRAIL: {activeExec.id}
                </span>
                <span style={{ fontSize: '0.75rem', color: '#00E676', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <ShieldCheck style={{ width: '14px', height: '14px' }} /> 100% STEPS SUCCEEDED
                </span>
              </div>
              <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#F1F5F9' }}>
                {activeExec.playbook_name}
              </h3>
            </div>

            {/* Steps Workflow List */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
              {activeExec.steps.map((step) => (
                <div
                  key={step.id}
                  style={{
                    background: 'rgba(15, 23, 42, 0.7)',
                    padding: '1rem',
                    borderRadius: '8px',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '1rem'
                  }}
                >
                  <div style={{ width: '28px', height: '28px', borderRadius: '50%', background: 'rgba(0, 230, 118, 0.15)', color: '#00E676', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: '0.8rem' }}>
                    {step.step_number}
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.25rem' }}>
                      <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F1F5F9' }}>
                        {step.action_type}
                      </span>
                      <span style={{ fontSize: '0.7rem', color: '#00F2FE', fontFamily: 'var(--font-mono)' }}>
                        Target: {step.target}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.8rem', color: '#A7F3D0', fontFamily: 'var(--font-mono)', background: 'rgba(5, 8, 15, 0.6)', padding: '0.5rem', borderRadius: '4px', marginTop: '0.4rem' }}>
                      {step.output}
                    </div>
                  </div>
                </div>
              ))}
            </div>

          </div>
        ) : null}

      </div>

    </div>
  );
};

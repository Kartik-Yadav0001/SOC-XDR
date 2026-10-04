import React, { useState } from 'react';
import { Briefcase, ShieldAlert, CheckCircle, Clock, Plus, Server, User, MessageSquare, ChevronRight } from 'lucide-react';
import type { IncidentCase, IncidentStatus } from '../types';

interface IncidentManagerProps {
  incidents: IncidentCase[];
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
  onAddNote: (incidentId: string, noteText: string) => void;
}

export const IncidentManager: React.FC<IncidentManagerProps> = ({
  incidents,
  onUpdateStatus,
  onAddNote
}) => {
  const [selectedIncident, setSelectedIncident] = useState<IncidentCase>(incidents[0]);
  const [newNote, setNewNote] = useState('');

  const statusSteps: IncidentStatus[] = ['NEW', 'INVESTIGATING', 'CONTAINED', 'REMEDIATED', 'CLOSED'];

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Briefcase style={{ width: '22px', height: '22px', color: '#FF6B00' }} />
            Enterprise Incident Case Management
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Autonomous correlation case state machine, forensic timeline, and containment workflow</p>
        </div>
      </div>

      {/* Case Grid Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '1.25rem' }}>
        
        {/* Left Case Selector */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {incidents.map((inc) => (
            <div
              key={inc.id}
              className="glass-card"
              onClick={() => setSelectedIncident(inc)}
              style={{
                padding: '1.25rem',
                cursor: 'pointer',
                borderLeft: '4px solid #FF6B00',
                background: selectedIncident?.id === inc.id ? 'rgba(255, 107, 0, 0.08)' : 'var(--bg-card)',
                borderColor: selectedIncident?.id === inc.id ? '#FF6B00' : 'rgba(255,255,255,0.08)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.75rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: '#FF9E00' }}>
                  {inc.incident_number}
                </span>
                <span className="badge badge-critical">{inc.severity}</span>
              </div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.4rem' }}>
                {inc.title}
              </h4>
              <div style={{ fontSize: '0.75rem', color: '#94A3B8' }}>
                Status: <span style={{ color: '#00F2FE', fontWeight: 700 }}>{inc.status}</span>
              </div>
            </div>
          ))}
        </div>

        {/* Right Active Incident Case Detail */}
        {selectedIncident ? (
          <div className="glass-card" style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            
            {/* Top Case Details */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                <span style={{ fontSize: '0.85rem', fontFamily: 'var(--font-mono)', fontWeight: 800, color: '#FF9E00' }}>
                  {selectedIncident.incident_number}
                </span>
                <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Assigned: <strong style={{ color: '#F1F5F9' }}>{selectedIncident.assigned_to || 'Unassigned'}</strong></span>
              </div>
              <h3 style={{ fontSize: '1.25rem', fontWeight: 800, color: '#F1F5F9', marginBottom: '0.5rem' }}>
                {selectedIncident.title}
              </h3>
              <p style={{ fontSize: '0.85rem', color: '#94A3B8', lineHeight: '1.5' }}>
                {selectedIncident.description}
              </p>
            </div>

            {/* Lifecycle State Machine Progression */}
            <div style={{ background: 'rgba(15, 23, 42, 0.7)', padding: '1rem', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <div style={{ fontSize: '0.75rem', color: '#64748B', fontWeight: 800, marginBottom: '0.75rem', textTransform: 'uppercase' }}>
                Incident Lifecycle State Machine
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                {statusSteps.map((step, idx) => {
                  const isCurrent = selectedIncident.status === step;
                  const isPast = statusSteps.indexOf(selectedIncident.status) > idx;
                  return (
                    <React.Fragment key={step}>
                      <button
                        onClick={() => onUpdateStatus(selectedIncident.id, step)}
                        style={{
                          padding: '0.4rem 0.75rem',
                          borderRadius: '6px',
                          border: isCurrent ? '1px solid #00F2FE' : 'none',
                          background: isCurrent ? 'linear-gradient(135deg, #00F2FE, #4FACFE)' : isPast ? 'rgba(0, 230, 118, 0.2)' : 'rgba(255,255,255,0.05)',
                          color: isCurrent ? '#070A11' : isPast ? '#00E676' : '#64748B',
                          fontWeight: isCurrent ? 800 : 600,
                          fontSize: '0.75rem',
                          cursor: 'pointer',
                          transition: 'all 0.2s'
                        }}
                      >
                        {step}
                      </button>
                      {idx < statusSteps.length - 1 && (
                        <ChevronRight style={{ width: '14px', height: '14px', color: '#64748B' }} />
                      )}
                    </React.Fragment>
                  );
                })}
              </div>
            </div>

            {/* Affected Assets Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
                  <Server style={{ width: '14px', height: '14px', color: '#00F2FE' }} /> Affected Host Assets
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {selectedIncident.affected_hosts.map(h => (
                    <span key={h} style={{ fontSize: '0.75rem', background: 'rgba(0, 242, 254, 0.1)', color: '#00F2FE', padding: '0.2rem 0.5rem', borderRadius: '4px', fontFamily: 'var(--font-mono)' }}>
                      {h}
                    </span>
                  ))}
                </div>
              </div>

              <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '1rem', borderRadius: '8px' }}>
                <div style={{ fontSize: '0.75rem', color: '#94A3B8', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '0.4rem', marginBottom: '0.5rem' }}>
                  <User style={{ width: '14px', height: '14px', color: '#A855F7' }} /> Affected Identity Users
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                  {selectedIncident.affected_users.map(u => (
                    <span key={u} style={{ fontSize: '0.75rem', background: 'rgba(168, 85, 247, 0.1)', color: '#C084FC', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                      {u}
                    </span>
                  ))}
                </div>
              </div>
            </div>

            {/* Incident Forensic Timeline */}
            <div>
              <h4 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Clock style={{ width: '16px', height: '16px', color: '#00F2FE' }} /> Forensic Activity Timeline
              </h4>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem', paddingLeft: '1rem', borderLeft: '2px solid rgba(0, 242, 254, 0.3)' }}>
                {selectedIncident.timeline.map((evt) => (
                  <div key={evt.id} style={{ position: 'relative' }}>
                    <div style={{ fontSize: '0.7rem', color: '#64748B', fontFamily: 'var(--font-mono)' }}>
                      {new Date(evt.timestamp).toLocaleTimeString()} • <span style={{ color: '#00F2FE', fontWeight: 700 }}>{evt.actor}</span>
                    </div>
                    <div style={{ fontSize: '0.85rem', color: '#F1F5F9', fontWeight: 600 }}>
                      {evt.action}
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Note Form */}
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1.25rem' }}>
                <input
                  type="text"
                  className="glass-input"
                  placeholder="Add investigation update note or forensic observation..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  style={{ flex: 1, fontSize: '0.85rem' }}
                />
                <button
                  className="glass-button glass-button-primary"
                  onClick={() => {
                    if (newNote.trim()) {
                      onAddNote(selectedIncident.id, newNote);
                      setNewNote('');
                    }
                  }}
                >
                  <Plus style={{ width: '14px', height: '14px' }} /> Add Timeline Note
                </button>
              </div>
            </div>

          </div>
        ) : null}

      </div>

    </div>
  );
};

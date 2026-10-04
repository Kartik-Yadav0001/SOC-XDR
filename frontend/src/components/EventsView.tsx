import React, { useState } from 'react';
import { Activity, Filter, Eye, Code, Terminal, Search, ArrowRight } from 'lucide-react';
import type { SecurityEvent, Severity } from '../types';

interface EventsViewProps {
  events: SecurityEvent[];
}

export const EventsView: React.FC<EventsViewProps> = ({ events }) => {
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredEvents = events.filter((evt) => {
    const matchesSev = severityFilter === 'ALL' || evt.severity === severityFilter;
    const matchesSearch = 
      evt.event_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.source_ip.includes(searchTerm) ||
      (evt.user && evt.user.toLowerCase().includes(searchTerm.toLowerCase()));
    return matchesSev && matchesSearch;
  });

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Title Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Activity style={{ width: '22px', height: '22px', color: '#00F2FE' }} />
            Real-Time Telemetry Ingestion Stream
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>High-throughput normalized security log records from endpoint agents, network sensors, and cloud audit logs</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'rgba(0, 242, 254, 0.1)', padding: '0.4rem 0.8rem', borderRadius: '8px', border: '1px solid rgba(0, 242, 254, 0.3)' }}>
          <div className="live-dot" />
          <span style={{ fontSize: '0.75rem', fontWeight: 700, color: '#00F2FE' }}>INGESTING @ 1.42k EPS</span>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="glass-card" style={{ padding: '1rem', display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '240px' }}>
          <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '16px', height: '16px', color: '#64748B' }} />
          <input
            type="text"
            className="glass-input"
            placeholder="Filter by event type, IP, user, or agent source..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: '100%', paddingLeft: '38px', fontSize: '0.85rem' }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Filter style={{ width: '16px', height: '16px', color: '#94A3B8' }} />
          <span style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              style={{
                padding: '0.35rem 0.65rem',
                borderRadius: '6px',
                border: 'none',
                background: severityFilter === sev ? 'linear-gradient(135deg, #00F2FE, #4FACFE)' : 'rgba(15, 23, 42, 0.6)',
                color: severityFilter === sev ? '#070A11' : '#94A3B8',
                fontWeight: severityFilter === sev ? 800 : 500,
                fontSize: '0.75rem',
                cursor: 'pointer'
              }}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Events Table */}
      <div className="glass-card" style={{ padding: '1rem' }}>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#64748B', fontSize: '0.75rem' }}>
                <th style={{ padding: '0.75rem' }}>TIMESTAMP</th>
                <th style={{ padding: '0.75rem' }}>SEVERITY</th>
                <th style={{ padding: '0.75rem' }}>EVENT TYPE</th>
                <th style={{ padding: '0.75rem' }}>SENSOR / SOURCE</th>
                <th style={{ padding: '0.75rem' }}>FLOW (SRC → DST)</th>
                <th style={{ padding: '0.75rem' }}>USER</th>
                <th style={{ padding: '0.75rem', textAlign: 'right' }}>RAW DATA</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((evt) => (
                <tr key={evt.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)', transition: 'background 0.2s' }}>
                  <td style={{ padding: '0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: '#94A3B8' }}>
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </td>
                  <td style={{ padding: '0.75rem' }}>
                    <span className={`badge badge-${evt.severity.toLowerCase()}`}>
                      {evt.severity}
                    </span>
                  </td>
                  <td style={{ padding: '0.75rem', fontWeight: 700, color: '#F1F5F9' }}>
                    {evt.event_type}
                  </td>
                  <td style={{ padding: '0.75rem', color: '#00F2FE' }}>
                    {evt.source}
                  </td>
                  <td style={{ padding: '0.75rem', fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: '#94A3B8' }}>
                    {evt.source_ip} <ArrowRight style={{ width: '12px', height: '12px', display: 'inline', margin: '0 0.2rem' }} /> {evt.destination_ip}
                  </td>
                  <td style={{ padding: '0.75rem', color: '#E2E8F0' }}>
                    {evt.user || 'N/A'}
                  </td>
                  <td style={{ padding: '0.75rem', textAlign: 'right' }}>
                    <button
                      className="glass-button"
                      style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                      onClick={() => setSelectedEvent(evt)}
                    >
                      <Code style={{ width: '12px', height: '12px' }} /> Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Inspector Modal */}
      {selectedEvent && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          background: 'rgba(7, 10, 17, 0.85)',
          backdropFilter: 'blur(12px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '650px', maxWidth: '90vw', padding: '1.5rem', border: '1px solid #00F2FE' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.1)', paddingBottom: '0.75rem' }}>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <Terminal style={{ width: '18px', height: '18px', color: '#00F2FE' }} />
                Normalized Event Payload [{selectedEvent.id}]
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{ background: 'transparent', border: 'none', color: '#94A3B8', fontSize: '1.2rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            <div className="code-block" style={{ maxHeight: '380px' }}>
              <pre>{JSON.stringify(selectedEvent, null, 2)}</pre>
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
              <button className="glass-button" onClick={() => setSelectedEvent(null)}>
                Close Viewer
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

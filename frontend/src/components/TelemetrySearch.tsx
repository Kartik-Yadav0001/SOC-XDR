import React, { useState } from 'react';
import { Search, Filter, Terminal, ArrowRight, Zap, Database } from 'lucide-react';
import type { SecurityEvent } from '../types';

interface TelemetrySearchProps {
  events: SecurityEvent[];
}

export const TelemetrySearch: React.FC<TelemetrySearchProps> = ({ events }) => {
  const [query, setQuery] = useState('severity:CRITICAL');

  const filteredEvents = events.filter(e => {
    if (!query) return true;
    const lowerQuery = query.toLowerCase();
    if (lowerQuery.startsWith('severity:')) {
      const targetSev = lowerQuery.split(':')[1].toUpperCase();
      return e.severity === targetSev;
    }
    return (
      e.event_type.toLowerCase().includes(lowerQuery) ||
      e.source_ip.includes(lowerQuery) ||
      e.source.toLowerCase().includes(lowerQuery)
    );
  });

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Search style={{ width: '22px', height: '22px', color: '#00F2FE' }} />
            SIEM Telemetry Search & Facet Aggregation Engine
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Sub-second indexing search across multi-tenant security log lake</p>
        </div>
      </div>

      {/* Query Bar */}
      <div className="glass-card" style={{ padding: '1.25rem', border: '1px solid rgba(0, 242, 254, 0.4)' }}>
        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Terminal style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', width: '18px', height: '18px', color: '#00F2FE' }} />
            <input
              type="text"
              className="glass-input"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder='Enter SIEM search query... e.g. severity:CRITICAL source_ip:10.0.12.44 user:"j.doe"'
              style={{ width: '100%', paddingLeft: '44px', fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: '#A7F3D0' }}
            />
          </div>
          <button className="glass-button glass-button-primary">
            <Zap style={{ width: '16px', height: '16px' }} /> Execute Search
          </button>
        </div>

        {/* Quick Query Chips */}
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.85rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: '0.7rem', color: '#64748B', fontWeight: 700 }}>Quick Queries:</span>
          {['severity:CRITICAL', 'event_type:POWERSHELL', 'source_ip:192.168.1.105', 'user:admin_exec'].map(chip => (
            <button
              key={chip}
              onClick={() => setQuery(chip)}
              style={{
                fontSize: '0.7rem',
                fontFamily: 'var(--font-mono)',
                background: 'rgba(0, 242, 254, 0.1)',
                color: '#00F2FE',
                border: '1px solid rgba(0, 242, 254, 0.3)',
                padding: '0.2rem 0.5rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              {chip}
            </button>
          ))}
        </div>
      </div>

      {/* Result Metrics */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: '#94A3B8' }}>
        <div>
          Matched <strong style={{ color: '#F1F5F9' }}>{filteredEvents.length}</strong> events in <span style={{ color: '#00E676', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>14ms</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
          <Database style={{ width: '14px', height: '14px', color: '#00F2FE' }} /> Indexed 1,420,000 logs
        </div>
      </div>

      {/* Main Results Split */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr', gap: '1.25rem' }}>
        
        {/* Facet Sidebar */}
        <div className="glass-card" style={{ padding: '1rem', display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <h4 style={{ fontSize: '0.8rem', color: '#64748B', fontWeight: 800, textTransform: 'uppercase', marginBottom: '0.5rem' }}>
              Top Source IPs
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem', fontFamily: 'var(--font-mono)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#A7F3D0' }}>
                <span>10.0.12.44</span> <span>(42)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#A7F3D0' }}>
                <span>10.0.2.20</span> <span>(28)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#A7F3D0' }}>
                <span>192.168.1.105</span> <span>(14)</span>
              </div>
            </div>
          </div>

          <div>
            <h4 style={{ fontSize: '0.8rem', color: '#64748B', fontWeight: 800, textTransform: 'uppercase', marginBottom: '0.5rem' }}>
              Event Types
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.75rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#F1F5F9' }}>
                <span>AUTH_FAILED_BURST</span> <span>(19)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#F1F5F9' }}>
                <span>POWERSHELL_ENCODED</span> <span>(12)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#F1F5F9' }}>
                <span>LSASS_MEMORY_DUMP</span> <span>(8)</span>
              </div>
            </div>
          </div>
        </div>

        {/* Results Table */}
        <div className="glass-card" style={{ padding: '1rem' }}>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.1)', color: '#64748B', fontSize: '0.75rem' }}>
                  <th style={{ padding: '0.75rem' }}>TIMESTAMP</th>
                  <th style={{ padding: '0.75rem' }}>SEVERITY</th>
                  <th style={{ padding: '0.75rem' }}>EVENT TYPE</th>
                  <th style={{ padding: '0.75rem' }}>SOURCE IP</th>
                  <th style={{ padding: '0.75rem' }}>TARGET IP</th>
                  <th style={{ padding: '0.75rem' }}>USER</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((evt) => (
                  <tr key={evt.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.05)' }}>
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
                    <td style={{ padding: '0.75rem', fontFamily: 'var(--font-mono)', color: '#00F2FE' }}>
                      {evt.source_ip}
                    </td>
                    <td style={{ padding: '0.75rem', fontFamily: 'var(--font-mono)', color: '#94A3B8' }}>
                      {evt.destination_ip}
                    </td>
                    <td style={{ padding: '0.75rem', color: '#E2E8F0' }}>
                      {evt.user || 'N/A'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

      </div>

    </div>
  );
};

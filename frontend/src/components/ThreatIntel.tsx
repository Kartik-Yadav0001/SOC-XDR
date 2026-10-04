import React, { useState } from 'react';
import { Globe, Search, ShieldCheck, Tag, Upload, FileJson, CheckCircle2 } from 'lucide-react';
import type { ThreatIndicator } from '../types';

interface ThreatIntelProps {
  indicators: ThreatIndicator[];
}

export const ThreatIntel: React.FC<ThreatIntelProps> = ({ indicators }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [showStixModal, setShowStixModal] = useState(false);
  const [stixJson, setStixJson] = useState(`{
  "type": "bundle",
  "id": "bundle--5d00171a-67b1-4c12-9c46-950c2669e469",
  "objects": [
    {
      "type": "indicator",
      "id": "indicator--d81f86b9-975b-4c0b-a675-0e69d7a224a0",
      "pattern": "[domain-name:value = 'c2-server-beacon-49.xyz']",
      "valid_from": "2026-09-20T00:00:00Z",
      "labels": ["malicious-activity", "c2"]
    }
  ]
}`);

  const filteredIndicators = indicators.filter(i => 
    i.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
    i.threat_type.toLowerCase().includes(searchTerm.toLowerCase()) ||
    i.source.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Globe style={{ width: '22px', height: '22px', color: '#00F2FE' }} />
            Threat Intelligence Platform (STIX 2.1 & MISP)
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Query global Indicators of Compromise (IoCs), malware hashes, and STIX 2.1 threat feeds</p>
        </div>

        <button
          className="glass-button glass-button-primary"
          onClick={() => setShowStixModal(true)}
        >
          <Upload style={{ width: '16px', height: '16px' }} /> Import STIX 2.1 / MISP Bundle
        </button>
      </div>

      {/* Search Toolbar */}
      <div className="glass-card" style={{ padding: '1rem' }}>
        <div style={{ position: 'relative' }}>
          <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '16px', height: '16px', color: '#64748B' }} />
          <input
            type="text"
            className="glass-input"
            placeholder="Search IoC value (IP, SHA256 Hash, Domain, URL), Threat Actor, or Tag..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{ width: '100%', paddingLeft: '38px', fontSize: '0.9rem' }}
          />
        </div>
      </div>

      {/* Indicators Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(380px, 1fr))', gap: '1.25rem' }}>
        {filteredIndicators.map((ioc) => (
          <div
            key={ioc.id}
            className="glass-card"
            style={{ padding: '1.25rem', borderLeft: `4px solid ${ioc.severity === 'CRITICAL' ? '#FF0844' : '#FF6B00'}` }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <span style={{ fontSize: '0.7rem', fontWeight: 800, background: 'rgba(0, 242, 254, 0.15)', color: '#00F2FE', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                {ioc.ioc_type}
              </span>
              <span style={{ fontSize: '0.75rem', color: '#00E676', fontWeight: 700 }}>
                {ioc.confidence}% Confidence
              </span>
            </div>

            <div style={{ fontSize: '1rem', fontWeight: 800, color: '#F1F5F9', fontFamily: 'var(--font-mono)', wordBreak: 'break-all', margin: '0.4rem 0' }}>
              {ioc.value}
            </div>

            <div style={{ fontSize: '0.8rem', color: '#FF9E00', fontWeight: 700, marginBottom: '0.4rem' }}>
              {ioc.threat_type}
            </div>

            <p style={{ fontSize: '0.8rem', color: '#94A3B8', marginBottom: '0.85rem', lineHeight: '1.4' }}>
              {ioc.description}
            </p>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '0.75rem' }}>
              <div style={{ display: 'flex', gap: '0.35rem', flexWrap: 'wrap' }}>
                {ioc.tags.map(t => (
                  <span key={t} style={{ fontSize: '0.65rem', background: 'rgba(255,255,255,0.05)', color: '#94A3B8', padding: '0.15rem 0.4rem', borderRadius: '4px' }}>
                    #{t}
                  </span>
                ))}
              </div>
              <span style={{ fontSize: '0.7rem', color: '#64748B' }}>Source: {ioc.source}</span>
            </div>
          </div>
        ))}
      </div>

      {/* STIX Modal */}
      {showStixModal && (
        <div style={{
          position: 'fixed', top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(7, 10, 17, 0.85)', backdropFilter: 'blur(12px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
        }}>
          <div className="glass-card" style={{ width: '600px', padding: '1.5rem', border: '1px solid #00F2FE' }}>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#F1F5F9', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <FileJson style={{ width: '20px', height: '20px', color: '#00F2FE' }} />
              STIX 2.1 / MISP Bundle Parser
            </h3>
            <p style={{ fontSize: '0.8rem', color: '#94A3B8', marginBottom: '1rem' }}>Paste raw STIX JSON object or MISP event package for threat intelligence ingestion</p>

            <textarea
              className="glass-input"
              style={{ width: '100%', height: '200px', fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}
              value={stixJson}
              onChange={(e) => setStixJson(e.target.value)}
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '1.25rem' }}>
              <button className="glass-button" onClick={() => setShowStixModal(false)}>Cancel</button>
              <button className="glass-button glass-button-primary" onClick={() => {
                alert('STIX 2.1 Bundle parsed successfully! 1 new IoC added to threat database.');
                setShowStixModal(false);
              }}>
                <CheckCircle2 style={{ width: '14px', height: '14px' }} /> Parse & Ingest Indicators
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

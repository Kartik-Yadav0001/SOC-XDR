import React from 'react';
import { HeartPulse, HardDrive, Cpu, Radio, CheckCircle2, Activity, Zap } from 'lucide-react';
import type { SystemHealthStatus } from '../types';

interface SystemHealthProps {
  health: SystemHealthStatus;
}

export const SystemHealth: React.FC<SystemHealthProps> = ({ health }) => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <HeartPulse style={{ width: '22px', height: '22px', color: '#00E676' }} />
            System Pipeline Diagnostics & Infrastructure Health
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Real-time telemetry ingestion pipeline health, database connections, and worker stats</p>
        </div>
        <span style={{ fontSize: '0.75rem', background: 'rgba(0, 230, 118, 0.15)', color: '#00E676', border: '1px solid rgba(0, 230, 118, 0.4)', padding: '0.35rem 0.75rem', borderRadius: '20px', fontWeight: 800 }}>
          STATUS: {health.status}
        </span>
      </div>

      {/* Grid of System Subservices */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1.25rem' }}>
        
        {/* Database Status */}
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F1F5F9' }}>PostgreSQL / SQLite ORM</span>
            <HardDrive style={{ width: '18px', height: '18px', color: '#00F2FE' }} />
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#00E676' }}>
            {health.database}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
            Connection Pool: 20 active connections
          </div>
        </div>

        {/* Redis Cache */}
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F1F5F9' }}>Redis In-Memory Cache</span>
            <Zap style={{ width: '18px', height: '18px', color: '#F59E0B' }} />
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#00E676' }}>
            {health.redis_cache}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
            Sub-millisecond alert caching
          </div>
        </div>

        {/* Detection Engine */}
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F1F5F9' }}>Autonomous Detection Engine</span>
            <Activity style={{ width: '18px', height: '18px', color: '#FF0844' }} />
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#00E676' }}>
            {health.detection_engine}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
            Evaluating 104 active SIGMA rules
          </div>
        </div>

        {/* WebSockets */}
        <div className="glass-card" style={{ padding: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '0.85rem', fontWeight: 700, color: '#F1F5F9' }}>WebSocket Event Stream</span>
            <Radio style={{ width: '18px', height: '18px', color: '#A855F7' }} />
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: '#A855F7' }}>
            {health.active_websockets} Active Channels
          </div>
          <div style={{ fontSize: '0.75rem', color: '#94A3B8', marginTop: '0.35rem' }}>
            Real-time broadcast enabled
          </div>
        </div>

      </div>

      {/* Metrics Gauges */}
      <div className="glass-card" style={{ padding: '1.5rem', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem' }}>
        <div>
          <div style={{ fontSize: '0.8rem', color: '#94A3B8', fontWeight: 700, marginBottom: '0.4rem' }}>CPU UTILIZATION</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#00F2FE' }}>{health.cpu_usage_pct}%</div>
            <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{ width: `${health.cpu_usage_pct}%`, height: '100%', background: '#00F2FE' }} />
            </div>
          </div>
        </div>

        <div>
          <div style={{ fontSize: '0.8rem', color: '#94A3B8', fontWeight: 700, marginBottom: '0.4rem' }}>RAM MEMORY UTILIZATION</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div style={{ fontSize: '1.8rem', fontWeight: 900, color: '#A855F7' }}>{health.memory_usage_pct}%</div>
            <div style={{ flex: 1, height: '8px', background: 'rgba(255,255,255,0.1)', borderRadius: '4px', overflow: 'hidden' }}>
              <div style={{ width: `${health.memory_usage_pct}%`, height: '100%', background: '#A855F7' }} />
            </div>
          </div>
        </div>
      </div>

    </div>
  );
};

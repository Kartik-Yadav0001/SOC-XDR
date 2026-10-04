import React from 'react';
import { Building2, Shield, Layers, Users, CheckCircle2, HardDrive } from 'lucide-react';
import type { TenantWorkspace } from '../types';

interface TenantManagerProps {
  tenants: TenantWorkspace[];
  currentTenant: TenantWorkspace;
  onSelectTenant: (t: TenantWorkspace) => void;
}

export const TenantManager: React.FC<TenantManagerProps> = ({
  tenants,
  currentTenant,
  onSelectTenant
}) => {
  return (
    <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h2 style={{ fontSize: '1.3rem', fontWeight: 800, color: '#F1F5F9', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Building2 style={{ width: '22px', height: '22px', color: '#00F2FE' }} />
            Multi-Tenant Workspace & Data Isolation
          </h2>
          <p style={{ fontSize: '0.8rem', color: '#94A3B8' }}>Granular workspace tenant isolation, agent deployment scopes, and retention policies</p>
        </div>
      </div>

      {/* Tenant Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: '1.25rem' }}>
        {tenants.map((t) => {
          const isSelected = t.id === currentTenant.id;
          return (
            <div
              key={t.id}
              className="glass-card"
              style={{
                padding: '1.25rem',
                border: isSelected ? '2px solid #00F2FE' : '1px solid rgba(255,255,255,0.08)',
                background: isSelected ? 'rgba(0, 242, 254, 0.08)' : 'var(--bg-card)'
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
                <span style={{ fontSize: '0.7rem', fontWeight: 800, background: 'rgba(0, 242, 254, 0.15)', color: '#00F2FE', padding: '0.2rem 0.5rem', borderRadius: '4px' }}>
                  {t.subscription_tier} TIER
                </span>
                {isSelected && (
                  <span style={{ fontSize: '0.75rem', color: '#00E676', fontWeight: 800, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                    <CheckCircle2 style={{ width: '14px', height: '14px' }} /> ACTIVE WORKSPACE
                  </span>
                )}
              </div>

              <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: '#F1F5F9', marginBottom: '0.25rem' }}>
                {t.name}
              </h3>
              <p style={{ fontSize: '0.8rem', color: '#64748B', fontFamily: 'var(--font-mono)', marginBottom: '1rem' }}>
                slug: {t.slug}
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', fontSize: '0.8rem', marginBottom: '1.25rem' }}>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '0.6rem', borderRadius: '6px' }}>
                  <span style={{ fontSize: '0.65rem', color: '#64748B', display: 'block' }}>ACTIVE AGENTS</span>
                  <strong style={{ color: '#00F2FE', fontSize: '1.1rem' }}>{t.active_agents_count}</strong>
                </div>
                <div style={{ background: 'rgba(15, 23, 42, 0.6)', padding: '0.6rem', borderRadius: '6px' }}>
                  <span style={{ fontSize: '0.65rem', color: '#64748B', display: 'block' }}>RETENTION</span>
                  <strong style={{ color: '#F1F5F9', fontSize: '1.1rem' }}>{t.event_retention_days} Days</strong>
                </div>
              </div>

              <button
                className={`glass-button ${isSelected ? 'glass-button-primary' : ''}`}
                style={{ width: '100%', justifyContent: 'center' }}
                onClick={() => onSelectTenant(t)}
              >
                {isSelected ? 'Currently Loaded' : 'Switch Workspace'}
              </button>
            </div>
          );
        })}
      </div>

    </div>
  );
};

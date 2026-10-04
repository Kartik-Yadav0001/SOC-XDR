import React, { useState, useEffect } from 'react';
import { Shield, Radio, Search, Bell, User, Layers, RefreshCw } from 'lucide-react';
import type { TenantWorkspace } from '../types';

interface HeaderProps {
  tenants: TenantWorkspace[];
  currentTenant: TenantWorkspace;
  onTenantChange: (tenant: TenantWorkspace) => void;
  onRefresh: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  tenants,
  currentTenant,
  onTenantChange,
  onRefresh
}) => {
  const [time, setTime] = useState(new Date().toLocaleTimeString());

  useEffect(() => {
    const timer = setInterval(() => setTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(timer);
  }, []);

  return (
    <header className="glass-panel" style={{
      height: '70px',
      padding: '0 1.5rem',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      borderBottom: '1px solid rgba(255, 255, 255, 0.08)'
    }}>
      {/* Brand & Logo */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <div style={{
          background: 'linear-gradient(135deg, #00F2FE, #4FACFE)',
          padding: '0.6rem',
          borderRadius: '10px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          boxShadow: '0 0 16px rgba(0, 242, 254, 0.4)'
        }}>
          <Shield style={{ width: '24px', height: '24px', color: '#070A11' }} />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.25rem', fontWeight: 800, letterSpacing: '-0.02em', background: 'linear-gradient(to right, #00F2FE, #FFFFFF)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              SENTINEL<span style={{ color: '#00F2FE', WebkitTextFillColor: '#00F2FE' }}>X</span>
            </span>
            <span style={{ fontSize: '0.65rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(0, 242, 254, 0.15)', color: '#00F2FE', border: '1px solid rgba(0, 242, 254, 0.3)', fontWeight: 700 }}>
              v2.4 SOC/XDR
            </span>
          </div>
          <p style={{ fontSize: '0.75rem', color: '#94A3B8' }}>Autonomous Cyber Defense Platform</p>
        </div>
      </div>

      {/* Center Actions / Global Search */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flex: 1, maxWidth: '500px', margin: '0 2rem' }}>
        <div style={{ position: 'relative', width: '100%' }}>
          <Search style={{ position: 'absolute', left: '12px', top: '50%', transform: 'translateY(-50%)', width: '16px', height: '16px', color: '#64748B' }} />
          <input
            type="text"
            className="glass-input"
            placeholder="Search IoC, IP, Hash, User, Alert ID across workspace..."
            style={{ width: '100%', paddingLeft: '38px', fontSize: '0.85rem' }}
          />
        </div>
      </div>

      {/* Right Quick Controls */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem' }}>
        {/* Live WS Pulse */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.4rem 0.8rem',
          borderRadius: '20px',
          background: 'rgba(0, 230, 118, 0.1)',
          border: '1px solid rgba(0, 230, 118, 0.3)'
        }}>
          <div className="live-dot" />
          <Radio style={{ width: '14px', height: '14px', color: '#00E676' }} />
          <span style={{ fontSize: '0.75rem', color: '#00E676', fontWeight: 600 }}>LIVE WEBSOCKET</span>
        </div>

        {/* Tenant Selector */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'rgba(15, 23, 42, 0.6)', padding: '0.4rem 0.75rem', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.1)' }}>
          <Layers style={{ width: '14px', height: '14px', color: '#00F2FE' }} />
          <select
            value={currentTenant.id}
            onChange={(e) => {
              const selected = tenants.find(t => t.id === e.target.value);
              if (selected) onTenantChange(selected);
            }}
            style={{
              background: 'transparent',
              color: '#F1F5F9',
              border: 'none',
              outline: 'none',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            {tenants.map(t => (
              <option key={t.id} value={t.id} style={{ background: '#0B0F19', color: '#F1F5F9' }}>
                {t.name}
              </option>
            ))}
          </select>
        </div>

        {/* Manual Refresh Button */}
        <button
          onClick={onRefresh}
          className="glass-button"
          style={{ padding: '0.45rem 0.75rem', fontSize: '0.8rem' }}
          title="Refresh Data Feeds"
        >
          <RefreshCw style={{ width: '14px', height: '14px' }} />
        </button>

        {/* System Time */}
        <div style={{ fontSize: '0.8rem', fontFamily: 'var(--font-mono)', color: '#94A3B8' }}>
          {time}
        </div>

        {/* User Profile Badge */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', paddingLeft: '0.5rem', borderLeft: '1px solid rgba(255, 255, 255, 0.1)' }}>
          <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'linear-gradient(135deg, #A855F7, #00F2FE)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#070A11', fontWeight: 800, fontSize: '0.85rem' }}>
            AV
          </div>
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: '#F1F5F9' }}>Alex Vance</div>
            <div style={{ fontSize: '0.65rem', color: '#00F2FE' }}>SUPER ADMIN</div>
          </div>
        </div>
      </div>
    </header>
  );
};

import React from 'react';
import { 
  LayoutDashboard, 
  Activity, 
  ShieldAlert, 
  AlertTriangle, 
  Briefcase, 
  Cpu, 
  Globe, 
  Search, 
  Building2, 
  HeartPulse 
} from 'lucide-react';

export type TabType = 
  | 'dashboard' 
  | 'events' 
  | 'rules' 
  | 'alerts' 
  | 'incidents' 
  | 'soar' 
  | 'intel' 
  | 'telemetry' 
  | 'tenants' 
  | 'health';

interface SidebarProps {
  activeTab: TabType;
  setActiveTab: (tab: TabType) => void;
  activeAlertCount: number;
  openIncidentCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  activeAlertCount,
  openIncidentCount
}) => {
  const menuItems = [
    { id: 'dashboard', label: 'Executive Dashboard', icon: LayoutDashboard },
    { id: 'events', label: 'Real-Time Events', icon: Activity },
    { id: 'rules', label: 'Detection Engine', icon: ShieldAlert },
    { 
      id: 'alerts', 
      label: 'Alert Center', 
      icon: AlertTriangle, 
      badge: activeAlertCount > 0 ? activeAlertCount : undefined,
      badgeColor: '#FF0844' 
    },
    { 
      id: 'incidents', 
      label: 'Incident Manager', 
      icon: Briefcase, 
      badge: openIncidentCount > 0 ? openIncidentCount : undefined,
      badgeColor: '#FF6B00' 
    },
    { id: 'soar', label: 'SOAR Playbooks', icon: Cpu },
    { id: 'intel', label: 'Threat Intel (STIX/MISP)', icon: Globe },
    { id: 'telemetry', label: 'SIEM Search', icon: Search },
    { id: 'tenants', label: 'Multi-Tenant Workspaces', icon: Building2 },
    { id: 'health', label: 'System Health', icon: HeartPulse },
  ];

  return (
    <aside className="glass-panel" style={{
      width: '240px',
      minWidth: '240px',
      minHeight: 'calc(100vh - 70px)',
      padding: '1.25rem 0.75rem',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      borderRight: '1px solid rgba(255, 255, 255, 0.08)'
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
        <div style={{ padding: '0 0.75rem 0.75rem 0.75rem', fontSize: '0.65rem', fontWeight: 800, textTransform: 'uppercase', color: '#64748B', letterSpacing: '0.08em' }}>
          SOC Navigation
        </div>

        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id as TabType)}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                width: '100%',
                padding: '0.7rem 0.85rem',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'linear-gradient(90deg, rgba(0, 242, 254, 0.15), rgba(79, 172, 254, 0.05))' : 'transparent',
                borderLeft: isActive ? '3px solid #00F2FE' : '3px solid transparent',
                color: isActive ? '#00F2FE' : '#94A3B8',
                fontWeight: isActive ? 700 : 500,
                fontSize: '0.85rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                textAlign: 'left'
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <Icon style={{ width: '18px', height: '18px', color: isActive ? '#00F2FE' : '#64748B' }} />
                <span>{item.label}</span>
              </div>
              {item.badge !== undefined && (
                <span style={{
                  background: item.badgeColor || '#00F2FE',
                  color: '#070A11',
                  borderRadius: '12px',
                  padding: '0.15rem 0.45rem',
                  fontSize: '0.7rem',
                  fontWeight: 800
                }}>
                  {item.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Footer Info */}
      <div className="glass-card" style={{ padding: '0.85rem', marginTop: '1rem' }}>
        <div style={{ fontSize: '0.7rem', color: '#94A3B8', fontWeight: 600 }}>Engine Status</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', marginTop: '0.25rem' }}>
          <div className="live-dot" />
          <span style={{ fontSize: '0.75rem', color: '#00E676', fontWeight: 700 }}>AUTONOMOUS PROTECTED</span>
        </div>
      </div>
    </aside>
  );
};

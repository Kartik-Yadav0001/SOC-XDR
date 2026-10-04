import React, { useState, useEffect } from 'react';
import { Header } from './components/Header';
import { Sidebar, type TabType } from './components/Sidebar';
import { Dashboard } from './components/Dashboard';
import { EventsView } from './components/EventsView';
import { DetectionRulesView } from './components/DetectionRulesView';
import { AlertCenter } from './components/AlertCenter';
import { IncidentManager } from './components/IncidentManager';
import { SoarPlaybooks } from './components/SoarPlaybooks';
import { ThreatIntel } from './components/ThreatIntel';
import { TelemetrySearch } from './components/TelemetrySearch';
import { TenantManager } from './components/TenantManager';
import { SystemHealth } from './components/SystemHealth';
import { SentinelApi } from './services/api';
import type { 
  SecurityEvent, 
  DetectionRule, 
  SecurityAlert, 
  IncidentCase, 
  PlaybookExecution, 
  ThreatIndicator, 
  SystemHealthStatus, 
  TenantWorkspace,
  IncidentStatus
} from './types';

export function App() {
  const [activeTab, setActiveTab] = useState<TabType>('dashboard');
  const [tenants, setTenants] = useState<TenantWorkspace[]>([]);
  const [currentTenant, setCurrentTenant] = useState<TenantWorkspace>({
    id: 'tenant-001',
    name: 'Global Finance Corp',
    slug: 'global-finance',
    subscription_tier: 'ENTERPRISE',
    event_retention_days: 90,
    active_agents_count: 450,
    is_active: true
  });

  const [health, setHealth] = useState<SystemHealthStatus>({
    status: 'HEALTHY',
    database: 'CONNECTED',
    redis_cache: 'CONNECTED',
    detection_engine: 'RUNNING',
    ingestion_rate_eps: 1420,
    active_websockets: 8,
    uptime_seconds: 432000,
    cpu_usage_pct: 24.8,
    memory_usage_pct: 42.1
  });

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<IncidentCase[]>([]);
  const [playbooks, setPlaybooks] = useState<PlaybookExecution[]>([]);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);

  const loadData = async () => {
    const [h, evts, r, a, inc, pb, ioc, t] = await Promise.all([
      SentinelApi.getHealth(),
      SentinelApi.getEvents(),
      SentinelApi.getRules(),
      SentinelApi.getAlerts(),
      SentinelApi.getIncidents(),
      SentinelApi.getPlaybooks(),
      SentinelApi.getThreatIntel(),
      SentinelApi.getTenants()
    ]);

    setHealth(h);
    setEvents(evts);
    setRules(r);
    setAlerts(a);
    setIncidents(inc);
    setPlaybooks(pb);
    setIndicators(ioc);
    setTenants(t);
    if (t.length > 0 && !currentTenant.id) {
      setCurrentTenant(t[0]);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Handler functions
  const handleToggleRule = (ruleId: string) => {
    setRules(prev => prev.map(r => r.id === ruleId ? { ...r, is_active: !r.is_active } : r));
  };

  const handleUpdateAlertStatus = (alertId: string, status: SecurityAlert['status']) => {
    setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status } : a));
  };

  const handleUpdateIncidentStatus = (incidentId: string, status: IncidentStatus) => {
    setIncidents(prev => prev.map(inc => inc.id === incidentId ? { ...inc, status, updated_at: new Date().toISOString() } : inc));
  };

  const handleAddIncidentNote = (incidentId: string, noteText: string) => {
    setIncidents(prev => prev.map(inc => {
      if (inc.id === incidentId) {
        return {
          ...inc,
          timeline: [
            ...inc.timeline,
            {
              id: `t-${Date.now()}`,
              timestamp: new Date().toISOString(),
              action: noteText,
              actor: 'Alex Vance (Lead Analyst)'
            }
          ]
        };
      }
      return inc;
    }));
  };

  const handleTriggerPlaybook = (playbookName: string, target: string) => {
    const newExec: PlaybookExecution = {
      id: `pb-exec-${Date.now().toString().slice(-3)}`,
      playbook_name: playbookName,
      triggered_by: 'Analyst On-Demand Action',
      status: 'COMPLETED',
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      steps: [
        { id: 's1', step_number: 1, action_type: 'ISOLATE_HOST', target: target, status: 'SUCCESS', output: `Host ${target} interface isolated via EDR agent` },
        { id: 's2', step_number: 2, action_type: 'COLLECT_MEMORY_DUMP', target: target, status: 'SUCCESS', output: `Forensic memory image generated & stored` },
        { id: 's3', step_number: 3, action_type: 'NOTIFY_SLACK', target: '#sec-alerts', status: 'SUCCESS', output: `Response team notified on Slack` }
      ]
    };
    setPlaybooks(prev => [newExec, ...prev]);
    setActiveTab('soar');
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', backgroundColor: '#070A11' }}>
      {/* Top Header */}
      <Header
        tenants={tenants}
        currentTenant={currentTenant}
        onTenantChange={setCurrentTenant}
        onRefresh={loadData}
      />

      {/* Main Layout */}
      <div style={{ display: 'flex', flex: 1 }}>
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          setActiveTab={setActiveTab}
          activeAlertCount={alerts.filter(a => a.status === 'UNTRIAGED').length}
          openIncidentCount={incidents.filter(i => i.status !== 'CLOSED').length}
        />

        {/* Dynamic Content Body */}
        <main style={{ flex: 1, overflowY: 'auto' }}>
          {activeTab === 'dashboard' && (
            <Dashboard
              alerts={alerts}
              incidents={incidents}
              events={events}
              onSelectAlert={() => setActiveTab('alerts')}
              onSelectIncident={() => setActiveTab('incidents')}
            />
          )}

          {activeTab === 'events' && (
            <EventsView events={events} />
          )}

          {activeTab === 'rules' && (
            <DetectionRulesView rules={rules} onToggleRule={handleToggleRule} />
          )}

          {activeTab === 'alerts' && (
            <AlertCenter
              alerts={alerts}
              onUpdateAlertStatus={handleUpdateAlertStatus}
              onTriggerSoar={(alert) => handleTriggerPlaybook('Automated Host Isolation & Memory Dump', alert.source_ip)}
            />
          )}

          {activeTab === 'incidents' && (
            <IncidentManager
              incidents={incidents}
              onUpdateStatus={handleUpdateIncidentStatus}
              onAddNote={handleAddIncidentNote}
            />
          )}

          {activeTab === 'soar' && (
            <SoarPlaybooks
              playbooks={playbooks}
              onTriggerPlaybook={handleTriggerPlaybook}
            />
          )}

          {activeTab === 'intel' && (
            <ThreatIntel indicators={indicators} />
          )}

          {activeTab === 'telemetry' && (
            <TelemetrySearch events={events} />
          )}

          {activeTab === 'tenants' && (
            <TenantManager
              tenants={tenants}
              currentTenant={currentTenant}
              onSelectTenant={setCurrentTenant}
            />
          )}

          {activeTab === 'health' && (
            <SystemHealth health={health} />
          )}
        </main>
      </div>
    </div>
  );
}

export default App;

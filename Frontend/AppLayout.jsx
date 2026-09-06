import React from 'react';

export default function AppLayout({ children }) {
  return (
    <div style={{ display: 'flex', height: '100vh', backgroundColor: '#0f172a', color: '#f8fafc', fontFamily: 'sans-serif' }}>
      <aside style={{ width: '240px', borderRight: '1px solid #334155', padding: '20px' }}>
        <h2 style={{ color: '#38bdf8', fontSize: '1.2rem', marginBottom: '30px' }}>IoT-NIDS SOC</h2>
        <nav style={{ display: 'flex', flexDirection: 'column', gap: '15px' }}>
          <a href="#dashboard" style={{ color: '#f8fafc', textDecoration: 'none' }}>Dashboard</a>
          <a href="#alerts" style={{ color: '#94a3b8', textDecoration: 'none' }}>Live Alerts</a>
          <a href="#devices" style={{ color: '#94a3b8', textDecoration: 'none' }}>Topology</a>
        </nav>
      </aside>
      <main style={{ flex: 1, padding: '30px', overflowY: 'auto' }}>{children}</main>
    </div>
  );
}

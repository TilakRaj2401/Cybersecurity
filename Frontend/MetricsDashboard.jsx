import React from 'react';

export default function MetricsDashboard({ metrics }) {
  const cardStyle = { backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '20px', flex: 1 };
  
  return (
    <div style={{ display: 'flex', gap: '20px', marginBottom: '30px' }}>
      <div style={cardStyle}>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Total Traffic</div>
        <div style={{ fontSize: '1.8rem', fontWeight: 'bold' }}>{metrics.totalPackets} pkts</div>
      </div>
      <div style={cardStyle}>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Active IoT Devices</div>
        <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#38bdf8' }}>{metrics.activeDevices}</div>
      </div>
      <div style={cardStyle}>
        <div style={{ color: '#94a3b8', fontSize: '0.875rem' }}>Active Threats</div>
        <div style={{ fontSize: '1.8rem', fontWeight: 'bold', color: '#f43f5e' }}>{metrics.threats}</div>
      </div>
    </div>
  );
}

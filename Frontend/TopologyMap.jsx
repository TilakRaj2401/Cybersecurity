import React from 'react';

export default function TopologyMap({ devices }) {
  return (
    <div style={{ backgroundColor: '#1e293b', padding: '20px', borderRadius: '8px', border: '1px solid #334155' }}>
      <h3 style={{ marginTop: 0, color: '#94a3b8' }}>Network Device Topology</h3>
      <div style={{ display: 'flex', gap: '20px', flexWrap: 'wrap' }}>
        {devices.map((dev, i) => (
          <div key={i} style={{ border: `2px solid ${dev.isCompromised ? '#f43f5e' : '#10b981'}`, padding: '15px', borderRadius: '8px', textAlign: 'center', width: '120px' }}>
            <div style={{ fontSize: '1.5rem' }}>{dev.type === 'Gateway' ? '🌐' : '📱'}</div>
            <div style={{ fontWeight: 'bold', fontSize: '0.85rem', marginTop: '5px' }}>{dev.name}</div>
            <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{dev.ip}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

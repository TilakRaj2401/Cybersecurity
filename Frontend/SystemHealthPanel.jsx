import React from 'react';

export default function SystemHealthPanel({ health }) {
  return (
    <div style={{ backgroundColor: '#1e293b', padding: '15px', borderRadius: '8px', border: '1px solid #334155', marginTop: '20px' }}>
      <h4 style={{ margin: '0 0 10px 0', color: '#94a3b8' }}>Edge Gateway Metrics</h4>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.85rem' }}>
        <span>CPU Utilization: <strong>{health.cpu}%</strong></span>
        <span>RAM Consumption: <strong>{health.ram}%</strong></span>
        <span>Dropped Packets: <strong style={{ color: health.droppedPkts > 0 ? '#f43f5e' : '#f8fafc' }}>{health.droppedPkts}</strong></span>
      </div>
    </div>
  );
}

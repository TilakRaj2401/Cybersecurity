import React from 'react';

export default function DeviceProfile({ device }) {
  if (!device) return <div>Select a device</div>;

  return (
    <div style={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '20px' }}>
      <h3 style={{ margin: 0, color: '#f8fafc' }}>{device.name} Overview</h3>
      <div style={{ color: '#94a3b8', fontSize: '0.85rem', marginBottom: '15px' }}>{device.mac}</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', fontSize: '0.9rem' }}>
        <div>Protocol: <strong style={{ color: '#38bdf8' }}>{device.protocol}</strong></div>
        <div>Firmware: <strong>{device.firmware}</strong></div>
        <div>Risk Rating: <strong style={{ color: device.riskScore > 70 ? '#f43f5e' : '#34d399' }}>{device.riskScore}/100</strong></div>
      </div>
    </div>
  );
}

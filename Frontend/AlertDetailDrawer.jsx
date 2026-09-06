import React from 'react';

export default function AlertDetailDrawer({ alert, onClose }) {
  if (!alert) return null;

  return (
    <div style={{ position: 'fixed', right: 0, top: 0, height: '100vh', width: '400px', backgroundColor: '#1e293b', borderLeft: '1px solid #334155', padding: '25px', boxShadow: '-5px 0 15px rgba(0,0,0,0.5)' }}>
      <button onClick={onClose} style={{ float: 'right', background: 'none', border: 'none', color: '#f8fafc', cursor: 'pointer' }}>✖</button>
      <h3 style={{ color: '#38bdf8', marginTop: 0 }}>Incident Details</h3>
      <div style={{ marginTop: '20px', fontSize: '0.9rem', lineHeight: '1.6' }}>
        <p><strong>Rule ID:</strong> {alert.rule_id}</p>
        <p><strong>Engine:</strong> {alert.detection_type}</p>
        <p><strong>Severity:</strong> {alert.severity}</p>
        <p><strong>Source IP:</strong> {alert.src_ip}</p>
        <p><strong>Raw Payload Stream:</strong></p>
        <pre style={{ backgroundColor: '#0f172a', padding: '10px', borderRadius: '4px', overflowX: 'auto', fontSize: '0.8rem', color: '#34d399' }}>
          {JSON.stringify(alert, null, 2)}
        </pre>
      </div>
    </div>
  );
}

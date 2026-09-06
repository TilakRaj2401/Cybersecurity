import React from 'react';

export default function AlertsTable({ alerts }) {
  const getBadgeColor = (sev) => {
    if (sev === 'Critical' || sev === 'High') return '#f43f5e';
    if (sev === 'Medium') return '#fbbf24';
    return '#38bdf8';
  };

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse', backgroundColor: '#1e293b', borderRadius: '8px', overflow: 'hidden' }}>
      <thead>
        <tr style={{ backgroundColor: '#334155', textAlign: 'left', color: '#94a3b8' }}>
          <th style={{ padding: '12px' }}>Rule ID</th>
          <th style={{ padding: '12px' }}>Severity</th>
          <th style={{ padding: '12px' }}>Source IP</th>
          <th style={{ padding: '12px' }}>Description</th>
        </tr>
      </thead>
      <tbody>
        {alerts.map((al, idx) => (
          <tr key={idx} style={{ borderBottom: '1px solid #334155' }}>
            <td style={{ padding: '12px', fontFamily: 'monospace' }}>{al.rule_id}</td>
            <td style={{ padding: '12px' }}>
              <span style={{ backgroundColor: getBadgeColor(al.severity), color: '#000', padding: '2px 8px', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                {al.severity}
              </span>
            </td>
            <td style={{ padding: '12px' }}>{al.src_ip}</td>
            <td style={{ padding: '12px' }}>{al.message}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

import React from 'react';

function ThreatFeed({ threats = [] }) {
  
  const getTimeAgo = (isoString) => {
    const date = new Date(isoString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  console.log('ThreatFeed received threats:', threats);

  return (
    <div className="stat-card">
      <div style={{ display: 'flex', alignItems: 'center', marginBottom: '24px' }}>
        <div style={{ fontSize: '24px', marginRight: '12px' }}>🚨</div>
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', margin: 0 }}>
          Recent Threats Blocked
        </h3>
      </div>
      
      <div style={{ maxHeight: '450px', overflowY: 'auto' }}>
        {threats.length === 0 ? (
          <div style={{ 
            textAlign: 'center', 
            padding: '60px 20px',
            color: '#a0aec0'
          }}>
            <div style={{ fontSize: '48px', marginBottom: '16px' }}>✅</div>
            <p style={{ fontSize: '16px', fontWeight: '600' }}>
              No threats detected yet
            </p>
            <p style={{ fontSize: '14px', marginTop: '8px' }}>
              Your links are safe!
            </p>
          </div>
        ) : (
          threats.map(threat => (
            <div key={threat.id} className="threat-item">
              <div style={{ flex: 1 }}>
                <div className="threat-url">
                  {threat.url}
                </div>
                <div style={{ fontSize: '12px', color: '#a0aec0', fontWeight: '600' }}>
                  🕐 {getTimeAgo(threat.time)}
                </div>
              </div>
              <div className="threat-badge">
                {threat.score.toFixed(2)}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

export default ThreatFeed;
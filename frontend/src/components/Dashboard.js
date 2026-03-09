import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ThreatFeed from './ThreatFeed';

const API_BASE = 'http://localhost:5000';

function Dashboard() {
  const [stats, setStats] = useState({
    totalUrls: 0,
    totalClicks: 0,
    threatsBlocked: 0,
    activeUrls: 0,
    expiredUrls: 0
  });
  const [threats, setThreats] = useState([]);
  const [activeUrls, setActiveUrls] = useState([]);
  const [expiredUrls, setExpiredUrls] = useState([]);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('active');
  const [copied, setCopied] = useState(null);

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  const fetchDashboardData = async () => {
    try {
      const response = await axios.get(`${API_BASE}/api/dashboard/stats`);

      setStats({
        totalUrls: response.data.stats.total_urls || 0,
        totalClicks: response.data.stats.total_clicks || 0,
        threatsBlocked: response.data.stats.threats_blocked || 0,
        activeUrls: response.data.stats.active_urls || 0,
        expiredUrls: response.data.stats.expired_urls || 0
      });

      setThreats(response.data.recent_threats || []);
      setActiveUrls(response.data.active_urls || []);
      setExpiredUrls(response.data.expired_urls || []);
      setLoading(false);

    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
      setLoading(false);
    }
  };

  const getTimeAgo = (isoString) => {
    const date = new Date(isoString);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
    return `${Math.floor(seconds / 86400)}d ago`;
  };

  const getExpiresIn = (isoString) => {
    if (!isoString) return 'Never';
    const date = new Date(isoString);
    const now = new Date();
    const seconds = Math.floor((date - now) / 1000);
    if (seconds < 0) return 'Expired';
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m left`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)}h left`;
    return `${Math.floor(seconds / 86400)}d left`;
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const statCards = [
    {
      icon: '🔗',
      label: 'Total URLs',
      value: stats.totalUrls,
      gradient: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
    },
    {
      icon: '👆',
      label: 'Total Clicks',
      value: stats.totalClicks,
      gradient: 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)'
    },
    {
      icon: '✅',
      label: 'Active URLs',
      value: stats.activeUrls,
      gradient: 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)'
    },
    {
      icon: '⏰',
      label: 'Expired URLs',
      value: stats.expiredUrls,
      gradient: 'linear-gradient(135deg, #ed8936 0%, #dd6b20 100%)'
    },
    {
      icon: '🛡️',
      label: 'Threats Blocked',
      value: stats.threatsBlocked,
      gradient: 'linear-gradient(135deg, #f56565 0%, #c53030 100%)'
    }
  ];

  const tabs = [
    {
      id: 'active',
      label: `✅ Active URLs`,
      count: stats.activeUrls,
      activeGradient: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)'
    },
    {
      id: 'expired',
      label: `⏰ Expired URLs`,
      count: stats.expiredUrls,
      activeGradient: 'linear-gradient(135deg, #ed8936 0%, #dd6b20 100%)'
    },
    {
      id: 'threats',
      label: `🚨 Threats`,
      count: stats.threatsBlocked,
      activeGradient: 'linear-gradient(135deg, #f56565 0%, #c53030 100%)'
    }
  ];

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px', color: 'white' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }} className="loading">⏳</div>
        <p style={{ fontSize: '18px', fontWeight: '600' }}>Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <h2 style={{
        color: 'white',
        marginBottom: '32px',
        fontSize: '32px',
        fontWeight: '800',
        letterSpacing: '-0.5px'
      }}>
        Dashboard Overview
      </h2>

      {/* Stats Grid */}
      <div
        className="dashboard-grid"
        style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', marginBottom: '32px' }}
      >
        {statCards.map((card, index) => (
          <div className="stat-card" key={index}>
            <div className="stat-icon">{card.icon}</div>
            <div className="stat-label">{card.label}</div>
            <div className="stat-value" style={{
              background: card.gradient,
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
              backgroundClip: 'text'
            }}>
              {card.value.toLocaleString()}
            </div>
          </div>
        ))}
      </div>

      {/* URL Management Tabs */}
      <div className="stat-card" style={{ marginBottom: '24px' }}>

        {/* Tab Headers */}
        <div style={{
          display: 'flex',
          gap: '8px',
          marginBottom: '24px',
          borderBottom: '2px solid #e2e8f0',
          paddingBottom: '16px',
          flexWrap: 'wrap'
        }}>
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '10px 20px',
                border: 'none',
                borderRadius: '10px',
                cursor: 'pointer',
                fontWeight: '700',
                fontSize: '14px',
                background: activeTab === tab.id ? tab.activeGradient : '#f7fafc',
                color: activeTab === tab.id ? 'white' : '#718096',
                transition: 'all 0.2s',
                boxShadow: activeTab === tab.id ? '0 4px 12px rgba(0,0,0,0.15)' : 'none'
              }}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </div>

        {/* Active URLs Tab */}
        {activeTab === 'active' && (
          <div>
            {activeUrls.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px', color: '#a0aec0' }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>🔗</div>
                <p style={{ fontSize: '16px', fontWeight: '600' }}>No active URLs yet</p>
                <p style={{ fontSize: '14px' }}>Create your first short URL!</p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #e2e8f0' }}>
                      {['SHORT URL', 'ORIGINAL URL', 'CLICKS', 'VERDICT', 'EXPIRES', 'CREATED', 'COPY'].map((h) => (
                        <th
                          key={h}
                          style={{
                            textAlign: h === 'SHORT URL' || h === 'ORIGINAL URL' ? 'left' : 'center',
                            padding: '12px',
                            color: '#718096',
                            fontWeight: '700',
                            fontSize: '12px',
                            letterSpacing: '0.5px'
                          }}
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeUrls.map((url) => (
                      <tr
                        key={url.id}
                        style={{ borderBottom: '1px solid #e2e8f0', transition: 'background 0.2s' }}
                        onMouseEnter={(e) => e.currentTarget.style.background = '#f7fafc'}
                        onMouseLeave={(e) => e.currentTarget.style.background = 'white'}
                      >
                        <td style={{ padding: '12px' }}>
                          <a
                            href={url.short_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{
                              color: '#667eea',
                              fontWeight: '600',
                              fontFamily: 'monospace',
                              fontSize: '14px',
                              textDecoration: 'none'
                            }}
                          >
                            /{url.short_code}
                          </a>
                        </td>
                        <td style={{ padding: '12px', maxWidth: '250px' }}>
                          <div style={{
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontSize: '13px',
                            color: '#4a5568'
                          }}>
                            {url.original_url}
                          </div>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px', fontWeight: '700', color: '#2d3748' }}>
                          {url.clicks}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px' }}>
                          <span style={{
                            padding: '4px 12px',
                            borderRadius: '12px',
                            fontSize: '12px',
                            fontWeight: '700',
                            background: url.verdict === 'SAFE' ? '#c6f6d5' : '#feebc8',
                            color: url.verdict === 'SAFE' ? '#2f855a' : '#c05621'
                          }}>
                            {url.verdict}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px', fontSize: '13px' }}>
                          {url.expires_at ? (
                            <span style={{ color: '#ed8936', fontWeight: '600' }}>
                              {getExpiresIn(url.expires_at)}
                            </span>
                          ) : (
                            <span style={{ color: '#48bb78', fontWeight: '600' }}>Never</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px', fontSize: '13px', color: '#718096' }}>
                          {getTimeAgo(url.created_at)}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px' }}>
                          <button
                            onClick={() => copyToClipboard(url.short_url, url.id)}
                            style={{
                              background: copied === url.id
                                ? 'linear-gradient(135deg, #48bb78 0%, #38a169 100%)'
                                : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                              color: 'white',
                              border: 'none',
                              borderRadius: '8px',
                              padding: '6px 12px',
                              cursor: 'pointer',
                              fontSize: '12px',
                              fontWeight: '600',
                              transition: 'all 0.2s'
                            }}
                          >
                            {copied === url.id ? '✅ Copied!' : '📋 Copy'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Expired URLs Tab */}
        {activeTab === 'expired' && (
          <div>
            {expiredUrls.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '40px', color: '#a0aec0' }}>
                <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏰</div>
                <p style={{ fontSize: '16px', fontWeight: '600' }}>No expired URLs yet</p>
                <p style={{ fontSize: '14px' }}>Links with expiration dates will appear here.</p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ borderBottom: '2px solid #e2e8f0' }}>
                      {['SHORT URL', 'ORIGINAL URL', 'CLICKS', 'EXPIRED ON', 'CREATED'].map((h) => (
                        <th
                          key={h}
                          style={{
                            textAlign: h === 'SHORT URL' || h === 'ORIGINAL URL' ? 'left' : 'center',
                            padding: '12px',
                            color: '#718096',
                            fontWeight: '700',
                            fontSize: '12px',
                            letterSpacing: '0.5px'
                          }}
                        >
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {expiredUrls.map((url) => (
                      <tr
                        key={url.id}
                        style={{ borderBottom: '1px solid #e2e8f0', opacity: 0.65 }}
                      >
                        <td style={{ padding: '12px' }}>
                          <span style={{
                            color: '#718096',
                            fontFamily: 'monospace',
                            fontSize: '14px',
                            textDecoration: 'line-through'
                          }}>
                            /{url.short_code}
                          </span>
                        </td>
                        <td style={{ padding: '12px', maxWidth: '250px' }}>
                          <div style={{
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            fontSize: '13px',
                            color: '#4a5568'
                          }}>
                            {url.original_url}
                          </div>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px', fontWeight: '700', color: '#2d3748' }}>
                          {url.clicks}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px' }}>
                          <span style={{ color: '#e53e3e', fontWeight: '600', fontSize: '13px' }}>
                            {new Date(url.expires_at).toLocaleDateString('en-US', {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric'
                            })}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px', fontSize: '13px', color: '#718096' }}>
                          {getTimeAgo(url.created_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Threats Tab */}
        {activeTab === 'threats' && (
          <ThreatFeed threats={threats} />
        )}
      </div>
    </div>
  );
}

export default Dashboard;
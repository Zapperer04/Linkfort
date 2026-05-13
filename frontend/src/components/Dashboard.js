import React, { useState, useEffect } from 'react';
import axios from 'axios';
import ThreatFeed from './ThreatFeed';
import './Dashboard.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000';

function Dashboard({ onOpenURL }) {
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
      const token = localStorage.getItem('linkfort_token') || localStorage.getItem('access_token') || localStorage.getItem('token');
      const headers = token ? { headers: { Authorization: `Bearer ${token}` } } : {};

      const response = await axios.get(`${API_BASE}/api/dashboard/stats`, headers);
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
    { icon: '🔗', label: 'Total URLs', value: stats.totalUrls },
    { icon: '👆', label: 'Total Clicks', value: stats.totalClicks },
    { icon: '✅', label: 'Active URLs', value: stats.activeUrls },
    { icon: '⏰', label: 'Expired URLs', value: stats.expiredUrls },
    { icon: '🛡️', label: 'Threats Blocked', value: stats.threatsBlocked }
  ];

  const tabs = [
    { id: 'active', label: '✅ Active URLs', count: stats.activeUrls },
    { id: 'expired', label: '⏰ Expired URLs', count: stats.expiredUrls },
    { id: 'threats', label: '🚨 Threats', count: stats.threatsBlocked }
  ];

  const manageBtn = (shortCode) => (
    <button
      onClick={() => onOpenURL && onOpenURL(shortCode)}
      className="dashboard-btn dashboard-btn-manage"
    >
      ⚙️ Manage
    </button>
  );

  if (loading) {
    return (
      <div className="dashboard-loading">
        <div className="dashboard-loading-icon">⏳</div>
        <p className="dashboard-loading-text">Loading dashboard...</p>
      </div>
    );
  }

  return (
    <div className="dashboard">
      <h2>Dashboard Overview</h2>

      {/* Stats Grid */}
      <div className="dashboard-grid">
        {statCards.map((card, index) => (
          <div className="stat-card" key={index}>
            <div className="stat-icon">{card.icon}</div>
            <div className="stat-label">{card.label}</div>
            <div className="stat-value">{card.value.toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* URL Management Tabs */}
      <div className="stat-card">
        {/* Tab Headers */}
        <div className="dashboard-tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`dashboard-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            >
              {tab.label} ({tab.count})
            </button>
          ))}
        </div>

        {/* Active URLs Tab */}
        {activeTab === 'active' && (
          <div>
            {activeUrls.length === 0 ? (
              <div className="dashboard-empty">
                <div className="dashboard-empty-icon">🔗</div>
                <p className="dashboard-empty-title">No active URLs yet</p>
                <p className="dashboard-empty-desc">Create your first short URL!</p>
              </div>
            ) : (
              <div className="dashboard-table-wrapper">
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      {['SHORT URL', 'ORIGINAL URL', 'CLICKS', 'VERDICT', 'EXPIRES', 'CREATED', 'COPY', 'MANAGE'].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {activeUrls.map((url) => (
                      <tr key={url.id}>
                        <td>
                          <a href={url.short_url} target="_blank" rel="noopener noreferrer">
                            /{url.short_code}
                          </a>
                        </td>
                        <td>
                          <div className="dashboard-table-cell-ellipsis">{url.original_url}</div>
                        </td>
                        <td style={{ textAlign: 'center', fontWeight: '700' }}>{url.clicks}</td>
                        <td style={{ textAlign: 'center' }}>
                          <span className={`dashboard-verdict ${url.verdict === 'SAFE' ? 'safe' : 'threat'}`}>
                            {url.verdict}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          {url.expires_at ? (
                            <span className="dashboard-status-expired">{getExpiresIn(url.expires_at)}</span>
                          ) : (
                            <span className="dashboard-status-never">Never</span>
                          )}
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <span className="dashboard-status-time">{getTimeAgo(url.created_at)}</span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <button
                            onClick={() => copyToClipboard(url.short_url, url.id)}
                            className={`dashboard-btn dashboard-btn-copy ${copied === url.id ? 'copied' : ''}`}
                          >
                            {copied === url.id ? '✅ Copied!' : '📋 Copy'}
                          </button>
                        </td>
                        <td style={{ textAlign: 'center' }}>{manageBtn(url.short_code)}</td>
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
              <div className="dashboard-empty">
                <div className="dashboard-empty-icon">⏰</div>
                <p className="dashboard-empty-title">No expired URLs yet</p>
                <p className="dashboard-empty-desc">Links with expiration dates will appear here.</p>
              </div>
            ) : (
              <div className="dashboard-table-wrapper">
                <table className="dashboard-table">
                  <thead>
                    <tr>
                      {['SHORT URL', 'ORIGINAL URL', 'CLICKS', 'EXPIRED ON', 'CREATED', 'MANAGE'].map((h) => (
                        <th key={h}>{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {expiredUrls.map((url) => (
                      <tr key={url.id} className="expired">
                        <td>
                          <span className="dashboard-status-expired">/{url.short_code}</span>
                        </td>
                        <td>
                          <div className="dashboard-table-cell-ellipsis">{url.original_url}</div>
                        </td>
                        <td style={{ textAlign: 'center', fontWeight: '700' }}>{url.clicks}</td>
                        <td style={{ textAlign: 'center', color: 'var(--lf-dashboard-pink)' }}>
                          <span style={{ fontWeight: '600', fontSize: '13px' }}>
                            {new Date(url.expires_at).toLocaleDateString('en-US', {
                              month: 'short',
                              day: 'numeric',
                              year: 'numeric'
                            })}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center' }}>
                          <span className="dashboard-status-time">{getTimeAgo(url.created_at)}</span>
                        </td>
                        <td style={{ textAlign: 'center' }}>{manageBtn(url.short_code)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Threats Tab */}
        {activeTab === 'threats' && <ThreatFeed threats={threats} />}
      </div>

    </div>
  );
}

export default Dashboard;

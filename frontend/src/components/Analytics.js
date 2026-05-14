import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000';

function Analytics() {
  const [loading, setLoading] = useState(true);
  const [analyticsData, setAnalyticsData] = useState({
    threatTrends: [],
    scoreDistribution: [],
    topBlockedDomains: [],
    layerPerformance: [],
    clickStats: []
  });

  useEffect(() => {
    fetchAnalytics();
    // Refresh every 30 seconds
    const interval = setInterval(fetchAnalytics, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchAnalytics = async () => {
    try {
      const token = localStorage.getItem('linkfort_token') || localStorage.getItem('access_token') || localStorage.getItem('token');
      const headers = token ? { headers: { Authorization: `Bearer ${token}` } } : {};
      const response = await axios.get(`${API_BASE}/api/analytics`, headers);
      setAnalyticsData(response.data);
      setLoading(false);
    } catch (error) {
      console.error('Failed to fetch analytics:', error);
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px', color: 'white' }}>
        <div style={{ fontSize: '48px', marginBottom: '16px' }}>📊</div>
        <p style={{ fontSize: '18px', fontWeight: '600' }}>Loading analytics...</p>
      </div>
    );
  }

  const COLORS = {
    safe: '#48bb78',
    warn: '#ed8936',
    block: '#f56565',
    layer1: '#667eea',
    layer2: '#764ba2',
    layer3: '#f093fb'
  };

  return (
    <div className="analytics">
      <h2 style={{
        color: 'white',
        marginBottom: '32px',
        fontSize: '32px',
        fontWeight: '800',
        letterSpacing: '-0.5px'
      }}>
        📊 Analytics & Insights
      </h2>

      {/* Threat Trends Over Time */}
      {/* Threat Trends Over Time */}
      <div className="stat-card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--lf-dashboard-text-light)', marginBottom: '24px' }}>
          🔍 Threat Detection Trends
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={analyticsData.threatTrends}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--lf-dashboard-border)" />
            <XAxis dataKey="date" stroke="var(--lf-dashboard-text-dark)" />
            <YAxis stroke="var(--lf-dashboard-text-dark)" />
            <Tooltip
              contentStyle={{ background: 'var(--lf-dashboard-bg)', border: '1px solid var(--lf-dashboard-border)', borderRadius: '8px', color: 'var(--lf-dashboard-text-light)' }}
            />
            <Legend />
            <Line type="monotone" dataKey="safe" stroke={COLORS.safe} strokeWidth={2} name="Safe URLs" />
            <Line type="monotone" dataKey="warn" stroke={COLORS.warn} strokeWidth={2} name="Warnings" />
            <Line type="monotone" dataKey="blocked" stroke={COLORS.block} strokeWidth={2} name="Blocked" />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '24px', marginBottom: '24px' }}>
        {/* Threat Score Distribution */}
        <div className="stat-card">
          <h3 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--lf-dashboard-text-light)', marginBottom: '24px' }}>
            📈 Threat Score Distribution
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={analyticsData.scoreDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--lf-dashboard-border)" />
              <XAxis dataKey="range" stroke="var(--lf-dashboard-text-dark)" />
              <YAxis stroke="var(--lf-dashboard-text-dark)" />
              <Tooltip
                contentStyle={{ background: 'var(--lf-dashboard-bg)', border: '1px solid var(--lf-dashboard-border)', borderRadius: '8px', color: 'var(--lf-dashboard-text-light)' }}
              />
              <Bar dataKey="count" fill="#667eea" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Layer Performance */}
        <div className="stat-card">
          <h3 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--lf-dashboard-text-light)', marginBottom: '24px' }}>
            🎯 Detection Layer Performance
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={analyticsData.layerPerformance}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {analyticsData.layerPerformance.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={Object.values(COLORS)[index + 3]} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'var(--lf-dashboard-bg)', border: '1px solid var(--lf-dashboard-border)', borderRadius: '8px', color: 'var(--lf-dashboard-text-light)' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Blocked Domains */}
      <div className="stat-card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--lf-dashboard-text-light)', marginBottom: '24px' }}>
          🚫 Top Blocked Domains
        </h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--lf-dashboard-border)' }}>
                <th style={{ textAlign: 'left', padding: '12px', color: 'var(--lf-dashboard-text-dark)', fontWeight: '700' }}>Domain</th>
                <th style={{ textAlign: 'center', padding: '12px', color: 'var(--lf-dashboard-text-dark)', fontWeight: '700' }}>Attempts</th>
                <th style={{ textAlign: 'center', padding: '12px', color: 'var(--lf-dashboard-text-dark)', fontWeight: '700' }}>Avg Score</th>
                <th style={{ textAlign: 'left', padding: '12px', color: 'var(--lf-dashboard-text-dark)', fontWeight: '700' }}>Top Reason</th>
              </tr>
            </thead>
            <tbody>
              {analyticsData.topBlockedDomains.map((domain, index) => (
                <tr key={index} style={{ borderBottom: '1px solid rgba(0, 217, 255, 0.1)' }}>
                  <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '14px', color: 'var(--lf-dashboard-pink)' }}>
                    {domain.domain}
                  </td>
                  <td style={{ textAlign: 'center', padding: '12px', fontWeight: '600', color: 'var(--lf-dashboard-text-light)' }}>
                    {domain.count}
                  </td>
                  <td style={{ textAlign: 'center', padding: '12px' }}>
                    <span style={{
                      background: domain.avgScore > 0.7 ? 'rgba(255, 94, 168, 0.2)' : 'rgba(237, 137, 54, 0.2)',
                      color: domain.avgScore > 0.7 ? 'var(--lf-dashboard-pink)' : '#ed8936',
                      border: `1px solid ${domain.avgScore > 0.7 ? 'var(--lf-dashboard-pink)' : '#ed8936'}`,
                      padding: '4px 12px',
                      borderRadius: '12px',
                      fontSize: '12px',
                      fontWeight: '700'
                    }}>
                      {domain.avgScore.toFixed(2)}
                    </span>
                  </td>
                  <td style={{ padding: '12px', fontSize: '14px', color: 'var(--lf-dashboard-text-light)' }}>
                    {domain.topReason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Click Statistics */}
      <div className="stat-card">
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: 'var(--lf-dashboard-text-light)', marginBottom: '24px' }}>
          👆 Click Activity
        </h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={analyticsData.clickStats}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--lf-dashboard-border)" />
            <XAxis dataKey="hour" stroke="var(--lf-dashboard-text-dark)" />
            <YAxis stroke="var(--lf-dashboard-text-dark)" />
            <Tooltip
              contentStyle={{ background: 'var(--lf-dashboard-bg)', border: '1px solid var(--lf-dashboard-border)', borderRadius: '8px', color: 'var(--lf-dashboard-text-light)' }}
            />
            <Legend />
            <Bar dataKey="clicks" fill="#48bb78" radius={[8, 8, 0, 0]} name="Clicks" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

export default Analytics;
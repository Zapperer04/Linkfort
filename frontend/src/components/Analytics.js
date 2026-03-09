import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  LineChart, Line, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

const API_BASE = 'http://localhost:5000';

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
      const response = await axios.get(`${API_BASE}/api/analytics`);
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
      <div className="stat-card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', marginBottom: '24px' }}>
          🔍 Threat Detection Trends
        </h3>
        <ResponsiveContainer width="100%" height={300}>
          <LineChart data={analyticsData.threatTrends}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="date" stroke="#718096" />
            <YAxis stroke="#718096" />
            <Tooltip
              contentStyle={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
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
          <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', marginBottom: '24px' }}>
            📈 Threat Score Distribution
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={analyticsData.scoreDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="range" stroke="#718096" />
              <YAxis stroke="#718096" />
              <Tooltip
                contentStyle={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
              />
              <Bar dataKey="count" fill="#667eea" radius={[8, 8, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Layer Performance */}
        <div className="stat-card">
          <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', marginBottom: '24px' }}>
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
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Top Blocked Domains */}
      <div className="stat-card" style={{ marginBottom: '24px' }}>
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', marginBottom: '24px' }}>
          🚫 Top Blocked Domains
        </h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid #e2e8f0' }}>
                <th style={{ textAlign: 'left', padding: '12px', color: '#718096', fontWeight: '700' }}>Domain</th>
                <th style={{ textAlign: 'center', padding: '12px', color: '#718096', fontWeight: '700' }}>Attempts</th>
                <th style={{ textAlign: 'center', padding: '12px', color: '#718096', fontWeight: '700' }}>Avg Score</th>
                <th style={{ textAlign: 'left', padding: '12px', color: '#718096', fontWeight: '700' }}>Top Reason</th>
              </tr>
            </thead>
            <tbody>
              {analyticsData.topBlockedDomains.map((domain, index) => (
                <tr key={index} style={{ borderBottom: '1px solid #e2e8f0' }}>
                  <td style={{ padding: '12px', fontFamily: 'monospace', fontSize: '14px', color: '#e53e3e' }}>
                    {domain.domain}
                  </td>
                  <td style={{ textAlign: 'center', padding: '12px', fontWeight: '600' }}>
                    {domain.count}
                  </td>
                  <td style={{ textAlign: 'center', padding: '12px' }}>
                    <span style={{
                      background: domain.avgScore > 0.7 ? '#fed7d7' : '#feebc8',
                      color: domain.avgScore > 0.7 ? '#c53030' : '#c05621',
                      padding: '4px 12px',
                      borderRadius: '12px',
                      fontSize: '14px',
                      fontWeight: '600'
                    }}>
                      {domain.avgScore.toFixed(2)}
                    </span>
                  </td>
                  <td style={{ padding: '12px', fontSize: '14px', color: '#4a5568' }}>
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
        <h3 style={{ fontSize: '20px', fontWeight: '700', color: '#2d3748', marginBottom: '24px' }}>
          👆 Click Activity
        </h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={analyticsData.clickStats}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
            <XAxis dataKey="hour" stroke="#718096" />
            <YAxis stroke="#718096" />
            <Tooltip
              contentStyle={{ background: '#fff', border: '1px solid #e2e8f0', borderRadius: '8px' }}
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
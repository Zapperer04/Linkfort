import React, { useState } from 'react';
import './App.css';
import { AuthProvider, useAuth } from './context/AuthContext';
import Auth from './components/Auth';
import Dashboard from './components/Dashboard';
import CreateShortURL from './components/CreateShortURL';
import Analytics from './components/Analytics';
import URLDetailPage from './components/URLDetailPage';

function AppContent() {
  const { user, logout, loading } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedShortCode, setSelectedShortCode] = useState(null);

  // Navigate to URL detail view
  const openURLDetail = (shortCode) => {
    setSelectedShortCode(shortCode);
    setActiveTab('url-detail');
  };

  // Go back to dashboard from detail view
  const backToDashboard = () => {
    setSelectedShortCode(null);
    setActiveTab('dashboard');
  };

  if (loading) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ textAlign: 'center', color: 'white' }}>
          <div style={{ fontSize: '48px', marginBottom: '16px' }}>⏳</div>
          <p style={{ fontSize: '18px', fontWeight: '600' }}>Loading LinkFort...</p>
        </div>
      </div>
    );
  }

  if (!user) {
    return <Auth onSuccess={() => setActiveTab('dashboard')} />;
  }

  return (
    <div className="App">
      <header className="app-header">
        <div className="header-content" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1>🛡️ LinkFort</h1>
            <p className="tagline">Secure URL Shortener with Real-Time Threat Detection</p>
          </div>
          {/* User Info */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ color: 'white', fontWeight: '700', fontSize: '15px' }}>
                👤 {user.username}
              </div>
              <div style={{ color: 'rgba(255,255,255,0.7)', fontSize: '12px' }}>
                {user.email}
              </div>
            </div>
            <button
              onClick={logout}
              style={{
                background: 'rgba(255,255,255,0.2)',
                border: '1px solid rgba(255,255,255,0.3)',
                color: 'white',
                padding: '8px 16px',
                borderRadius: '10px',
                cursor: 'pointer',
                fontWeight: '600',
                fontSize: '14px',
                transition: 'all 0.2s'
              }}
              onMouseEnter={e => e.target.style.background = 'rgba(255,255,255,0.3)'}
              onMouseLeave={e => e.target.style.background = 'rgba(255,255,255,0.2)'}
            >
              🚪 Logout
            </button>
          </div>
        </div>

        {/* Hide tabs when on detail view */}
        {activeTab !== 'url-detail' && (
          <nav className="tabs">
            <button
              className={activeTab === 'dashboard' ? 'active' : ''}
              onClick={() => setActiveTab('dashboard')}
            >
              📊 Dashboard
            </button>
            <button
              className={activeTab === 'create' ? 'active' : ''}
              onClick={() => setActiveTab('create')}
            >
              ✨ Create Short URL
            </button>
            <button
              className={activeTab === 'analytics' ? 'active' : ''}
              onClick={() => setActiveTab('analytics')}
            >
              📈 Analytics
            </button>
          </nav>
        )}
      </header>

      <main className="app-main">
        <div style={{ animation: 'fadeIn 0.3s ease-in' }}>
          {activeTab === 'dashboard' && (
            <Dashboard onOpenURL={openURLDetail} />
          )}
          {activeTab === 'create' && <CreateShortURL />}
          {activeTab === 'analytics' && <Analytics />}
          {activeTab === 'url-detail' && selectedShortCode && (
            <URLDetailPage
              shortCode={selectedShortCode}
              onBack={backToDashboard}
            />
          )}
        </div>
      </main>

      <footer style={{
        textAlign: 'center',
        padding: '20px',
        color: 'rgba(255, 255, 255, 0.8)',
        fontSize: '14px',
        fontWeight: '500'
      }}>
        <p>Built with ❤️ using Flask + React + PostgreSQL + Redis</p>
        <p style={{ fontSize: '12px', marginTop: '8px', opacity: 0.7 }}>
          Multi-layer threat detection • Bloom filters • Rate limiting • Real-time analytics
        </p>
      </footer>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
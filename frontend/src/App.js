import React, { useState } from 'react';
import './App.css';
import { AuthProvider, useAuth } from './context/AuthContext';
import Homepage from './components/Homepage';
import Auth from './components/Auth';
import Dashboard from './components/Dashboard';
import CreateShortURL from './components/CreateShortURL';
import Analytics from './components/Analytics';
import URLDetailPage from './components/URLDetailPage';

function AppContent() {
  const { user, logout, loading } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [selectedShortCode, setSelectedShortCode] = useState(null);
  const [showHomepage, setShowHomepage] = useState(true);
  const [authMode, setAuthMode] = useState('login');

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
    if (showHomepage) {
      return (
        <Homepage
          onNavigateToAuth={() => {
            setAuthMode('login');
            setShowHomepage(false);
          }}
          onNavigateToSignup={() => {
            setAuthMode('signup');
            setShowHomepage(false);
          }}
        />
      );
    }
    return (
      <Auth
        initialMode={authMode}
        onSuccess={() => setActiveTab('dashboard')}
        onBackToHome={() => setShowHomepage(true)}
      />
    );
  }

  return (
    <div className="App">
      {/* Background Particles */}
      <div className="app-particles" aria-hidden="true">
        {Array.from({ length: 28 }).map((_, i) => (
          <span
            key={i}
            className="app-particle"
            style={{
              left: `${Math.random() * 100}%`,
              top: `${Math.random() * 100}%`,
              width: `${2 + Math.random() * 3}px`,
              height: `${2 + Math.random() * 3}px`,
              animationDelay: `${Math.random() * 8}s`,
              animationDuration: `${14 + Math.random() * 12}s`
            }}
          />
        ))}
      </div>

      {/* Floating Glow Blobs */}
      <div className="app-bg-glow app-bg-glow-a" />
      <div className="app-bg-glow app-bg-glow-b" />

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
              className="btn-logout"
              aria-label="Logout"
            >
              <span className="btn-logout-emoji">🚪</span>
              <span className="btn-logout-text">Logout</span>
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

      <footer className="app-footer">
        <div className="app-footer-container">
          <div className="app-footer-shell">
            <div className="app-footer-brand">
              <div className="app-footer-logo">LinkFort</div>
              <p>
                Secure short links with risk checks, click tracking, and a premium dashboard experience.
              </p>
              <div className="app-footer-badges">
                <span>Threat Detection</span>
                <span>Click Analytics</span>
                <span>Expiration Control</span>
              </div>
            </div>

            <div className="app-footer-column">
              <h3>Product</h3>
              <a onClick={() => { setActiveTab('dashboard'); setSelectedShortCode(null); }}>Overview</a>
              <a onClick={() => { setActiveTab('create'); setSelectedShortCode(null); }}>Create Link</a>
              <a onClick={() => { setActiveTab('analytics'); setSelectedShortCode(null); }}>Analytics</a>
            </div>

            <div className="app-footer-column">
              <h3>Support</h3>
              <a href="mailto:support@linkfort.local">Contact Support</a>
              <a onClick={() => { setActiveTab('dashboard'); setSelectedShortCode(null); }}>Dashboard</a>
              <a onClick={() => { setActiveTab('analytics'); setSelectedShortCode(null); }}>Metrics Guide</a>
            </div>

            <div className="app-footer-column">
              <h3>Actions</h3>
              <button className="app-footer-action" onClick={() => { setActiveTab('create'); setSelectedShortCode(null); }}>✨ Shorten URL</button>
              <button className="app-footer-action secondary" onClick={logout}>🚪 Log out</button>
            </div>
          </div>

          <div className="app-footer-bottom">
            <div className="footer-copyright">
              <span>© 2026 LinkFort</span>
              <span className="footer-dot">•</span>
              <span>Shorten, protect, and track your links.</span>
            </div>
            <div className="footer-status">
              <span className="status-indicator"></span>
              <span>Threat Protection Active</span>
            </div>
          </div>
        </div>
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
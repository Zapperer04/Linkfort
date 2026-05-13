import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import './Auth.css';

function Auth({ onSuccess, onBackToHome }) {
  const [isLogin, setIsLogin] = useState(true);
  const [formData, setFormData] = useState({
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const { login, register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (isLogin) {
        await login(formData.email, formData.password);
      } else {
        if (formData.password !== formData.confirmPassword) {
          setError('Passwords do not match');
          setLoading(false);
          return;
        }
        await register(formData.email, formData.password);
      }
      onSuccess();
    } catch (err) {
      setError(err.response?.data?.error || 'Something went wrong');
    }
    setLoading(false);
  };

  return (
    <div className="lf-auth">
      <div className="lf-auth-bg-grid" />
      <div className="lf-auth-bg-glow lf-auth-bg-glow-a" />
      <div className="lf-auth-bg-glow lf-auth-bg-glow-b" />
      
      <div className="lf-auth-particles" aria-hidden="true">
        {Array.from({ length: 20 }).map((_, i) => (
          <span
            key={i}
            className="lf-auth-particle"
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

      {onBackToHome && (
        <button className="lf-auth-back" onClick={onBackToHome}>
          ← Back to Home
        </button>
      )}

      <div className="lf-auth-container">
        <div className="lf-auth-left">
          <div className="lf-auth-branding">
            <div className="lf-auth-logo-icon">🔒</div>
            <h1>LinkFort</h1>
            <p className="lf-auth-tagline">Secure. Protected. Tracked.</p>
          </div>

          <div className="lf-auth-features">
            {[
              { icon: '⚡', title: 'Lightning Fast', desc: 'Create links instantly' },
              { icon: '🛡️', title: 'Protected', desc: 'Safety checks included' },
              { icon: '📊', title: 'Analytics', desc: 'Track every click' },
              { icon: '🔐', title: 'Encrypted', desc: 'Password protected' }
            ].map((feature, idx) => (
              <div key={idx} className="lf-auth-feature-card">
                <div className="lf-auth-feature-icon">{feature.icon}</div>
                <div className="lf-auth-feature-text">
                  <h3>{feature.title}</h3>
                  <p>{feature.desc}</p>
                </div>
              </div>
            ))}
          </div>

        </div>

        <div className="lf-auth-right">
          <div className="lf-auth-form-wrapper">
            <div className="lf-auth-header">
              <h2>{isLogin ? 'Welcome Back' : 'Get Started'}</h2>
              <p>{isLogin ? 'Sign in to your account' : 'Create your account in seconds'}</p>
            </div>

            <div className="lf-auth-toggle">
              {['Sign In', 'Sign Up'].map((tab, idx) => (
                <button
                  key={idx}
                  onClick={() => { setIsLogin(idx === 0); setError(''); }}
                  className={`lf-auth-toggle-btn ${(idx === 0 ? isLogin : !isLogin) ? 'active' : ''}`}
                >
                  {tab}
                </button>
              ))}
            </div>

            {error && (
              <div className="lf-auth-error">
                ⚠️ {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="lf-auth-form">
              <div className="lf-auth-form-group">
                <label>Email</label>
                <input
                  type="email"
                  value={formData.email}
                  onChange={(e) => setFormData({ ...formData, email: e.target.value })}
                  placeholder="your@email.com"
                  required
                />
              </div>

              <div className="lf-auth-form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={formData.password}
                  onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                  placeholder="••••••••"
                  required
                />
              </div>

              {!isLogin && (
                <div className="lf-auth-form-group">
                  <label>Confirm Password</label>
                  <input
                    type="password"
                    value={formData.confirmPassword}
                    onChange={(e) => setFormData({ ...formData, confirmPassword: e.target.value })}
                    placeholder="••••••••"
                    required={!isLogin}
                  />
                </div>
              )}

              <button type="submit" disabled={loading} className="lf-auth-submit">
                {loading ? '⏳ Processing...' : isLogin ? '🔐 Sign In' : '🚀 Create Account'}
              </button>
            </form>

            <div className="lf-auth-footer">
              <span>{isLogin ? "Don't have an account? " : 'Already have an account? '}</span>
              <button
                onClick={() => { setIsLogin(!isLogin); setError(''); }}
                className="lf-auth-toggle-link"
              >
                {isLogin ? 'Sign Up' : 'Sign In'}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Auth;

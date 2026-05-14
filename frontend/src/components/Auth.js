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

  const getAuthErrorMessage = (err) => {
    const apiError = err?.response?.data?.error || err?.response?.data?.message || '';
    const status = err?.response?.status;

    if (!err?.response) {
      return 'Unable to reach the server. Please try again.';
    }

    if (status === 401) {
      if (isLogin) {
        return 'Incorrect email or password.';
      }
      return apiError || 'You could not be signed up. Please check your password and try again.';
    }

    if (status === 400) {
      return apiError || (isLogin
        ? 'Please check your login details.'
        : 'Please fix the highlighted signup details and try again.');
    }

    if (status === 404) {
      return apiError || 'Account not found.';
    }

    if (status >= 500) {
      return 'Server error. Please try again in a moment.';
    }

    return apiError || 'Something went wrong. Please try again.';
  };

  // Password strength calculator
  const calculatePasswordStrength = (password) => {
    const checks = {
      length: password.length >= 6,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      numbers: /\d/.test(password),      // eslint-disable-next-line no-useless-escape      special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>/?]/.test(password)
    };
    
    const score = Object.values(checks).filter(Boolean).length;
    return { checks, score, maxScore: 5 };
  };

  const passwordStrength = calculatePasswordStrength(formData.password);

  const getStrengthColor = () => {
    if (passwordStrength.score <= 1) return '#ef4444';
    if (passwordStrength.score <= 2) return '#f97316';
    if (passwordStrength.score === 3) return '#eab308';
    if (passwordStrength.score === 4) return '#84cc16';
    return '#22c55e';
  };

  const getStrengthText = () => {
    if (!formData.password) return '';
    if (passwordStrength.score <= 1) return 'Weak';
    if (passwordStrength.score <= 2) return 'Fair';
    if (passwordStrength.score === 3) return 'Good';
    if (passwordStrength.score === 4) return 'Strong';
    return 'Very Strong';
  };

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
        if (passwordStrength.score < 2) {
          setError('Password is too weak. Add uppercase, numbers, or special characters.');
          setLoading(false);
          return;
        }
        await register(formData.email, formData.password);
      }
      onSuccess();
    } catch (err) {
      setError(getAuthErrorMessage(err));
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
                
                {!isLogin && formData.password && (
                  <div className="lf-password-strength">
                    <div className="lf-strength-bar">
                      <div 
                        className="lf-strength-fill" 
                        style={{
                          width: `${(passwordStrength.score / passwordStrength.maxScore) * 100}%`,
                          backgroundColor: getStrengthColor()
                        }}
                      />
                    </div>
                    <div className="lf-strength-text" style={{ color: getStrengthColor() }}>
                      Strength: <strong>{getStrengthText()}</strong>
                    </div>
                    <div className="lf-strength-checklist">
                      <div className={`lf-check-item ${passwordStrength.checks.length ? 'active' : ''}`}>
                        {passwordStrength.checks.length ? '✓' : '○'} At least 6 characters
                      </div>
                      <div className={`lf-check-item ${passwordStrength.checks.uppercase ? 'active' : ''}`}>
                        {passwordStrength.checks.uppercase ? '✓' : '○'} Uppercase letter (A-Z)
                      </div>
                      <div className={`lf-check-item ${passwordStrength.checks.lowercase ? 'active' : ''}`}>
                        {passwordStrength.checks.lowercase ? '✓' : '○'} Lowercase letter (a-z)
                      </div>
                      <div className={`lf-check-item ${passwordStrength.checks.numbers ? 'active' : ''}`}>
                        {passwordStrength.checks.numbers ? '✓' : '○'} Number (0-9)
                      </div>
                      <div className={`lf-check-item ${passwordStrength.checks.special ? 'active' : ''}`}>
                        {passwordStrength.checks.special ? '✓' : '○'} Special character (!@#$...)
                      </div>
                    </div>
                  </div>
                )}
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
